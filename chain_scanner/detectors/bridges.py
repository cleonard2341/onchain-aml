"""Cross-chain bridge detection module."""

from typing import Any

from ..chains.base import Transaction
from ..config import load_json_data, ScannerConfig
from .base import Detector, DetectionResult, RiskLevel, Flag


class BridgesDetector(Detector):
    """Detector for cross-chain bridge usage."""

    name = "bridges"
    description = "Detects usage of cross-chain bridges (potential chain-hopping)"
    default_severity = RiskLevel.LOW

    def __init__(self, config: ScannerConfig | None = None):
        super().__init__(config)
        self._bridges_data: dict[str, Any] | None = None
        self._eth_bridge_addresses: dict[str, dict[str, Any]] | None = None

    def _load_bridges_data(self) -> None:
        """Load bridge data from JSON file."""
        if self._bridges_data is not None:
            return

        self._bridges_data = load_json_data("bridges.json")

        # Build address lookup dict
        self._eth_bridge_addresses = {}

        eth_bridges = self._bridges_data.get("ethereum", {})
        for bridge_key, bridge_info in eth_bridges.items():
            name = bridge_info.get("name", bridge_key)
            risk_level = bridge_info.get("risk_level", "LOW")
            description = bridge_info.get("description", "")

            for addr in bridge_info.get("addresses", []):
                self._eth_bridge_addresses[addr.lower()] = {
                    "name": name,
                    "risk_level": risk_level,
                    "description": description,
                    "bridge_key": bridge_key,
                }

    def analyze_transactions(
        self,
        transactions: list[Transaction],
        target_address: str | None = None,
    ) -> DetectionResult:
        """Check transactions for bridge interactions."""
        self._load_bridges_data()

        flags: list[Flag] = []
        bridge_interactions: dict[str, list[str]] = {}  # bridge_name -> [tx_hashes]

        for tx in transactions:
            bridge_info = self._check_bridge_interaction(tx)
            if bridge_info:
                bridge_name = bridge_info["name"]
                if bridge_name not in bridge_interactions:
                    bridge_interactions[bridge_name] = []
                bridge_interactions[bridge_name].append(tx.hash)

                flag = self._create_bridge_flag(tx, bridge_info)
                flags.append(flag)

        # Analyze patterns - multiple bridge usage is more suspicious
        if len(bridge_interactions) > 1:
            # Using multiple different bridges is suspicious
            flag = self._create_multi_bridge_flag(bridge_interactions)
            flags.append(flag)

        total_score = sum(f.score_contribution for f in flags)

        return DetectionResult(
            detector_name=self.name,
            flags=flags,
            score_contribution=min(100.0, total_score),
            metadata={
                "bridge_interactions": {k: len(v) for k, v in bridge_interactions.items()},
                "unique_bridges_used": len(bridge_interactions),
                "total_bridge_txs": sum(len(v) for v in bridge_interactions.values()),
            },
        )

    def _check_bridge_interaction(self, tx: Transaction) -> dict[str, Any] | None:
        """Check if transaction interacts with a bridge."""
        addresses_to_check = []

        if tx.to_address:
            addresses_to_check.append(tx.to_address)
        if tx.from_address:
            addresses_to_check.append(tx.from_address)
        if tx.contract_address:
            addresses_to_check.append(tx.contract_address)

        for addr in addresses_to_check:
            addr_lower = addr.lower()
            if addr_lower in self._eth_bridge_addresses:
                return self._eth_bridge_addresses[addr_lower]

        return None

    def _create_bridge_flag(
        self,
        tx: Transaction,
        bridge_info: dict[str, Any],
    ) -> Flag:
        """Create a flag for bridge interaction."""
        bridge_name = bridge_info["name"]
        risk_str = bridge_info.get("risk_level", "LOW")

        risk_map = {
            "LOW": RiskLevel.LOW,
            "MEDIUM": RiskLevel.MEDIUM,
            "HIGH": RiskLevel.HIGH,
            "CRITICAL": RiskLevel.CRITICAL,
        }
        severity = risk_map.get(risk_str.upper(), RiskLevel.LOW)

        # Determine direction
        to_bridge = (
            tx.to_address and
            tx.to_address.lower() in self._eth_bridge_addresses
        )
        direction = "deposit to" if to_bridge else "withdrawal from"

        details = f"Cross-chain bridge {direction}: {bridge_name}"

        # Base score for bridges is lower since bridge usage alone isn't highly suspicious
        base_score = self.config.risk_weights.bridge

        # Adjust score based on bridge risk level
        score_multiplier = 1.0
        if risk_str == "MEDIUM":
            score_multiplier = 1.5
        elif risk_str == "HIGH":
            score_multiplier = 2.0

        return self.create_flag(
            details=details,
            severity=severity,
            tx_hash=tx.hash,
            address=tx.to_address if to_bridge else tx.from_address,
            score=base_score * score_multiplier * 0.5,  # Per-tx score is halved
            metadata={
                "bridge_name": bridge_name,
                "bridge_key": bridge_info.get("bridge_key", ""),
                "direction": "deposit" if to_bridge else "withdrawal",
            },
        )

    def _create_multi_bridge_flag(
        self,
        bridge_interactions: dict[str, list[str]],
    ) -> Flag:
        """Create a flag for using multiple bridges."""
        bridge_names = list(bridge_interactions.keys())
        total_txs = sum(len(txs) for txs in bridge_interactions.values())

        details = (
            f"Multiple bridge usage: {len(bridge_names)} different bridges "
            f"({total_txs} transactions)"
        )

        # Multiple bridges is more suspicious
        severity = RiskLevel.MEDIUM
        if len(bridge_names) >= 3:
            severity = RiskLevel.HIGH

        return self.create_flag(
            details=details,
            severity=severity,
            score=self.config.risk_weights.bridge * 1.5,
            metadata={
                "bridges_used": bridge_names,
                "transaction_counts": {k: len(v) for k, v in bridge_interactions.items()},
            },
        )

    def is_bridge_address(self, address: str) -> bool:
        """Check if an address is a known bridge."""
        self._load_bridges_data()
        return address.lower() in self._eth_bridge_addresses

    def get_bridge_info(self, address: str) -> dict[str, Any] | None:
        """Get bridge information for an address."""
        self._load_bridges_data()
        return self._eth_bridge_addresses.get(address.lower())
