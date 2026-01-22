"""Privacy coin and anonymity-enhanced token detection."""

from typing import Any

from ..chains.base import Transaction
from ..config import load_json_data, ScannerConfig
from .base import Detector, DetectionResult, RiskLevel, Flag


class PrivacyCoinsDetector(Detector):
    """Detector for privacy coin and anonymity-enhanced token interactions."""

    name = "privacy_coins"
    description = "Detects interactions with privacy-enhancing protocols and tokens"
    default_severity = RiskLevel.MEDIUM

    def __init__(self, config: ScannerConfig | None = None):
        super().__init__(config)
        self._privacy_data: dict[str, Any] | None = None
        self._eth_privacy_addresses: dict[str, dict[str, Any]] | None = None
        self._privacy_token_addresses: set[str] | None = None

    def _load_privacy_data(self) -> None:
        """Load privacy token data from JSON file."""
        if self._privacy_data is not None:
            return

        self._privacy_data = load_json_data("privacy_tokens.json")

        # Build address lookup dict
        self._eth_privacy_addresses = {}
        self._privacy_token_addresses = set()

        eth_protocols = self._privacy_data.get("ethereum", {})
        for protocol_key, protocol_info in eth_protocols.items():
            name = protocol_info.get("name", protocol_key)
            risk_level = protocol_info.get("risk_level", "MEDIUM")
            description = protocol_info.get("description", "")

            for addr in protocol_info.get("addresses", []):
                if addr:  # Skip empty addresses
                    self._eth_privacy_addresses[addr.lower()] = {
                        "name": name,
                        "risk_level": risk_level,
                        "description": description,
                        "protocol_key": protocol_key,
                        "type": "protocol",
                    }

        # Add privacy token addresses
        for token in self._privacy_data.get("privacy_tokens", []):
            if token.get("address"):
                addr = token["address"].lower()
                self._privacy_token_addresses.add(addr)
                self._eth_privacy_addresses[addr] = {
                    "name": token.get("name", token.get("symbol", "Unknown")),
                    "risk_level": token.get("risk_level", "MEDIUM"),
                    "description": token.get("description", ""),
                    "symbol": token.get("symbol"),
                    "type": "token",
                }

    def analyze_transactions(
        self,
        transactions: list[Transaction],
        target_address: str | None = None,
    ) -> DetectionResult:
        """Check transactions for privacy coin/protocol interactions."""
        self._load_privacy_data()

        flags: list[Flag] = []
        interactions: dict[str, int] = {}  # protocol_name -> count

        for tx in transactions:
            privacy_info = self._check_privacy_interaction(tx)
            if privacy_info:
                name = privacy_info["name"]
                interactions[name] = interactions.get(name, 0) + 1

                flag = self._create_privacy_flag(tx, privacy_info)
                flags.append(flag)

            # Also check token transfers
            if tx.token_address:
                token_info = self._check_token_address(tx.token_address)
                if token_info:
                    name = token_info["name"]
                    interactions[name] = interactions.get(name, 0) + 1

                    flag = self._create_privacy_flag(tx, token_info, is_token=True)
                    flags.append(flag)

        total_score = sum(f.score_contribution for f in flags)

        return DetectionResult(
            detector_name=self.name,
            flags=flags,
            score_contribution=min(100.0, total_score),
            metadata={
                "protocol_interactions": interactions,
                "total_privacy_txs": len(flags),
            },
        )

    def _check_privacy_interaction(self, tx: Transaction) -> dict[str, Any] | None:
        """Check if transaction interacts with privacy protocol."""
        addresses_to_check = []

        if tx.to_address:
            addresses_to_check.append(tx.to_address)
        if tx.from_address:
            addresses_to_check.append(tx.from_address)
        if tx.contract_address:
            addresses_to_check.append(tx.contract_address)

        for addr in addresses_to_check:
            addr_lower = addr.lower()
            if addr_lower in self._eth_privacy_addresses:
                info = self._eth_privacy_addresses[addr_lower]
                if info.get("type") == "protocol":
                    return info

        return None

    def _check_token_address(self, address: str) -> dict[str, Any] | None:
        """Check if a token address is a privacy token."""
        addr_lower = address.lower()
        if addr_lower in self._privacy_token_addresses:
            return self._eth_privacy_addresses.get(addr_lower)
        return None

    def _create_privacy_flag(
        self,
        tx: Transaction,
        privacy_info: dict[str, Any],
        is_token: bool = False,
    ) -> Flag:
        """Create a flag for privacy protocol/token interaction."""
        name = privacy_info["name"]
        risk_str = privacy_info.get("risk_level", "MEDIUM")

        risk_map = {
            "LOW": RiskLevel.LOW,
            "MEDIUM": RiskLevel.MEDIUM,
            "HIGH": RiskLevel.HIGH,
            "CRITICAL": RiskLevel.CRITICAL,
        }
        severity = risk_map.get(risk_str.upper(), RiskLevel.MEDIUM)

        if is_token:
            details = f"Privacy token transfer: {name}"
            if tx.token_symbol:
                details = f"Privacy token transfer: {tx.token_symbol} ({name})"
        else:
            # Determine direction
            to_protocol = (
                tx.to_address and
                tx.to_address.lower() in self._eth_privacy_addresses
            )
            direction = "deposit to" if to_protocol else "interaction with"
            details = f"Privacy protocol {direction}: {name}"

        return self.create_flag(
            details=details,
            severity=severity,
            tx_hash=tx.hash,
            address=tx.to_address or tx.contract_address,
            score=self.config.risk_weights.privacy_coin,
            metadata={
                "protocol_name": name,
                "protocol_key": privacy_info.get("protocol_key", ""),
                "is_token": is_token,
                "symbol": privacy_info.get("symbol"),
            },
        )

    def is_privacy_address(self, address: str) -> bool:
        """Check if an address is associated with privacy protocols."""
        self._load_privacy_data()
        return address.lower() in self._eth_privacy_addresses

    def get_privacy_info(self, address: str) -> dict[str, Any] | None:
        """Get privacy protocol information for an address."""
        self._load_privacy_data()
        return self._eth_privacy_addresses.get(address.lower())
