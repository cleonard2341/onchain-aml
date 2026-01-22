"""Mixer/tumbler detection module."""

from typing import Any

from ..chains.base import Transaction
from ..config import load_json_data, ScannerConfig
from .base import Detector, DetectionResult, RiskLevel, Flag


class MixerDetector(Detector):
    """Detector for mixer and tumbler service interactions."""

    name = "mixer"
    description = "Detects interactions with known mixer/tumbler services"
    default_severity = RiskLevel.HIGH

    def __init__(self, config: ScannerConfig | None = None):
        super().__init__(config)
        self._mixers_data: dict[str, Any] | None = None
        self._eth_mixer_addresses: dict[str, dict[str, Any]] | None = None

    def _load_mixers_data(self) -> None:
        """Load mixer data from JSON file."""
        if self._mixers_data is not None:
            return

        self._mixers_data = load_json_data("mixers.json")

        # Build address lookup dict with metadata
        self._eth_mixer_addresses = {}

        eth_mixers = self._mixers_data.get("ethereum", {})
        for mixer_key, mixer_info in eth_mixers.items():
            name = mixer_info.get("name", mixer_key)
            risk_level = mixer_info.get("risk_level", "HIGH")
            description = mixer_info.get("description", "")

            for addr in mixer_info.get("addresses", []):
                self._eth_mixer_addresses[addr.lower()] = {
                    "name": name,
                    "risk_level": risk_level,
                    "description": description,
                    "mixer_key": mixer_key,
                }

    def analyze_transactions(
        self,
        transactions: list[Transaction],
        target_address: str | None = None,
    ) -> DetectionResult:
        """Check transactions for mixer interactions."""
        self._load_mixers_data()

        flags: list[Flag] = []
        mixer_interactions: dict[str, list[str]] = {}  # mixer_name -> [tx_hashes]

        for tx in transactions:
            # Check if transaction interacts with known mixer
            mixer_info = self._check_mixer_interaction(tx)
            if mixer_info:
                mixer_name = mixer_info["name"]
                if mixer_name not in mixer_interactions:
                    mixer_interactions[mixer_name] = []
                mixer_interactions[mixer_name].append(tx.hash)

                # Create flag for each interaction
                flag = self._create_mixer_flag(tx, mixer_info)
                flags.append(flag)

            # For Bitcoin, check for CoinJoin patterns
            if tx.chain == "bitcoin":
                if self._is_coinjoin(tx):
                    flag = self._create_coinjoin_flag(tx)
                    flags.append(flag)

        # Calculate total score
        total_score = sum(f.score_contribution for f in flags)

        return DetectionResult(
            detector_name=self.name,
            flags=flags,
            score_contribution=min(100.0, total_score),
            metadata={
                "mixer_interactions": mixer_interactions,
                "total_mixer_txs": len(flags),
            },
        )

    def _check_mixer_interaction(self, tx: Transaction) -> dict[str, Any] | None:
        """Check if transaction interacts with a mixer."""
        # Check to_address
        if tx.to_address:
            to_lower = tx.to_address.lower()
            if to_lower in self._eth_mixer_addresses:
                return self._eth_mixer_addresses[to_lower]

        # Check from_address (receiving from mixer)
        if tx.from_address:
            from_lower = tx.from_address.lower()
            if from_lower in self._eth_mixer_addresses:
                return self._eth_mixer_addresses[from_lower]

        # Check contract_address
        if tx.contract_address:
            contract_lower = tx.contract_address.lower()
            if contract_lower in self._eth_mixer_addresses:
                return self._eth_mixer_addresses[contract_lower]

        return None

    def _create_mixer_flag(self, tx: Transaction, mixer_info: dict[str, Any]) -> Flag:
        """Create a flag for mixer interaction."""
        mixer_name = mixer_info["name"]
        risk_str = mixer_info.get("risk_level", "HIGH")

        # Map string to RiskLevel
        risk_map = {
            "LOW": RiskLevel.LOW,
            "MEDIUM": RiskLevel.MEDIUM,
            "HIGH": RiskLevel.HIGH,
            "CRITICAL": RiskLevel.CRITICAL,
        }
        severity = risk_map.get(risk_str.upper(), RiskLevel.HIGH)

        # Determine direction
        to_mixer = (
            tx.to_address and
            tx.to_address.lower() in self._eth_mixer_addresses
        )
        direction = "deposit to" if to_mixer else "withdrawal from"

        details = f"{mixer_name} interaction: {direction} mixer"

        return self.create_flag(
            details=details,
            severity=severity,
            tx_hash=tx.hash,
            address=tx.to_address if to_mixer else tx.from_address,
            score=self.config.risk_weights.mixer,
            metadata={
                "mixer_name": mixer_name,
                "direction": "deposit" if to_mixer else "withdrawal",
                "mixer_key": mixer_info.get("mixer_key", ""),
            },
        )

    def _is_coinjoin(self, tx: Transaction) -> bool:
        """Detect if a Bitcoin transaction is a CoinJoin."""
        if not tx.inputs or not tx.outputs:
            return False

        # Get unique input addresses
        input_addresses = set()
        for inp in tx.inputs:
            if inp.get("addresses"):
                input_addresses.update(inp["addresses"])

        # CoinJoin typically has multiple different input addresses
        if len(input_addresses) < 2:
            return False

        # Check for multiple outputs of similar values
        output_values = [out.get("value", 0) for out in tx.outputs]
        if len(output_values) < 3:
            return False

        # Count outputs with similar values (within 1%)
        sorted_values = sorted(output_values, reverse=True)
        similar_groups = 0

        for i in range(len(sorted_values) - 1):
            if sorted_values[i] > 0:
                diff = abs(sorted_values[i] - sorted_values[i + 1])
                if diff / sorted_values[i] < 0.01:
                    similar_groups += 1

        # If we have multiple outputs of similar value, likely CoinJoin
        return similar_groups >= 2

    def _create_coinjoin_flag(self, tx: Transaction) -> Flag:
        """Create a flag for CoinJoin transaction."""
        num_inputs = len(tx.inputs) if tx.inputs else 0
        num_outputs = len(tx.outputs) if tx.outputs else 0

        details = f"CoinJoin pattern detected: {num_inputs} inputs, {num_outputs} outputs"

        return self.create_flag(
            details=details,
            severity=RiskLevel.HIGH,
            tx_hash=tx.hash,
            score=self.config.risk_weights.mixer,
            metadata={
                "type": "coinjoin",
                "num_inputs": num_inputs,
                "num_outputs": num_outputs,
            },
        )

    def is_known_mixer(self, address: str) -> bool:
        """Check if an address is a known mixer."""
        self._load_mixers_data()
        return address.lower() in self._eth_mixer_addresses

    def get_mixer_info(self, address: str) -> dict[str, Any] | None:
        """Get mixer information for an address."""
        self._load_mixers_data()
        return self._eth_mixer_addresses.get(address.lower())
