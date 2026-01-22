"""Sanctions/blocklist address detector."""

from typing import Any

from ..chains.base import Transaction
from ..config import load_json_data, ScannerConfig
from .base import Detector, DetectionResult, RiskLevel, Flag


class SanctionsDetector(Detector):
    """Detector for OFAC/sanctions list address matching."""

    name = "sanctions"
    description = "Detects interactions with OFAC-sanctioned addresses"
    default_severity = RiskLevel.CRITICAL

    def __init__(self, config: ScannerConfig | None = None):
        super().__init__(config)
        self._sanctions_data: dict[str, Any] | None = None
        self._eth_addresses: set[str] | None = None
        self._btc_addresses: set[str] | None = None

    def _load_sanctions_data(self) -> None:
        """Load sanctions data from JSON file."""
        if self._sanctions_data is not None:
            return

        self._sanctions_data = load_json_data("sanctions.json")

        # Build address lookup sets
        self._eth_addresses = set()
        self._btc_addresses = set()

        for entry in self._sanctions_data.get("ethereum", []):
            addr = entry.get("address", "").lower()
            if addr:
                self._eth_addresses.add(addr)

        for entry in self._sanctions_data.get("bitcoin", []):
            addr = entry.get("address", "").lower()
            if addr:
                self._btc_addresses.add(addr)

    def analyze_transactions(
        self,
        transactions: list[Transaction],
        target_address: str | None = None,
    ) -> DetectionResult:
        """Check transactions for sanctioned address interactions."""
        self._load_sanctions_data()

        flags: list[Flag] = []
        checked_addresses: set[str] = set()

        for tx in transactions:
            # Check from address
            if tx.from_address and tx.from_address.lower() not in checked_addresses:
                flag = self._check_address(tx.from_address, tx)
                if flag:
                    flags.append(flag)
                checked_addresses.add(tx.from_address.lower())

            # Check to address
            if tx.to_address and tx.to_address.lower() not in checked_addresses:
                flag = self._check_address(tx.to_address, tx)
                if flag:
                    flags.append(flag)
                checked_addresses.add(tx.to_address.lower())

        # Also check target address directly
        if target_address and target_address.lower() not in checked_addresses:
            flag = self._check_address(target_address, None)
            if flag:
                flags.append(flag)

        total_score = sum(f.score_contribution for f in flags)

        return DetectionResult(
            detector_name=self.name,
            flags=flags,
            score_contribution=min(100.0, total_score),
        )

    def analyze_address(
        self,
        address: str,
        transactions: list[Transaction] | None = None,
    ) -> DetectionResult:
        """Check if a single address is sanctioned."""
        self._load_sanctions_data()

        flags: list[Flag] = []

        flag = self._check_address(address, None)
        if flag:
            flags.append(flag)

        # Also check transactions if provided
        if transactions:
            tx_result = self.analyze_transactions(transactions, target_address=address)
            # Merge flags, avoiding duplicates
            existing_addrs = {f.address for f in flags}
            for f in tx_result.flags:
                if f.address not in existing_addrs:
                    flags.append(f)

        total_score = sum(f.score_contribution for f in flags)

        return DetectionResult(
            detector_name=self.name,
            flags=flags,
            score_contribution=min(100.0, total_score),
        )

    def _check_address(self, address: str, tx: Transaction | None) -> Flag | None:
        """Check if address is on sanctions list."""
        addr_lower = address.lower()

        # Check Ethereum addresses
        if addr_lower in self._eth_addresses:
            entry = self._get_sanctions_entry(addr_lower, "ethereum")
            return self._create_sanctions_flag(address, entry, tx)

        # Check Bitcoin addresses
        if addr_lower in self._btc_addresses:
            entry = self._get_sanctions_entry(addr_lower, "bitcoin")
            return self._create_sanctions_flag(address, entry, tx)

        return None

    def _get_sanctions_entry(self, address: str, chain: str) -> dict[str, Any]:
        """Get sanctions entry for an address."""
        for entry in self._sanctions_data.get(chain, []):
            if entry.get("address", "").lower() == address:
                return entry
        return {}

    def _create_sanctions_flag(
        self,
        address: str,
        entry: dict[str, Any],
        tx: Transaction | None,
    ) -> Flag:
        """Create a sanctions flag."""
        name = entry.get("name", "Unknown sanctioned entity")
        program = entry.get("program", "OFAC")
        date_added = entry.get("date_added", "unknown date")

        details = f"OFAC sanctioned address: {name} ({program}, added {date_added})"

        return self.create_flag(
            details=details,
            severity=RiskLevel.CRITICAL,
            tx_hash=tx.hash if tx else None,
            address=address,
            score=self.config.risk_weights.sanctions,
            metadata={
                "sanctions_name": name,
                "program": program,
                "date_added": date_added,
            },
        )

    def is_sanctioned(self, address: str) -> bool:
        """Quick check if an address is sanctioned."""
        self._load_sanctions_data()
        addr_lower = address.lower()
        return addr_lower in self._eth_addresses or addr_lower in self._btc_addresses

    def get_sanctions_info(self, address: str) -> dict[str, Any] | None:
        """Get sanctions information for an address."""
        self._load_sanctions_data()
        addr_lower = address.lower()

        if addr_lower in self._eth_addresses:
            return self._get_sanctions_entry(addr_lower, "ethereum")
        if addr_lower in self._btc_addresses:
            return self._get_sanctions_entry(addr_lower, "bitcoin")

        return None
