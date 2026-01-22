"""Structuring/smurfing pattern detection."""

from collections import defaultdict
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

from ..chains.base import Transaction
from ..config import ScannerConfig
from .base import Detector, DetectionResult, RiskLevel, Flag


class StructuringDetector(Detector):
    """Detector for structuring (smurfing) patterns."""

    name = "structuring"
    description = "Detects transaction splitting to avoid reporting thresholds"
    default_severity = RiskLevel.MEDIUM

    def __init__(self, config: ScannerConfig | None = None):
        super().__init__(config)
        self.structuring_config = self.config.structuring

    def analyze_transactions(
        self,
        transactions: list[Transaction],
        target_address: str | None = None,
    ) -> DetectionResult:
        """Analyze transactions for structuring patterns."""
        flags: list[Flag] = []

        if not transactions:
            return self._empty_result()

        # Get configuration values
        threshold = Decimal(str(self.structuring_config.threshold_usd))
        margin_percent = Decimal(str(self.structuring_config.margin_percent))
        min_transactions = self.structuring_config.min_transactions
        time_window_hours = self.structuring_config.time_window_hours

        # Calculate the suspicious range (e.g., $9,500 - $9,999 for $10k threshold)
        lower_bound = threshold * (1 - margin_percent / 100)
        upper_bound = threshold

        # Group transactions by time windows
        time_groups = self._group_by_time_window(transactions, time_window_hours)

        for window_start, txs in time_groups.items():
            # Find transactions in suspicious range
            suspicious_txs = self._find_suspicious_transactions(
                txs, lower_bound, upper_bound, target_address
            )

            if len(suspicious_txs) >= min_transactions:
                flag = self._create_structuring_flag(
                    suspicious_txs, lower_bound, upper_bound, window_start
                )
                flags.append(flag)

        # Also check for round number structuring
        round_number_flags = self._check_round_number_structuring(
            transactions, target_address
        )
        flags.extend(round_number_flags)

        total_score = sum(f.score_contribution for f in flags)

        return DetectionResult(
            detector_name=self.name,
            flags=flags,
            score_contribution=min(100.0, total_score),
            metadata={
                "threshold_usd": float(threshold),
                "margin_percent": float(margin_percent),
                "time_window_hours": time_window_hours,
            },
        )

    def _group_by_time_window(
        self,
        transactions: list[Transaction],
        window_hours: int,
    ) -> dict[datetime, list[Transaction]]:
        """Group transactions into time windows."""
        groups: dict[datetime, list[Transaction]] = defaultdict(list)

        for tx in transactions:
            if tx.timestamp:
                # Round down to window start
                window_start = tx.timestamp.replace(
                    minute=0, second=0, microsecond=0
                )
                # Further round to window_hours boundary
                hour = window_start.hour - (window_start.hour % window_hours)
                window_start = window_start.replace(hour=hour)

                groups[window_start].append(tx)

        return dict(groups)

    def _find_suspicious_transactions(
        self,
        transactions: list[Transaction],
        lower_bound: Decimal,
        upper_bound: Decimal,
        target_address: str | None,
    ) -> list[Transaction]:
        """Find transactions within the suspicious value range."""
        suspicious = []

        for tx in transactions:
            # Use USD value if available, otherwise use raw value
            value = tx.value_usd if tx.value_usd else tx.value

            if value is None:
                continue

            # Check if value is in suspicious range
            if lower_bound <= value < upper_bound:
                # If target address specified, only count outgoing txs
                if target_address:
                    if tx.from_address and tx.from_address.lower() == target_address.lower():
                        suspicious.append(tx)
                else:
                    suspicious.append(tx)

        return suspicious

    def _create_structuring_flag(
        self,
        transactions: list[Transaction],
        lower_bound: Decimal,
        upper_bound: Decimal,
        window_start: datetime,
    ) -> Flag:
        """Create a structuring flag."""
        if not transactions:
            # Should not happen, but guard against empty list
            return self.create_flag(
                details="Structuring pattern detected (no transaction details)",
                severity=RiskLevel.MEDIUM,
                score=self.config.risk_weights.structuring,
            )

        num_txs = len(transactions)
        total_value = sum(tx.value_usd or tx.value or Decimal(0) for tx in transactions)

        # Get value range (safe: transactions is non-empty)
        values = [tx.value_usd or tx.value or Decimal(0) for tx in transactions]
        min_val = min(values)
        max_val = max(values)

        details = (
            f"Potential structuring: {num_txs} transactions of "
            f"${min_val:,.2f}-${max_val:,.2f} within time window"
        )

        # Higher severity for more transactions
        severity = RiskLevel.MEDIUM
        if num_txs >= 5:
            severity = RiskLevel.HIGH
        if num_txs >= 10:
            severity = RiskLevel.CRITICAL

        # Adjust score based on number of transactions
        base_score = self.config.risk_weights.structuring
        score_multiplier = min(2.0, 1 + (num_txs - 3) * 0.2)

        return self.create_flag(
            details=details,
            severity=severity,
            tx_hash=transactions[0].hash if transactions else None,
            score=base_score * score_multiplier,
            metadata={
                "transaction_count": num_txs,
                "total_value": float(total_value),
                "value_range": [float(min_val), float(max_val)],
                "window_start": window_start.isoformat() if window_start else None,
                "tx_hashes": [tx.hash for tx in transactions],
            },
        )

    def _check_round_number_structuring(
        self,
        transactions: list[Transaction],
        target_address: str | None,
    ) -> list[Flag]:
        """Check for suspicious patterns of round numbers."""
        flags: list[Flag] = []

        # Common structuring amounts (USD)
        suspicious_amounts = [
            Decimal("9000"),
            Decimal("9500"),
            Decimal("9800"),
            Decimal("9900"),
            Decimal("9950"),
            Decimal("9990"),
            Decimal("4500"),
            Decimal("4900"),
        ]

        # Tolerance for matching (within 1%)
        tolerance = Decimal("0.01")

        # Count transactions near each suspicious amount
        amount_counts: dict[Decimal, list[Transaction]] = defaultdict(list)

        for tx in transactions:
            value = tx.value_usd if tx.value_usd else tx.value
            if value is None:
                continue

            # Check outgoing only if target specified
            if target_address:
                if not tx.from_address or tx.from_address.lower() != target_address.lower():
                    continue

            for suspicious in suspicious_amounts:
                # Guard against division by zero (should never happen with current list)
                if suspicious > 0 and value is not None:
                    diff = abs(value - suspicious) / suspicious
                    if diff <= tolerance:
                        amount_counts[suspicious].append(tx)
                        break

        # Flag amounts with multiple occurrences
        for amount, txs in amount_counts.items():
            if len(txs) >= 3:
                details = (
                    f"Repeated transactions near ${amount:,.0f}: "
                    f"{len(txs)} transactions"
                )

                flags.append(self.create_flag(
                    details=details,
                    severity=RiskLevel.MEDIUM,
                    score=self.config.risk_weights.structuring * 0.5,
                    metadata={
                        "suspicious_amount": float(amount),
                        "count": len(txs),
                        "tx_hashes": [tx.hash for tx in txs],
                    },
                ))

        return flags
