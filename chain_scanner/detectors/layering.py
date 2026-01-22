"""Layering/peel chain detection module."""

from collections import defaultdict
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

from ..chains.base import Transaction
from ..config import ScannerConfig
from .base import Detector, DetectionResult, RiskLevel, Flag


class LayeringDetector(Detector):
    """Detector for rapid fund layering and peel chain patterns."""

    name = "layering"
    description = "Detects rapid fund movement through multiple addresses"
    default_severity = RiskLevel.MEDIUM

    def __init__(self, config: ScannerConfig | None = None):
        super().__init__(config)
        self.layering_config = self.config.layering

    def analyze_transactions(
        self,
        transactions: list[Transaction],
        target_address: str | None = None,
    ) -> DetectionResult:
        """Analyze transactions for layering patterns."""
        flags: list[Flag] = []

        if not transactions or len(transactions) < 2:
            return self._empty_result()

        # Build transaction graph
        graph = self._build_transaction_graph(transactions)

        # Detect rapid chains
        chains = self._find_rapid_chains(transactions, graph, target_address)

        for chain in chains:
            if len(chain) >= self.layering_config.min_hops:
                flag = self._create_layering_flag(chain)
                flags.append(flag)

        # Detect peel chain patterns
        peel_flags = self._detect_peel_chains(transactions, target_address)
        flags.extend(peel_flags)

        total_score = sum(f.score_contribution for f in flags)

        return DetectionResult(
            detector_name=self.name,
            flags=flags,
            score_contribution=min(100.0, total_score),
            metadata={
                "min_hops": self.layering_config.min_hops,
                "time_window_hours": self.layering_config.time_window_hours,
                "chains_detected": len(chains),
            },
        )

    def _build_transaction_graph(
        self,
        transactions: list[Transaction],
    ) -> dict[str, list[dict[str, Any]]]:
        """Build a graph of address connections from transactions."""
        graph: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for tx in transactions:
            if tx.from_address and tx.to_address:
                from_addr = tx.from_address.lower()
                to_addr = tx.to_address.lower()

                graph[from_addr].append({
                    "to": to_addr,
                    "tx": tx,
                    "value": tx.value or Decimal(0),
                    "timestamp": tx.timestamp,
                })

        return dict(graph)

    def _find_rapid_chains(
        self,
        transactions: list[Transaction],
        graph: dict[str, list[dict[str, Any]]],
        target_address: str | None,
    ) -> list[list[Transaction]]:
        """Find chains of rapid consecutive transfers."""
        chains: list[list[Transaction]] = []
        time_window = timedelta(hours=self.layering_config.time_window_hours)

        # Sort transactions by timestamp
        sorted_txs = sorted(
            [tx for tx in transactions if tx.timestamp],
            key=lambda x: x.timestamp,
        )

        if not sorted_txs:
            return chains

        # Start from target address or from all addresses
        start_addresses = set()
        if target_address:
            start_addresses.add(target_address.lower())
        else:
            start_addresses = set(graph.keys())

        visited_txs: set[str] = set()

        for start_addr in start_addresses:
            # BFS to find chains
            chain = self._trace_chain(
                start_addr, graph, time_window, visited_txs
            )
            if len(chain) >= self.layering_config.min_hops:
                chains.append(chain)

        return chains

    def _trace_chain(
        self,
        start_address: str,
        graph: dict[str, list[dict[str, Any]]],
        time_window: timedelta,
        visited_txs: set[str],
    ) -> list[Transaction]:
        """Trace a chain of rapid transfers starting from an address."""
        chain: list[Transaction] = []
        current_addr = start_address
        last_timestamp: datetime | None = None

        max_iterations = 50  # Prevent infinite loops

        for _ in range(max_iterations):
            outgoing = graph.get(current_addr, [])
            if not outgoing:
                break

            # Find the next transaction in the chain
            next_tx_data = None
            for tx_data in outgoing:
                tx = tx_data["tx"]
                if tx.hash in visited_txs:
                    continue

                # Check time constraint
                if last_timestamp:
                    if tx.timestamp and (tx.timestamp - last_timestamp) > time_window:
                        continue

                # Check value constraint (most of the value moves forward)
                if chain:
                    prev_value = chain[-1].value or Decimal(0)
                    curr_value = tx.value or Decimal(0)
                    if prev_value > 0:
                        transfer_pct = (curr_value / prev_value) * 100
                        if transfer_pct < self.layering_config.min_transfer_percent:
                            continue

                next_tx_data = tx_data
                break

            if not next_tx_data:
                break

            tx = next_tx_data["tx"]
            chain.append(tx)
            visited_txs.add(tx.hash)
            current_addr = next_tx_data["to"]
            last_timestamp = tx.timestamp

        return chain

    def _create_layering_flag(self, chain: list[Transaction]) -> Flag:
        """Create a layering flag for a detected chain."""
        num_hops = len(chain)

        # Calculate time span
        if chain[0].timestamp and chain[-1].timestamp:
            time_span = chain[-1].timestamp - chain[0].timestamp
            time_str = f" within {time_span.total_seconds() / 3600:.1f} hours"
        else:
            time_str = ""

        # Get addresses in chain
        addresses = []
        for tx in chain:
            if tx.from_address and tx.from_address not in addresses:
                addresses.append(tx.from_address)
            if tx.to_address and tx.to_address not in addresses:
                addresses.append(tx.to_address)

        details = f"Rapid layering: {num_hops} hops through {len(addresses)} addresses{time_str}"

        # Severity based on number of hops
        severity = RiskLevel.MEDIUM
        if num_hops >= 5:
            severity = RiskLevel.HIGH
        if num_hops >= 8:
            severity = RiskLevel.CRITICAL

        # Score increases with chain length
        base_score = self.config.risk_weights.layering
        score_multiplier = min(2.0, 1 + (num_hops - 3) * 0.15)

        return self.create_flag(
            details=details,
            severity=severity,
            tx_hash=chain[0].hash,
            score=base_score * score_multiplier,
            metadata={
                "hop_count": num_hops,
                "address_count": len(addresses),
                "addresses": addresses[:10],  # Limit stored addresses
                "tx_hashes": [tx.hash for tx in chain],
                "time_span_hours": (
                    (chain[-1].timestamp - chain[0].timestamp).total_seconds() / 3600
                    if chain[0].timestamp and chain[-1].timestamp
                    else None
                ),
            },
        )

    def _detect_peel_chains(
        self,
        transactions: list[Transaction],
        target_address: str | None,
    ) -> list[Flag]:
        """Detect peel chain patterns (gradual fund extraction)."""
        flags: list[Flag] = []

        if not target_address:
            return flags

        target_lower = target_address.lower()

        # Find outgoing transactions from target
        outgoing = [
            tx for tx in transactions
            if tx.from_address and tx.from_address.lower() == target_lower
        ]

        if len(outgoing) < 3:
            return flags

        # Sort by timestamp
        sorted_txs = sorted(
            [tx for tx in outgoing if tx.timestamp],
            key=lambda x: x.timestamp,
        )

        # Look for decreasing value pattern (peel chain characteristic)
        values = [tx.value or Decimal(0) for tx in sorted_txs]

        decreasing_count = 0
        for i in range(1, len(values)):
            if values[i] < values[i - 1]:
                decreasing_count += 1

        # If most transactions are decreasing in value, likely peel chain
        if len(values) > 3 and decreasing_count >= len(values) * 0.6:
            details = (
                f"Potential peel chain: {len(sorted_txs)} decreasing-value "
                f"transactions from address"
            )

            flags.append(self.create_flag(
                details=details,
                severity=RiskLevel.MEDIUM,
                address=target_address,
                score=self.config.risk_weights.layering * 0.7,
                metadata={
                    "pattern": "peel_chain",
                    "transaction_count": len(sorted_txs),
                    "decreasing_count": decreasing_count,
                },
            ))

        return flags
