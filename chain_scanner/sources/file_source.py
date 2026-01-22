"""File-based data source for JSON/CSV transaction data."""

import csv
import json
from pathlib import Path
from typing import Any, Iterator

from ..chains.base import AddressInfo, ChainAdapter, Transaction
from .base import DataSource


class FileSource(DataSource):
    """Data source for reading transactions from JSON/CSV files."""

    source_type = "file"

    def __init__(
        self,
        file_path: str | Path,
        format: str | None = None,
        chain_adapter: ChainAdapter | None = None,
    ):
        """
        Initialize file source.

        Args:
            file_path: Path to the transaction file
            format: File format ("json" or "csv"), auto-detected if not specified
            chain_adapter: Optional chain adapter for parsing transactions
        """
        self.file_path = Path(file_path)

        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {self.file_path}")

        # Auto-detect format from extension
        if format:
            self.format = format.lower()
        else:
            suffix = self.file_path.suffix.lower()
            if suffix == ".json":
                self.format = "json"
            elif suffix == ".csv":
                self.format = "csv"
            else:
                raise ValueError(
                    f"Cannot auto-detect format for {suffix}. "
                    "Please specify format='json' or format='csv'"
                )

        self.chain_adapter = chain_adapter
        self._transactions: list[dict[str, Any]] | None = None

    def _load_data(self) -> list[dict[str, Any]]:
        """Load and cache transaction data from file."""
        if self._transactions is not None:
            return self._transactions

        if self.format == "json":
            self._transactions = self._load_json()
        elif self.format == "csv":
            self._transactions = self._load_csv()
        else:
            raise ValueError(f"Unsupported format: {self.format}")

        return self._transactions

    def _load_json(self) -> list[dict[str, Any]]:
        """Load transactions from JSON file."""
        with open(self.file_path, "r") as f:
            data = json.load(f)

        # Handle different JSON structures
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            # Check common wrapper keys
            for key in ["transactions", "txs", "data", "result"]:
                if key in data and isinstance(data[key], list):
                    return data[key]
            # Single transaction
            return [data]
        else:
            raise ValueError(f"Unexpected JSON structure in {self.file_path}")

    def _load_csv(self) -> list[dict[str, Any]]:
        """Load transactions from CSV file."""
        transactions = []

        with open(self.file_path, "r", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Convert numeric fields
                tx = dict(row)
                for key in ["value", "gasPrice", "gas", "gasUsed", "blockNumber", "timeStamp"]:
                    if key in tx and tx[key]:
                        try:
                            tx[key] = int(tx[key])
                        except ValueError:
                            try:
                                tx[key] = float(tx[key])
                            except ValueError:
                                pass
                transactions.append(tx)

        return transactions

    def get_transactions(
        self,
        address: str,
        start_block: int | None = None,
        end_block: int | None = None,
        limit: int | None = None,
    ) -> Iterator[Transaction]:
        """Get transactions for a specific address."""
        data = self._load_data()
        address_lower = address.lower()
        count = 0

        for raw_tx in data:
            # Filter by address
            from_addr = str(raw_tx.get("from", "")).lower()
            to_addr = str(raw_tx.get("to", "")).lower()

            if address_lower not in (from_addr, to_addr):
                continue

            # Filter by block range
            block_num = raw_tx.get("blockNumber")
            if block_num:
                if start_block and block_num < start_block:
                    continue
                if end_block and block_num > end_block:
                    continue

            # Parse transaction
            if self.chain_adapter:
                tx = self.chain_adapter.parse_transaction(raw_tx)
            else:
                tx = self._parse_generic_transaction(raw_tx)

            yield tx
            count += 1

            if limit and count >= limit:
                break

    def get_all_transactions(self) -> Iterator[Transaction]:
        """Get all transactions from the file."""
        data = self._load_data()

        for raw_tx in data:
            if self.chain_adapter:
                tx = self.chain_adapter.parse_transaction(raw_tx)
            else:
                tx = self._parse_generic_transaction(raw_tx)
            yield tx

    def get_address_info(self, address: str) -> AddressInfo | None:
        """Get address info (limited data from file)."""
        data = self._load_data()
        address_lower = address.lower()

        tx_count = 0
        for raw_tx in data:
            from_addr = str(raw_tx.get("from", "")).lower()
            to_addr = str(raw_tx.get("to", "")).lower()
            if address_lower in (from_addr, to_addr):
                tx_count += 1

        if tx_count == 0:
            return None

        chain = "unknown"
        if self.chain_adapter:
            chain = self.chain_adapter.chain_id

        return AddressInfo(
            address=address,
            chain=chain,
            tx_count=tx_count,
        )

    def get_transaction(self, tx_hash: str) -> Transaction | None:
        """Get a single transaction by hash."""
        data = self._load_data()
        hash_lower = tx_hash.lower()

        for raw_tx in data:
            raw_hash = str(raw_tx.get("hash", raw_tx.get("transactionHash", ""))).lower()
            if raw_hash == hash_lower:
                if self.chain_adapter:
                    return self.chain_adapter.parse_transaction(raw_tx)
                return self._parse_generic_transaction(raw_tx)

        return None

    def _parse_generic_transaction(self, raw_tx: dict[str, Any]) -> Transaction:
        """Parse transaction without chain-specific adapter."""
        from decimal import Decimal
        from datetime import datetime, timezone
        from ..chains.base import TransactionType

        tx_hash = raw_tx.get("hash") or raw_tx.get("transactionHash", "")
        from_addr = raw_tx.get("from", "")
        to_addr = raw_tx.get("to")

        # Parse value
        value_raw = raw_tx.get("value", 0)
        if isinstance(value_raw, str):
            try:
                if value_raw.startswith("0x"):
                    value_raw = int(value_raw, 16)
                else:
                    value_raw = int(value_raw)
            except ValueError:
                value_raw = 0
        # Convert from wei to ETH (assume 18 decimals if unknown)
        value = Decimal(value_raw) / Decimal(10**18)

        # Parse timestamp
        timestamp = None
        ts = raw_tx.get("timeStamp") or raw_tx.get("timestamp")
        if ts:
            if isinstance(ts, str):
                ts = int(ts)
            timestamp = datetime.fromtimestamp(ts, tz=timezone.utc)

        return Transaction(
            hash=tx_hash,
            chain="unknown",
            block_number=raw_tx.get("blockNumber"),
            timestamp=timestamp,
            from_address=from_addr,
            to_address=to_addr,
            value=value,
            tx_type=TransactionType.TRANSFER,
            raw=raw_tx,
        )
