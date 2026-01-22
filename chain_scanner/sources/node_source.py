"""Local node RPC data source."""

from typing import Any, Iterator

from ..chains.base import AddressInfo, ChainAdapter, Transaction
from .base import DataSource


class NodeSource(DataSource):
    """Data source for local blockchain node via RPC."""

    source_type = "node"

    def __init__(
        self,
        rpc_url: str,
        chain: str = "ethereum",
        chain_adapter: ChainAdapter | None = None,
    ):
        """
        Initialize node source.

        Args:
            rpc_url: RPC endpoint URL (e.g., http://localhost:8545)
            chain: Chain type ("ethereum" or "bitcoin")
            chain_adapter: Optional chain adapter for parsing
        """
        self.rpc_url = rpc_url
        self.chain = chain.lower()
        self.chain_adapter = chain_adapter
        self._web3 = None
        self._btc_rpc = None

        self._connect()

    def _connect(self) -> None:
        """Establish connection to the node."""
        if self.chain in ("ethereum", "eth"):
            self._connect_ethereum()
        elif self.chain in ("bitcoin", "btc"):
            self._connect_bitcoin()
        else:
            raise ValueError(f"Unsupported chain: {self.chain}")

    def _connect_ethereum(self) -> None:
        """Connect to Ethereum node."""
        try:
            from web3 import Web3
        except ImportError:
            raise ImportError("web3 package required for Ethereum node connection")

        self._web3 = Web3(Web3.HTTPProvider(self.rpc_url))

        if not self._web3.is_connected():
            raise ConnectionError(f"Failed to connect to Ethereum node at {self.rpc_url}")

    def _connect_bitcoin(self) -> None:
        """Connect to Bitcoin node via JSON-RPC."""
        # Bitcoin Core uses standard JSON-RPC
        # Store connection info for later use
        self._btc_rpc = {
            "url": self.rpc_url,
        }

    def get_transactions(
        self,
        address: str,
        start_block: int | None = None,
        end_block: int | None = None,
        limit: int | None = None,
    ) -> Iterator[Transaction]:
        """
        Get transactions for an address.

        Note: Full transaction history is not efficiently supported by
        standard Ethereum nodes. Consider using an indexed API source
        for historical queries.
        """
        if self.chain in ("ethereum", "eth"):
            yield from self._get_eth_transactions(address, start_block, end_block, limit)
        elif self.chain in ("bitcoin", "btc"):
            yield from self._get_btc_transactions(address, start_block, end_block, limit)

    def _get_eth_transactions(
        self,
        address: str,
        start_block: int | None,
        end_block: int | None,
        limit: int | None,
    ) -> Iterator[Transaction]:
        """Get Ethereum transactions (limited - nodes don't index by address)."""
        # Standard Ethereum nodes don't support getTransactionsByAddress
        # This would require scanning blocks which is very slow
        # For full address history, use APISource with Etherscan
        raise NotImplementedError(
            "Standard Ethereum nodes don't support address transaction history. "
            "Use an API source (Etherscan) or an indexed node (Erigon with --http.api=trace)"
        )

    def _get_btc_transactions(
        self,
        address: str,
        start_block: int | None,
        end_block: int | None,
        limit: int | None,
    ) -> Iterator[Transaction]:
        """Get Bitcoin transactions for an address."""
        # Bitcoin Core doesn't index by address either by default
        # Requires -txindex flag and additional setup
        raise NotImplementedError(
            "Standard Bitcoin Core doesn't support address transaction history. "
            "Use an API source or a node with address indexing."
        )

    def get_address_info(self, address: str) -> AddressInfo | None:
        """Get address information."""
        if self.chain in ("ethereum", "eth"):
            return self._get_eth_address_info(address)
        elif self.chain in ("bitcoin", "btc"):
            return self._get_btc_address_info(address)
        return None

    def _get_eth_address_info(self, address: str) -> AddressInfo:
        """Get Ethereum address info from node."""
        from decimal import Decimal

        # Normalize address
        address = self._web3.to_checksum_address(address)

        # Get balance
        balance_wei = self._web3.eth.get_balance(address)
        balance = Decimal(balance_wei) / Decimal(10**18)

        # Check if contract
        code = self._web3.eth.get_code(address)
        is_contract = len(code) > 0

        # Transaction count (nonce)
        tx_count = self._web3.eth.get_transaction_count(address)

        return AddressInfo(
            address=address,
            chain="ethereum",
            balance=balance,
            tx_count=tx_count,
            is_contract=is_contract,
        )

    def _get_btc_address_info(self, address: str) -> AddressInfo | None:
        """Get Bitcoin address info from node."""
        # Would need to call Bitcoin Core RPC
        # This requires complex UTXO scanning
        raise NotImplementedError(
            "Bitcoin address info requires indexing. Use an API source."
        )

    def get_transaction(self, tx_hash: str) -> Transaction | None:
        """Get a single transaction by hash."""
        if self.chain in ("ethereum", "eth"):
            return self._get_eth_transaction(tx_hash)
        elif self.chain in ("bitcoin", "btc"):
            return self._get_btc_transaction(tx_hash)
        return None

    def _get_eth_transaction(self, tx_hash: str) -> Transaction | None:
        """Get Ethereum transaction by hash."""
        try:
            raw_tx = self._web3.eth.get_transaction(tx_hash)
            if not raw_tx:
                return None

            # Get receipt for gas used
            receipt = self._web3.eth.get_transaction_receipt(tx_hash)

            # Get block for timestamp
            block = self._web3.eth.get_block(raw_tx["blockNumber"])

            # Combine data
            tx_data = dict(raw_tx)
            tx_data["gasUsed"] = receipt["gasUsed"]
            tx_data["timeStamp"] = block["timestamp"]

            if self.chain_adapter:
                return self.chain_adapter.parse_transaction(tx_data)

            # Basic parsing without adapter
            from decimal import Decimal
            from datetime import datetime, timezone
            from ..chains.base import TransactionType

            return Transaction(
                hash=tx_hash,
                chain="ethereum",
                block_number=raw_tx["blockNumber"],
                timestamp=datetime.fromtimestamp(block["timestamp"], tz=timezone.utc),
                from_address=raw_tx["from"],
                to_address=raw_tx.get("to"),
                value=Decimal(raw_tx["value"]) / Decimal(10**18),
                fee=Decimal(raw_tx["gasPrice"] * receipt["gasUsed"]) / Decimal(10**18),
                tx_type=TransactionType.TRANSFER,
                raw=tx_data,
            )

        except Exception:
            return None

    def _get_btc_transaction(self, tx_hash: str) -> Transaction | None:
        """Get Bitcoin transaction by hash."""
        import requests

        try:
            response = requests.post(
                self._btc_rpc["url"],
                json={
                    "jsonrpc": "1.0",
                    "method": "getrawtransaction",
                    "params": [tx_hash, True],  # True for decoded
                },
                timeout=30,
            )
            result = response.json()

            if "error" in result and result["error"]:
                return None

            raw_tx = result.get("result")
            if not raw_tx:
                return None

            if self.chain_adapter:
                return self.chain_adapter.parse_transaction(raw_tx)

            # Basic return
            from ..chains.base import TransactionType

            return Transaction(
                hash=tx_hash,
                chain="bitcoin",
                block_number=raw_tx.get("blockheight"),
                from_address="",
                to_address="",
                value=0,
                tx_type=TransactionType.TRANSFER,
                raw=raw_tx,
            )

        except Exception:
            return None

    def get_block(self, block_number: int) -> dict[str, Any] | None:
        """Get block data by number."""
        if self.chain in ("ethereum", "eth"):
            try:
                block = self._web3.eth.get_block(block_number, full_transactions=True)
                return dict(block)
            except Exception:
                return None
        return None

    def close(self) -> None:
        """Clean up connection."""
        self._web3 = None
        self._btc_rpc = None
