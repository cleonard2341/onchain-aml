"""Cached API data source for blockchain explorers."""

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Iterator

import requests

from ..chains.base import AddressInfo, ChainAdapter, Transaction
from .base import DataSource


class APISource(DataSource):
    """Data source using blockchain explorer APIs with local caching."""

    source_type = "api"

    # API endpoints
    ETHERSCAN_BASE = "https://api.etherscan.io/api"
    BLOCKCYPHER_BASE = "https://api.blockcypher.com/v1"

    def __init__(
        self,
        chain: str = "ethereum",
        api_key: str | None = None,
        chain_adapter: ChainAdapter | None = None,
        cache_enabled: bool = True,
        cache_dir: str = ".chain_scanner_cache",
        cache_ttl: int = 3600,
    ):
        """
        Initialize API source.

        Args:
            chain: Blockchain ("ethereum", "bitcoin")
            api_key: API key (Etherscan, BlockCypher, etc.)
            chain_adapter: Chain adapter for parsing
            cache_enabled: Whether to cache API responses
            cache_dir: Directory for cache files
            cache_ttl: Cache time-to-live in seconds
        """
        self.chain = chain.lower()
        self.api_key = api_key
        self.chain_adapter = chain_adapter
        self.cache_enabled = cache_enabled
        self.cache_dir = Path(cache_dir)
        self.cache_ttl = cache_ttl

        if self.cache_enabled:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

        self._session = requests.Session()

    def get_transactions(
        self,
        address: str,
        start_block: int | None = None,
        end_block: int | None = None,
        limit: int | None = None,
    ) -> Iterator[Transaction]:
        """Get transactions for an address from API."""
        if self.chain in ("ethereum", "eth"):
            yield from self._get_etherscan_transactions(
                address, start_block, end_block, limit
            )
        elif self.chain in ("bitcoin", "btc"):
            yield from self._get_blockcypher_transactions(
                address, start_block, end_block, limit
            )
        else:
            raise ValueError(f"Unsupported chain: {self.chain}")

    def _get_etherscan_transactions(
        self,
        address: str,
        start_block: int | None,
        end_block: int | None,
        limit: int | None,
    ) -> Iterator[Transaction]:
        """Fetch transactions from Etherscan API."""
        params = {
            "module": "account",
            "action": "txlist",
            "address": address,
            "startblock": start_block or 0,
            "endblock": end_block or 99999999,
            "sort": "desc",
        }

        if self.api_key:
            params["apikey"] = self.api_key

        data = self._cached_request(self.ETHERSCAN_BASE, params)

        if not data or data.get("status") != "1":
            return

        transactions = data.get("result", [])
        count = 0

        for raw_tx in transactions:
            if self.chain_adapter:
                tx = self.chain_adapter.parse_transaction(raw_tx)
            else:
                tx = self._parse_etherscan_tx(raw_tx)

            yield tx
            count += 1

            if limit and count >= limit:
                break

    def _get_blockcypher_transactions(
        self,
        address: str,
        start_block: int | None,
        end_block: int | None,
        limit: int | None,
    ) -> Iterator[Transaction]:
        """Fetch transactions from BlockCypher API."""
        url = f"{self.BLOCKCYPHER_BASE}/btc/main/addrs/{address}/full"
        params = {"limit": limit or 50}

        if self.api_key:
            params["token"] = self.api_key

        data = self._cached_request(url, params, method="get_direct")

        if not data:
            return

        transactions = data.get("txs", [])

        for raw_tx in transactions:
            # Filter by block if needed
            block_height = raw_tx.get("block_height", 0)
            if start_block and block_height < start_block:
                continue
            if end_block and block_height > end_block:
                continue

            if self.chain_adapter:
                tx = self.chain_adapter.parse_transaction(raw_tx)
            else:
                tx = self._parse_blockcypher_tx(raw_tx)

            yield tx

    def get_internal_transactions(
        self,
        address: str,
        start_block: int | None = None,
        end_block: int | None = None,
    ) -> Iterator[Transaction]:
        """Get internal (trace) transactions from Etherscan."""
        if self.chain not in ("ethereum", "eth"):
            return

        params = {
            "module": "account",
            "action": "txlistinternal",
            "address": address,
            "startblock": start_block or 0,
            "endblock": end_block or 99999999,
            "sort": "desc",
        }

        if self.api_key:
            params["apikey"] = self.api_key

        data = self._cached_request(self.ETHERSCAN_BASE, params)

        if not data or data.get("status") != "1":
            return

        for raw_tx in data.get("result", []):
            if self.chain_adapter:
                tx = self.chain_adapter.parse_transaction(raw_tx)
            else:
                tx = self._parse_etherscan_tx(raw_tx)

            # Mark as internal
            from ..chains.base import TransactionType
            tx.tx_type = TransactionType.INTERNAL

            yield tx

    def get_token_transfers(
        self,
        address: str,
        token_address: str | None = None,
        start_block: int | None = None,
        end_block: int | None = None,
    ) -> Iterator[Transaction]:
        """Get ERC-20 token transfers from Etherscan."""
        if self.chain not in ("ethereum", "eth"):
            return

        params = {
            "module": "account",
            "action": "tokentx",
            "address": address,
            "startblock": start_block or 0,
            "endblock": end_block or 99999999,
            "sort": "desc",
        }

        if token_address:
            params["contractaddress"] = token_address

        if self.api_key:
            params["apikey"] = self.api_key

        data = self._cached_request(self.ETHERSCAN_BASE, params)

        if not data or data.get("status") != "1":
            return

        for raw_tx in data.get("result", []):
            if self.chain_adapter:
                tx = self.chain_adapter.parse_transaction(raw_tx)
            else:
                tx = self._parse_etherscan_tx(raw_tx)

            yield tx

    def get_address_info(self, address: str) -> AddressInfo | None:
        """Get address information from API."""
        if self.chain in ("ethereum", "eth"):
            return self._get_etherscan_address_info(address)
        elif self.chain in ("bitcoin", "btc"):
            return self._get_blockcypher_address_info(address)
        return None

    def _get_etherscan_address_info(self, address: str) -> AddressInfo:
        """Get Ethereum address info from Etherscan."""
        from decimal import Decimal

        # Get balance
        params = {
            "module": "account",
            "action": "balance",
            "address": address,
            "tag": "latest",
        }

        if self.api_key:
            params["apikey"] = self.api_key

        data = self._cached_request(self.ETHERSCAN_BASE, params)

        balance = Decimal(0)
        if data and data.get("status") == "1":
            balance_wei = int(data.get("result", 0))
            balance = Decimal(balance_wei) / Decimal(10**18)

        # Get transaction count
        params["action"] = "txlist"
        params["startblock"] = 0
        params["endblock"] = 99999999
        params["page"] = 1
        params["offset"] = 1

        tx_data = self._cached_request(self.ETHERSCAN_BASE, params)
        tx_count = 0
        if tx_data and tx_data.get("status") == "1":
            tx_count = len(tx_data.get("result", []))

        return AddressInfo(
            address=address,
            chain="ethereum",
            balance=balance,
            tx_count=tx_count,
        )

    def _get_blockcypher_address_info(self, address: str) -> AddressInfo:
        """Get Bitcoin address info from BlockCypher."""
        from decimal import Decimal

        url = f"{self.BLOCKCYPHER_BASE}/btc/main/addrs/{address}"
        params = {}
        if self.api_key:
            params["token"] = self.api_key

        data = self._cached_request(url, params, method="get_direct")

        if not data:
            return AddressInfo(address=address, chain="bitcoin")

        balance_sat = data.get("balance", 0)
        balance = Decimal(balance_sat) / Decimal(10**8)

        return AddressInfo(
            address=address,
            chain="bitcoin",
            balance=balance,
            tx_count=data.get("n_tx", 0),
        )

    def get_transaction(self, tx_hash: str) -> Transaction | None:
        """Get a single transaction by hash."""
        if self.chain in ("ethereum", "eth"):
            params = {
                "module": "proxy",
                "action": "eth_getTransactionByHash",
                "txhash": tx_hash,
            }
            if self.api_key:
                params["apikey"] = self.api_key

            data = self._cached_request(self.ETHERSCAN_BASE, params)
            if data and data.get("result"):
                if self.chain_adapter:
                    return self.chain_adapter.parse_transaction(data["result"])
                return self._parse_etherscan_tx(data["result"])

        elif self.chain in ("bitcoin", "btc"):
            url = f"{self.BLOCKCYPHER_BASE}/btc/main/txs/{tx_hash}"
            params = {}
            if self.api_key:
                params["token"] = self.api_key

            data = self._cached_request(url, params, method="get_direct")
            if data:
                if self.chain_adapter:
                    return self.chain_adapter.parse_transaction(data)
                return self._parse_blockcypher_tx(data)

        return None

    def _cached_request(
        self,
        url: str,
        params: dict[str, Any],
        method: str = "get",
    ) -> dict[str, Any] | None:
        """Make a cached API request."""
        # Generate cache key
        cache_key = self._cache_key(url, params)
        cache_path = self.cache_dir / f"{cache_key}.json"

        # Check cache
        if self.cache_enabled and cache_path.exists():
            try:
                with open(cache_path, "r") as f:
                    cached = json.load(f)

                if time.time() - cached.get("timestamp", 0) < self.cache_ttl:
                    return cached.get("data")
            except (json.JSONDecodeError, IOError) as e:
                # Delete corrupted cache file
                import logging
                logging.warning(f"Corrupted cache file {cache_path}, removing: {e}")
                try:
                    cache_path.unlink()
                except OSError:
                    pass

        # Make request
        import logging
        try:
            if method == "get_direct":
                response = self._session.get(url, params=params, timeout=30)
            else:
                response = self._session.get(url, params=params, timeout=30)

            response.raise_for_status()
            data = response.json()

            # Cache response
            if self.cache_enabled:
                try:
                    with open(cache_path, "w") as f:
                        json.dump({"timestamp": time.time(), "data": data}, f)
                except IOError as e:
                    logging.warning(f"Failed to write cache file {cache_path}: {e}")

            return data

        except requests.exceptions.Timeout:
            logging.warning(f"Request timeout for {url}")
            return None
        except requests.exceptions.ConnectionError as e:
            logging.warning(f"Connection error for {url}: {e}")
            return None
        except requests.exceptions.HTTPError as e:
            logging.warning(f"HTTP error for {url}: {e}")
            return None
        except requests.RequestException as e:
            logging.error(f"Request failed for {url}: {e}")
            return None
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON response from {url}: {e}")
            return None

    def _cache_key(self, url: str, params: dict[str, Any]) -> str:
        """Generate cache key from request parameters."""
        # Remove API key from cache key
        cache_params = {k: v for k, v in params.items() if k not in ("apikey", "token")}
        key_data = f"{url}:{json.dumps(cache_params, sort_keys=True)}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def _parse_etherscan_tx(self, raw_tx: dict[str, Any]) -> Transaction:
        """Parse Etherscan transaction format."""
        from decimal import Decimal
        from datetime import datetime, timezone
        from ..chains.base import TransactionType

        value_wei = int(raw_tx.get("value", 0))
        value = Decimal(value_wei) / Decimal(10**18)

        timestamp = None
        if "timeStamp" in raw_tx:
            timestamp = datetime.fromtimestamp(int(raw_tx["timeStamp"]), tz=timezone.utc)

        return Transaction(
            hash=raw_tx.get("hash", raw_tx.get("transactionHash", "")),
            chain="ethereum",
            block_number=int(raw_tx.get("blockNumber", 0)),
            timestamp=timestamp,
            from_address=raw_tx.get("from", ""),
            to_address=raw_tx.get("to"),
            value=value,
            tx_type=TransactionType.TRANSFER,
            raw=raw_tx,
        )

    def _parse_blockcypher_tx(self, raw_tx: dict[str, Any]) -> Transaction:
        """Parse BlockCypher transaction format."""
        from decimal import Decimal
        from datetime import datetime
        from ..chains.base import TransactionType

        # Calculate total output value
        total_value = sum(out.get("value", 0) for out in raw_tx.get("outputs", []))
        value = Decimal(total_value) / Decimal(10**8)

        # Parse timestamp
        timestamp = None
        if "received" in raw_tx:
            try:
                timestamp = datetime.fromisoformat(
                    raw_tx["received"].replace("Z", "+00:00")
                )
            except ValueError:
                pass

        # Get addresses
        from_addresses = []
        for inp in raw_tx.get("inputs", []):
            if inp.get("addresses"):
                from_addresses.extend(inp["addresses"])

        to_addresses = []
        for out in raw_tx.get("outputs", []):
            if out.get("addresses"):
                to_addresses.extend(out["addresses"])

        return Transaction(
            hash=raw_tx.get("hash", ""),
            chain="bitcoin",
            block_number=raw_tx.get("block_height"),
            timestamp=timestamp,
            from_address=from_addresses[0] if from_addresses else "",
            to_address=to_addresses[0] if to_addresses else None,
            value=value,
            tx_type=TransactionType.TRANSFER,
            inputs=raw_tx.get("inputs", []),
            outputs=raw_tx.get("outputs", []),
            raw=raw_tx,
        )

    def clear_cache(self) -> int:
        """Clear all cached data. Returns number of files removed."""
        if not self.cache_dir.exists():
            return 0

        count = 0
        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink()
            count += 1

        return count

    def close(self) -> None:
        """Clean up session."""
        self._session.close()
