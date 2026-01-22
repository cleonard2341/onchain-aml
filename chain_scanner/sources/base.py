"""Abstract base class for data sources."""

from abc import ABC, abstractmethod
from typing import Iterator

from ..chains.base import AddressInfo, Transaction


class DataSource(ABC):
    """Abstract base class for data sources."""

    source_type: str = ""

    @abstractmethod
    def get_transactions(
        self,
        address: str,
        start_block: int | None = None,
        end_block: int | None = None,
        limit: int | None = None,
    ) -> Iterator[Transaction]:
        """
        Get transactions for an address.

        Args:
            address: The address to query
            start_block: Optional starting block number
            end_block: Optional ending block number
            limit: Maximum number of transactions to return

        Yields:
            Transaction objects
        """
        pass

    @abstractmethod
    def get_address_info(self, address: str) -> AddressInfo | None:
        """
        Get information about an address.

        Args:
            address: The address to query

        Returns:
            AddressInfo object or None if not found
        """
        pass

    @abstractmethod
    def get_transaction(self, tx_hash: str) -> Transaction | None:
        """
        Get a single transaction by hash.

        Args:
            tx_hash: The transaction hash

        Returns:
            Transaction object or None if not found
        """
        pass

    def get_internal_transactions(
        self,
        address: str,
        start_block: int | None = None,
        end_block: int | None = None,
    ) -> Iterator[Transaction]:
        """
        Get internal transactions for an address.

        Internal transactions are calls between contracts.
        Not all sources support this.

        Yields:
            Transaction objects with tx_type=INTERNAL
        """
        return iter([])

    def get_token_transfers(
        self,
        address: str,
        token_address: str | None = None,
        start_block: int | None = None,
        end_block: int | None = None,
    ) -> Iterator[Transaction]:
        """
        Get token transfers for an address.

        Args:
            address: The address to query
            token_address: Optional specific token contract to filter
            start_block: Optional starting block number
            end_block: Optional ending block number

        Yields:
            Transaction objects with tx_type=TOKEN_TRANSFER
        """
        return iter([])

    def close(self) -> None:
        """Clean up any resources."""
        pass

    def __enter__(self) -> "DataSource":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
