"""Abstract base class for blockchain adapters."""

from abc import ABC, abstractmethod
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class TransactionType(str, Enum):
    """Type of blockchain transaction."""

    TRANSFER = "transfer"
    CONTRACT_CALL = "contract_call"
    CONTRACT_CREATION = "contract_creation"
    INTERNAL = "internal"
    TOKEN_TRANSFER = "token_transfer"


class Transaction(BaseModel):
    """Normalized transaction model across chains."""

    hash: str = Field(description="Transaction hash")
    chain: str = Field(description="Chain identifier (ethereum, bitcoin)")
    block_number: int | None = Field(default=None, description="Block number")
    timestamp: datetime | None = Field(default=None, description="Transaction timestamp")

    from_address: str = Field(description="Sender address")
    to_address: str | None = Field(default=None, description="Recipient address")

    value: Decimal = Field(description="Native token value transferred")
    value_usd: Decimal | None = Field(default=None, description="USD value at time of tx")

    fee: Decimal | None = Field(default=None, description="Transaction fee")
    fee_usd: Decimal | None = Field(default=None, description="Fee in USD")

    tx_type: TransactionType = Field(
        default=TransactionType.TRANSFER, description="Transaction type"
    )

    # Contract interaction
    contract_address: str | None = Field(
        default=None, description="Contract address if contract call"
    )
    method_id: str | None = Field(default=None, description="Method signature for contract calls")
    method_name: str | None = Field(default=None, description="Decoded method name")

    # Token transfer details
    token_address: str | None = Field(default=None, description="Token contract address")
    token_symbol: str | None = Field(default=None, description="Token symbol")
    token_value: Decimal | None = Field(default=None, description="Token amount transferred")

    # Bitcoin-specific (UTXO)
    inputs: list[dict[str, Any]] | None = Field(
        default=None, description="Transaction inputs (UTXO model)"
    )
    outputs: list[dict[str, Any]] | None = Field(
        default=None, description="Transaction outputs (UTXO model)"
    )

    # Raw data
    raw: dict[str, Any] = Field(default_factory=dict, description="Raw transaction data")

    class Config:
        json_encoders = {
            Decimal: str,
            datetime: lambda v: v.isoformat() if v else None,
        }


class AddressInfo(BaseModel):
    """Information about a blockchain address."""

    address: str = Field(description="The address")
    chain: str = Field(description="Chain identifier")

    balance: Decimal | None = Field(default=None, description="Current balance")
    balance_usd: Decimal | None = Field(default=None, description="Balance in USD")

    tx_count: int = Field(default=0, description="Total transaction count")
    first_seen: datetime | None = Field(default=None, description="First transaction timestamp")
    last_seen: datetime | None = Field(default=None, description="Last transaction timestamp")

    is_contract: bool = Field(default=False, description="Whether address is a contract")
    contract_name: str | None = Field(default=None, description="Contract name if known")

    labels: list[str] = Field(default_factory=list, description="Known labels for this address")


class ChainAdapter(ABC):
    """Abstract base class for blockchain adapters."""

    chain_id: str = ""
    chain_name: str = ""
    native_token: str = ""
    native_decimals: int = 18

    @abstractmethod
    def normalize_address(self, address: str) -> str:
        """Normalize address format for the chain."""
        pass

    @abstractmethod
    def is_valid_address(self, address: str) -> bool:
        """Check if address is valid for this chain."""
        pass

    @abstractmethod
    def parse_transaction(self, raw_tx: dict[str, Any]) -> Transaction:
        """Parse raw transaction data into normalized Transaction model."""
        pass

    @abstractmethod
    def parse_address_info(self, raw_data: dict[str, Any]) -> AddressInfo:
        """Parse raw address data into normalized AddressInfo model."""
        pass

    def wei_to_native(self, wei: int | str) -> Decimal:
        """Convert smallest unit to native token (e.g., wei to ETH)."""
        wei_int = int(wei) if isinstance(wei, str) else wei
        return Decimal(wei_int) / Decimal(10**self.native_decimals)

    def native_to_wei(self, native: Decimal | float) -> int:
        """Convert native token to smallest unit."""
        return int(Decimal(native) * Decimal(10**self.native_decimals))
