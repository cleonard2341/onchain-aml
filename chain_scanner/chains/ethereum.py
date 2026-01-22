"""Ethereum/EVM chain adapter."""

import re
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from .base import AddressInfo, ChainAdapter, Transaction, TransactionType


class EthereumAdapter(ChainAdapter):
    """Adapter for Ethereum and EVM-compatible chains."""

    chain_id = "ethereum"
    chain_name = "Ethereum"
    native_token = "ETH"
    native_decimals = 18

    # Common method signatures
    METHOD_SIGNATURES = {
        "0xa9059cbb": "transfer",
        "0x23b872dd": "transferFrom",
        "0x095ea7b3": "approve",
        "0x40c10f19": "mint",
        "0x42966c68": "burn",
        "0xd0e30db0": "deposit",
        "0x2e1a7d4d": "withdraw",
        "0x": "transfer",  # Simple ETH transfer
    }

    def normalize_address(self, address: str) -> str:
        """Normalize Ethereum address to checksummed format."""
        address = address.strip().lower()

        # Remove 0x prefix if present for processing
        if address.startswith("0x"):
            address = address[2:]

        # Ensure it's 40 hex characters
        if len(address) != 40:
            return f"0x{address}"

        # Return with 0x prefix (lowercase for now, could implement EIP-55)
        return f"0x{address}"

    def is_valid_address(self, address: str) -> bool:
        """Check if address is a valid Ethereum address."""
        if not address:
            return False

        # Must start with 0x
        if not address.startswith("0x") and not address.startswith("0X"):
            return False

        # Must be 42 characters (0x + 40 hex chars)
        if len(address) != 42:
            return False

        # Must be valid hex
        try:
            int(address[2:], 16)
            return True
        except ValueError:
            return False

    def parse_transaction(self, raw_tx: dict[str, Any]) -> Transaction:
        """Parse raw Ethereum transaction data into normalized format."""
        # Handle various API formats (Etherscan, web3, etc.)
        tx_hash = raw_tx.get("hash") or raw_tx.get("transactionHash", "")

        # Parse addresses
        from_addr = self.normalize_address(raw_tx.get("from", "0x" + "0" * 40))
        to_addr = raw_tx.get("to")
        if to_addr:
            to_addr = self.normalize_address(to_addr)

        # Parse value (handle hex or decimal)
        value_raw = raw_tx.get("value", 0)
        if isinstance(value_raw, str):
            if value_raw.startswith("0x"):
                value_wei = int(value_raw, 16)
            else:
                value_wei = int(value_raw)
        else:
            value_wei = int(value_raw)

        value = self.wei_to_native(value_wei)

        # Parse block number
        block_num = raw_tx.get("blockNumber")
        if isinstance(block_num, str):
            block_num = int(block_num, 16) if block_num.startswith("0x") else int(block_num)

        # Parse timestamp
        timestamp = None
        ts_raw = raw_tx.get("timeStamp") or raw_tx.get("timestamp")
        if ts_raw:
            if isinstance(ts_raw, str):
                ts_raw = int(ts_raw)
            timestamp = datetime.fromtimestamp(ts_raw, tz=timezone.utc)

        # Determine transaction type
        tx_type = self._determine_tx_type(raw_tx, to_addr)

        # Parse method info
        input_data = raw_tx.get("input", raw_tx.get("data", ""))
        method_id = input_data[:10] if input_data and len(input_data) >= 10 else None
        method_name = self.METHOD_SIGNATURES.get(method_id) if method_id else None

        # Calculate fee
        gas_price = raw_tx.get("gasPrice", 0)
        gas_used = raw_tx.get("gasUsed") or raw_tx.get("gas", 0)
        fee = None
        if gas_price and gas_used:
            if isinstance(gas_price, str):
                gas_price = int(gas_price, 16) if gas_price.startswith("0x") else int(gas_price)
            if isinstance(gas_used, str):
                gas_used = int(gas_used, 16) if gas_used.startswith("0x") else int(gas_used)
            fee = self.wei_to_native(gas_price * gas_used)

        # Check for token transfer
        token_address = None
        token_value = None
        token_symbol = None

        if raw_tx.get("contractAddress") and tx_type == TransactionType.TOKEN_TRANSFER:
            token_address = self.normalize_address(raw_tx["contractAddress"])
            token_symbol = raw_tx.get("tokenSymbol")
            token_value_raw = raw_tx.get("value", 0)
            token_decimals = int(raw_tx.get("tokenDecimal", 18))
            if isinstance(token_value_raw, str):
                token_value_raw = int(token_value_raw)
            token_value = Decimal(token_value_raw) / Decimal(10**token_decimals)

        return Transaction(
            hash=tx_hash,
            chain=self.chain_id,
            block_number=block_num,
            timestamp=timestamp,
            from_address=from_addr,
            to_address=to_addr,
            value=value,
            value_usd=raw_tx.get("value_usd"),
            fee=fee,
            tx_type=tx_type,
            contract_address=to_addr if tx_type == TransactionType.CONTRACT_CALL else None,
            method_id=method_id,
            method_name=method_name,
            token_address=token_address,
            token_symbol=token_symbol,
            token_value=token_value,
            raw=raw_tx,
        )

    def parse_address_info(self, raw_data: dict[str, Any]) -> AddressInfo:
        """Parse raw address data into normalized AddressInfo model."""
        address = self.normalize_address(raw_data.get("address", ""))

        balance_raw = raw_data.get("balance", 0)
        if isinstance(balance_raw, str):
            if balance_raw.startswith("0x"):
                balance_raw = int(balance_raw, 16)
            else:
                balance_raw = int(balance_raw)
        balance = self.wei_to_native(balance_raw)

        return AddressInfo(
            address=address,
            chain=self.chain_id,
            balance=balance,
            tx_count=raw_data.get("txCount", 0),
            is_contract=raw_data.get("isContract", False),
            contract_name=raw_data.get("contractName"),
            labels=raw_data.get("labels", []),
        )

    def _determine_tx_type(self, raw_tx: dict[str, Any], to_addr: str | None) -> TransactionType:
        """Determine the transaction type from raw data."""
        # Check for token transfer format (from Etherscan token tx API)
        if raw_tx.get("tokenSymbol") or raw_tx.get("tokenName"):
            return TransactionType.TOKEN_TRANSFER

        # Contract creation (no to address)
        if not to_addr:
            return TransactionType.CONTRACT_CREATION

        # Internal transaction
        if raw_tx.get("type") == "call" or raw_tx.get("traceId"):
            return TransactionType.INTERNAL

        # Check for contract call (has input data beyond 0x)
        input_data = raw_tx.get("input", raw_tx.get("data", ""))
        if input_data and input_data != "0x" and len(input_data) > 2:
            return TransactionType.CONTRACT_CALL

        return TransactionType.TRANSFER

    def is_contract_address(self, address: str) -> bool:
        """
        Check if an address is a contract.

        Note: This is a basic check. For accurate detection,
        use web3.eth.get_code() with an actual node connection.
        """
        # Can't determine without on-chain data
        # Return False as default, actual check should use node
        return False
