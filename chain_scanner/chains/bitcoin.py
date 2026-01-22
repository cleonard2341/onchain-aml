"""Bitcoin chain adapter (UTXO model)."""

import re
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from .base import AddressInfo, ChainAdapter, Transaction, TransactionType


class BitcoinAdapter(ChainAdapter):
    """Adapter for Bitcoin and UTXO-based chains."""

    chain_id = "bitcoin"
    chain_name = "Bitcoin"
    native_token = "BTC"
    native_decimals = 8  # Satoshis

    # Address format patterns
    P2PKH_PATTERN = re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$")  # Legacy
    P2SH_PATTERN = re.compile(r"^3[a-km-zA-HJ-NP-Z1-9]{25,34}$")  # Script hash
    BECH32_PATTERN = re.compile(r"^bc1[ac-hj-np-z02-9]{39,59}$")  # Native SegWit
    BECH32M_PATTERN = re.compile(r"^bc1p[ac-hj-np-z02-9]{58}$")  # Taproot

    def normalize_address(self, address: str) -> str:
        """Normalize Bitcoin address format."""
        # Bitcoin addresses are case-sensitive, just strip whitespace
        return address.strip()

    def is_valid_address(self, address: str) -> bool:
        """Check if address is a valid Bitcoin address."""
        if not address:
            return False

        address = address.strip()

        # Check against known patterns
        if self.P2PKH_PATTERN.match(address):
            return True
        if self.P2SH_PATTERN.match(address):
            return True
        if self.BECH32_PATTERN.match(address):
            return True
        if self.BECH32M_PATTERN.match(address):
            return True

        return False

    def parse_transaction(self, raw_tx: dict[str, Any]) -> Transaction:
        """Parse raw Bitcoin transaction data into normalized format."""
        tx_hash = raw_tx.get("hash") or raw_tx.get("txid", "")

        # Parse timestamp
        timestamp = None
        ts_raw = raw_tx.get("time") or raw_tx.get("received") or raw_tx.get("timestamp")
        if ts_raw:
            if isinstance(ts_raw, str):
                # Handle ISO format or Unix timestamp
                try:
                    timestamp = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                except ValueError:
                    ts_raw = int(ts_raw)
                    timestamp = datetime.fromtimestamp(ts_raw, tz=timezone.utc)
            else:
                timestamp = datetime.fromtimestamp(ts_raw, tz=timezone.utc)

        # Parse block info
        block_num = raw_tx.get("block_height") or raw_tx.get("blockheight")

        # Parse inputs and outputs
        inputs = self._parse_inputs(raw_tx.get("inputs", raw_tx.get("vin", [])))
        outputs = self._parse_outputs(raw_tx.get("outputs", raw_tx.get("vout", [])))

        # Calculate total input/output values
        total_input = sum(inp.get("value", 0) for inp in inputs)
        total_output = sum(out.get("value", 0) for out in outputs)

        # Determine primary from/to addresses
        from_address = self._get_primary_input_address(inputs)
        to_address = self._get_primary_output_address(outputs, from_address)

        # Calculate value (largest output that's not change)
        value = self._calculate_transaction_value(inputs, outputs, from_address)

        # Calculate fee
        fee = None
        if total_input > 0 and total_output > 0:
            fee_satoshi = total_input - total_output
            if fee_satoshi > 0:
                fee = self.wei_to_native(fee_satoshi)

        return Transaction(
            hash=tx_hash,
            chain=self.chain_id,
            block_number=block_num,
            timestamp=timestamp,
            from_address=from_address,
            to_address=to_address,
            value=self.wei_to_native(value) if value else Decimal(0),
            value_usd=raw_tx.get("value_usd"),
            fee=fee,
            tx_type=TransactionType.TRANSFER,
            inputs=inputs,
            outputs=outputs,
            raw=raw_tx,
        )

    def parse_address_info(self, raw_data: dict[str, Any]) -> AddressInfo:
        """Parse raw address data into normalized AddressInfo model."""
        address = self.normalize_address(raw_data.get("address", ""))

        # Balance in satoshis
        balance_sat = raw_data.get("balance", raw_data.get("final_balance", 0))
        if isinstance(balance_sat, str):
            balance_sat = int(balance_sat)
        balance = self.wei_to_native(balance_sat)

        # Transaction count
        tx_count = raw_data.get("n_tx", raw_data.get("txCount", 0))

        return AddressInfo(
            address=address,
            chain=self.chain_id,
            balance=balance,
            tx_count=tx_count,
            is_contract=False,  # Bitcoin doesn't have contracts in the same way
            labels=raw_data.get("labels", []),
        )

    def _parse_inputs(self, raw_inputs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Parse transaction inputs."""
        inputs = []
        for inp in raw_inputs:
            parsed = {
                "tx_hash": inp.get("prev_hash") or inp.get("txid"),
                "output_index": inp.get("output_index") or inp.get("vout"),
                "value": 0,
                "addresses": [],
            }

            # Get value (in satoshis)
            if "output_value" in inp:
                parsed["value"] = inp["output_value"]
            elif "value" in inp:
                parsed["value"] = inp["value"]

            # Get addresses
            if "addresses" in inp:
                parsed["addresses"] = inp["addresses"]
            elif "prev_out" in inp and "addr" in inp["prev_out"]:
                parsed["addresses"] = [inp["prev_out"]["addr"]]
            elif "scriptSig" in inp:
                # Would need to decode scriptSig for address
                pass

            inputs.append(parsed)
        return inputs

    def _parse_outputs(self, raw_outputs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Parse transaction outputs."""
        outputs = []
        for idx, out in enumerate(raw_outputs):
            parsed = {
                "index": idx,
                "value": 0,
                "addresses": [],
                "spent": out.get("spent", False),
            }

            # Get value (in satoshis)
            if "value" in out:
                val = out["value"]
                # Handle float BTC values
                if isinstance(val, float) and val < 100:
                    parsed["value"] = int(val * 10**8)
                else:
                    parsed["value"] = int(val) if isinstance(val, (int, float)) else 0

            # Get addresses
            if "addresses" in out:
                parsed["addresses"] = out["addresses"]
            elif "addr" in out:
                parsed["addresses"] = [out["addr"]]
            elif "scriptPubKey" in out:
                script = out["scriptPubKey"]
                if "addresses" in script:
                    parsed["addresses"] = script["addresses"]
                elif "address" in script:
                    parsed["addresses"] = [script["address"]]

            outputs.append(parsed)
        return outputs

    def _get_primary_input_address(self, inputs: list[dict[str, Any]]) -> str:
        """Get the primary sender address from inputs."""
        for inp in inputs:
            addresses = inp.get("addresses")
            if addresses and len(addresses) > 0 and addresses[0]:
                return addresses[0]
        return "unknown"

    def _get_primary_output_address(
        self,
        outputs: list[dict[str, Any]],
        from_address: str,
    ) -> str | None:
        """Get the primary recipient address (excluding change)."""
        # Find largest output that's not back to sender
        non_change_outputs = [
            out for out in outputs
            if out.get("addresses") and len(out["addresses"]) > 0 and from_address not in out["addresses"]
        ]

        if non_change_outputs:
            # Return address of largest non-change output
            largest = max(non_change_outputs, key=lambda x: x.get("value", 0))
            addresses = largest.get("addresses")
            if addresses and len(addresses) > 0 and addresses[0]:
                return addresses[0]

        # If all outputs go back to sender, return first output
        for out in outputs:
            addresses = out.get("addresses")
            if addresses and len(addresses) > 0 and addresses[0]:
                return addresses[0]

        return None

    def _calculate_transaction_value(
        self,
        inputs: list[dict[str, Any]],
        outputs: list[dict[str, Any]],
        from_address: str,
    ) -> int:
        """Calculate the transaction value (excluding change)."""
        # Sum outputs not going back to sender
        value = 0
        for out in outputs:
            if out.get("addresses") and from_address not in out["addresses"]:
                value += out.get("value", 0)

        # If no external outputs, use total output value
        if value == 0:
            value = sum(out.get("value", 0) for out in outputs)

        return value

    def is_coinjoin_transaction(self, transaction: Transaction) -> bool:
        """
        Check if a transaction appears to be a CoinJoin.

        CoinJoin characteristics:
        - Multiple inputs from different addresses
        - Multiple outputs of similar value
        """
        if not transaction.inputs or not transaction.outputs:
            return False

        # Get unique input addresses
        input_addresses = set()
        for inp in transaction.inputs:
            if inp.get("addresses"):
                input_addresses.update(inp["addresses"])

        # Multiple different input addresses suggest CoinJoin
        if len(input_addresses) < 2:
            return False

        # Check for outputs of similar values
        output_values = [out.get("value", 0) for out in transaction.outputs]
        if len(output_values) < 3:
            return False

        # Check if multiple outputs have similar values (within 1%)
        sorted_values = sorted(output_values, reverse=True)
        similar_count = 0
        for i in range(len(sorted_values) - 1):
            current_val = sorted_values[i]
            next_val = sorted_values[i + 1]
            # Guard against division by zero
            if current_val > 0:
                diff = abs(current_val - next_val) / current_val
                if diff < 0.01:  # Within 1%
                    similar_count += 1

        return similar_count >= 2
