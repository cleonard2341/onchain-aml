"""Tests for data sources."""

import json
import tempfile
from decimal import Decimal
from pathlib import Path

import pytest

from chain_scanner.sources.file_source import FileSource
from chain_scanner.chains.ethereum import EthereumAdapter


FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestFileSource:
    """Tests for file-based data source."""

    def test_load_json_file(self):
        """Test loading transactions from JSON file."""
        fixture_path = FIXTURES_DIR / "clean_wallet.json"

        if not fixture_path.exists():
            pytest.skip("Fixture file not found")

        adapter = EthereumAdapter()
        source = FileSource(fixture_path, chain_adapter=adapter)

        txs = list(source.get_all_transactions())
        assert len(txs) == 5

        # Check first transaction
        tx = txs[0]
        assert tx.hash.startswith("0x")
        assert tx.chain == "ethereum"
        assert tx.value > 0

    def test_load_csv_file(self):
        """Test loading transactions from CSV file."""
        # Create temporary CSV file
        csv_content = """hash,from,to,value,blockNumber,timeStamp
0xabc123,0x1111111111111111111111111111111111111111,0x2222222222222222222222222222222222222222,1000000000000000000,15000000,1672531200
0xdef456,0x2222222222222222222222222222222222222222,0x3333333333333333333333333333333333333333,500000000000000000,15000100,1672617600
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write(csv_content)
            csv_path = f.name

        try:
            adapter = EthereumAdapter()
            source = FileSource(csv_path, chain_adapter=adapter)

            txs = list(source.get_all_transactions())
            assert len(txs) == 2

            assert txs[0].hash == "0xabc123"
            assert txs[0].value == Decimal("1")  # 1 ETH
        finally:
            Path(csv_path).unlink()

    def test_filter_by_address(self):
        """Test filtering transactions by address."""
        fixture_path = FIXTURES_DIR / "clean_wallet.json"

        if not fixture_path.exists():
            pytest.skip("Fixture file not found")

        adapter = EthereumAdapter()
        source = FileSource(fixture_path, chain_adapter=adapter)

        address = "0x1234567890123456789012345678901234567890"
        txs = list(source.get_transactions(address))

        # All transactions should involve this address
        for tx in txs:
            assert (
                tx.from_address.lower() == address.lower() or
                tx.to_address.lower() == address.lower()
            )

    def test_get_transaction_by_hash(self):
        """Test getting a single transaction by hash."""
        fixture_path = FIXTURES_DIR / "clean_wallet.json"

        if not fixture_path.exists():
            pytest.skip("Fixture file not found")

        adapter = EthereumAdapter()
        source = FileSource(fixture_path, chain_adapter=adapter)

        # Get hash from fixture
        with open(fixture_path) as f:
            data = json.load(f)
        expected_hash = data["transactions"][0]["hash"]

        tx = source.get_transaction(expected_hash)
        assert tx is not None
        assert tx.hash == expected_hash

    def test_nonexistent_transaction(self):
        """Test getting a transaction that doesn't exist."""
        fixture_path = FIXTURES_DIR / "clean_wallet.json"

        if not fixture_path.exists():
            pytest.skip("Fixture file not found")

        source = FileSource(fixture_path)
        tx = source.get_transaction("0xnonexistent")
        assert tx is None

    def test_get_address_info(self):
        """Test getting address info from file."""
        fixture_path = FIXTURES_DIR / "clean_wallet.json"

        if not fixture_path.exists():
            pytest.skip("Fixture file not found")

        adapter = EthereumAdapter()
        source = FileSource(fixture_path, chain_adapter=adapter)

        address = "0x1234567890123456789012345678901234567890"
        info = source.get_address_info(address)

        assert info is not None
        assert info.address == address
        assert info.tx_count > 0

    def test_file_not_found(self):
        """Test error handling for missing file."""
        with pytest.raises(FileNotFoundError):
            FileSource("/nonexistent/path/file.json")

    def test_auto_format_detection(self):
        """Test automatic format detection."""
        # JSON
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b'[]')
            json_path = f.name

        try:
            source = FileSource(json_path)
            assert source.format == "json"
        finally:
            Path(json_path).unlink()

        # CSV
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            f.write(b'hash,from,to\n')
            csv_path = f.name

        try:
            source = FileSource(csv_path)
            assert source.format == "csv"
        finally:
            Path(csv_path).unlink()

    def test_format_override(self):
        """Test explicit format specification."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b'[]')
            path = f.name

        try:
            source = FileSource(path, format="json")
            assert source.format == "json"
        finally:
            Path(path).unlink()


class TestEthereumAdapter:
    """Tests for Ethereum chain adapter."""

    def test_address_validation(self):
        """Test Ethereum address validation."""
        adapter = EthereumAdapter()

        # Valid addresses
        assert adapter.is_valid_address("0x1234567890123456789012345678901234567890")
        assert adapter.is_valid_address("0xABCDEF1234567890123456789012345678901234")

        # Invalid addresses
        assert adapter.is_valid_address("not-an-address") is False
        assert adapter.is_valid_address("0x123") is False
        assert adapter.is_valid_address("") is False
        assert adapter.is_valid_address("1234567890123456789012345678901234567890") is False

    def test_address_normalization(self):
        """Test address normalization."""
        adapter = EthereumAdapter()

        # Should normalize to lowercase with 0x prefix
        normalized = adapter.normalize_address("0xABCDEF1234567890123456789012345678901234")
        assert normalized == "0xabcdef1234567890123456789012345678901234"

        normalized = adapter.normalize_address("  0x1234567890123456789012345678901234567890  ")
        assert normalized == "0x1234567890123456789012345678901234567890"

    def test_wei_conversion(self):
        """Test wei to ETH conversion."""
        adapter = EthereumAdapter()

        # 1 ETH
        assert adapter.wei_to_native(10**18) == Decimal(1)

        # 0.5 ETH
        assert adapter.wei_to_native(5 * 10**17) == Decimal("0.5")

        # String input
        assert adapter.wei_to_native("1000000000000000000") == Decimal(1)

    def test_parse_transaction(self):
        """Test transaction parsing."""
        adapter = EthereumAdapter()

        raw_tx = {
            "hash": "0xabc123",
            "from": "0x1111111111111111111111111111111111111111",
            "to": "0x2222222222222222222222222222222222222222",
            "value": "1000000000000000000",
            "blockNumber": "15000000",
            "timeStamp": "1672531200",
            "gasPrice": "20000000000",
            "gasUsed": "21000",
            "input": "0x",
        }

        tx = adapter.parse_transaction(raw_tx)

        assert tx.hash == "0xabc123"
        assert tx.chain == "ethereum"
        assert tx.value == Decimal(1)
        assert tx.block_number == 15000000
        assert tx.timestamp is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
