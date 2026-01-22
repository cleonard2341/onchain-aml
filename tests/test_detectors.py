"""Tests for AML pattern detectors."""

import json
from decimal import Decimal
from datetime import datetime, timezone
from pathlib import Path

import pytest

from chain_scanner import Scanner, Transaction, TransactionType, RiskLevel
from chain_scanner.config import ScannerConfig
from chain_scanner.detectors.sanctions import SanctionsDetector
from chain_scanner.detectors.mixer import MixerDetector
from chain_scanner.detectors.structuring import StructuringDetector
from chain_scanner.detectors.bridges import BridgesDetector
from chain_scanner.detectors.privacy_coins import PrivacyCoinsDetector


FIXTURES_DIR = Path(__file__).parent / "fixtures"


# Helper to create test transactions
def create_transaction(
    tx_hash: str = "0x123",
    from_addr: str = "0xfrom",
    to_addr: str = "0xto",
    value: Decimal = Decimal("1.0"),
    timestamp: datetime | None = None,
    chain: str = "ethereum",
    value_usd: Decimal | None = None,
) -> Transaction:
    return Transaction(
        hash=tx_hash,
        chain=chain,
        from_address=from_addr,
        to_address=to_addr,
        value=value,
        value_usd=value_usd,
        timestamp=timestamp or datetime.now(timezone.utc),
        tx_type=TransactionType.TRANSFER,
    )


class TestSanctionsDetector:
    """Tests for sanctions detector."""

    def test_sanctioned_address_detected(self):
        """Test that sanctioned addresses are detected."""
        detector = SanctionsDetector()

        # OFAC sanctioned address (Tornado Cash)
        sanctioned_addr = "0x8589427373D6D84E98730D7795D8f6f8731FDA16"

        assert detector.is_sanctioned(sanctioned_addr) is True
        assert detector.is_sanctioned(sanctioned_addr.lower()) is True

    def test_clean_address_not_flagged(self):
        """Test that clean addresses are not flagged."""
        detector = SanctionsDetector()

        clean_addr = "0x1234567890123456789012345678901234567890"
        assert detector.is_sanctioned(clean_addr) is False

    def test_sanctions_in_transaction(self):
        """Test detection of sanctioned address in transactions."""
        detector = SanctionsDetector()

        tx = create_transaction(
            to_addr="0x8589427373D6D84E98730D7795D8f6f8731FDA16"
        )

        result = detector.analyze_transactions([tx])

        assert result.has_flags
        assert len(result.flags) == 1
        assert result.flags[0].type == "SANCTIONS"
        assert result.flags[0].severity == RiskLevel.CRITICAL

    def test_no_flags_for_clean_transactions(self):
        """Test no flags for clean transactions."""
        detector = SanctionsDetector()

        txs = [
            create_transaction(
                from_addr="0x1111111111111111111111111111111111111111",
                to_addr="0x2222222222222222222222222222222222222222",
            )
        ]

        result = detector.analyze_transactions(txs)
        assert not result.has_flags


class TestMixerDetector:
    """Tests for mixer detector."""

    def test_tornado_cash_deposit_detected(self):
        """Test detection of Tornado Cash deposits."""
        detector = MixerDetector()

        # Tornado Cash contract
        tornado_addr = "0x47CE0C6eD5B0Ce3d3A51fdb1C52DC66a7c3c2936"

        assert detector.is_known_mixer(tornado_addr) is True

    def test_mixer_transaction_flagged(self):
        """Test that mixer transactions are flagged."""
        detector = MixerDetector()

        tx = create_transaction(
            to_addr="0x47CE0C6eD5B0Ce3d3A51fdb1C52DC66a7c3c2936"
        )

        result = detector.analyze_transactions([tx])

        assert result.has_flags
        assert result.flags[0].type == "MIXER"
        assert result.flags[0].severity == RiskLevel.HIGH

    def test_clean_address_not_mixer(self):
        """Test that clean addresses are not flagged as mixers."""
        detector = MixerDetector()

        clean_addr = "0x1234567890123456789012345678901234567890"
        assert detector.is_known_mixer(clean_addr) is False


class TestStructuringDetector:
    """Tests for structuring pattern detector."""

    def test_structuring_pattern_detected(self):
        """Test detection of structuring pattern."""
        detector = StructuringDetector()

        # Create transactions just below $10k threshold
        base_time = datetime.now(timezone.utc)
        txs = []
        for i in range(5):
            txs.append(create_transaction(
                tx_hash=f"0xstruct{i}",
                value=Decimal("4.0"),  # ~$9,500 if ETH ~$2,375
                value_usd=Decimal("9800") + Decimal(str(i * 50)),
                timestamp=base_time,
            ))

        result = detector.analyze_transactions(
            txs,
            target_address="0xfrom",
        )

        assert result.has_flags
        assert any("structuring" in f.details.lower() for f in result.flags)

    def test_normal_transactions_not_flagged(self):
        """Test that normal transactions are not flagged."""
        detector = StructuringDetector()

        # Create transactions with varying amounts
        txs = [
            create_transaction(value_usd=Decimal("100")),
            create_transaction(value_usd=Decimal("5000")),
            create_transaction(value_usd=Decimal("15000")),
        ]

        result = detector.analyze_transactions(txs)
        # Should not have structuring flags (amounts too varied)
        assert not any("structuring" in f.details.lower() for f in result.flags)


class TestBridgesDetector:
    """Tests for bridge detector."""

    def test_bridge_interaction_detected(self):
        """Test detection of bridge interactions."""
        detector = BridgesDetector()

        # Wormhole bridge address
        wormhole_addr = "0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B"

        assert detector.is_bridge_address(wormhole_addr) is True

    def test_bridge_transaction_flagged(self):
        """Test that bridge transactions are flagged."""
        detector = BridgesDetector()

        tx = create_transaction(
            to_addr="0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B"
        )

        result = detector.analyze_transactions([tx])

        assert result.has_flags
        assert result.flags[0].type == "BRIDGES"


class TestPrivacyCoinsDetector:
    """Tests for privacy coin detector."""

    def test_railgun_detected(self):
        """Test detection of RAILGUN interactions."""
        detector = PrivacyCoinsDetector()

        railgun_addr = "0xFA7093CDD9EE6932B4eb2c9e1cde7CE00B1FA4b9"

        assert detector.is_privacy_address(railgun_addr) is True

    def test_privacy_transaction_flagged(self):
        """Test that privacy protocol transactions are flagged."""
        detector = PrivacyCoinsDetector()

        tx = create_transaction(
            to_addr="0xFA7093CDD9EE6932B4eb2c9e1cde7CE00B1FA4b9"
        )

        result = detector.analyze_transactions([tx])

        assert result.has_flags
        assert result.flags[0].type == "PRIVACY_COINS"


class TestScannerIntegration:
    """Integration tests for the Scanner class."""

    def test_scan_clean_wallet(self):
        """Test scanning a clean wallet fixture."""
        fixture_path = FIXTURES_DIR / "clean_wallet.json"

        if not fixture_path.exists():
            pytest.skip("Fixture file not found")

        scanner = Scanner(chain="ethereum")
        result = scanner.scan_file(fixture_path)

        assert result.risk_score < 50
        assert result.risk_level in (RiskLevel.LOW, RiskLevel.MEDIUM)

    def test_scan_flagged_wallet(self):
        """Test scanning a flagged wallet fixture."""
        fixture_path = FIXTURES_DIR / "flagged_wallet.json"

        if not fixture_path.exists():
            pytest.skip("Fixture file not found")

        scanner = Scanner(chain="ethereum")
        result = scanner.scan_file(fixture_path)

        assert result.risk_score > 50
        assert len(result.flags) > 0

        # Should detect mixer usage
        flag_types = {f.type for f in result.flags}
        assert "MIXER" in flag_types or "SANCTIONS" in flag_types

    def test_scan_structuring_pattern(self):
        """Test scanning structuring pattern fixture."""
        fixture_path = FIXTURES_DIR / "structuring_pattern.json"

        if not fixture_path.exists():
            pytest.skip("Fixture file not found")

        scanner = Scanner(chain="ethereum")
        result = scanner.scan_file(
            fixture_path,
            target_address="0xstruct000000000000000000000000000000000"
        )

        # Should detect structuring
        assert any("structuring" in f.details.lower() for f in result.flags)

    def test_scanner_with_custom_config(self):
        """Test scanner with custom configuration."""
        config = ScannerConfig()
        config.structuring.threshold_usd = 5000.0
        config.structuring.min_transactions = 2

        scanner = Scanner(chain="ethereum", config=config)
        assert scanner.config.structuring.threshold_usd == 5000.0

    def test_scanner_address_validation(self):
        """Test that invalid addresses are rejected."""
        scanner = Scanner(chain="ethereum")

        with pytest.raises(ValueError, match="Invalid address"):
            scanner.scan_address("not-an-address")

    def test_scanner_chain_selection(self):
        """Test scanner chain selection."""
        eth_scanner = Scanner(chain="ethereum")
        assert eth_scanner.chain_adapter.chain_id == "ethereum"

        btc_scanner = Scanner(chain="bitcoin")
        assert btc_scanner.chain_adapter.chain_id == "bitcoin"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
