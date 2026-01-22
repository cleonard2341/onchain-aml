"""
Chain Scanner - On-Chain AML Pattern Detector

A local/offline AML pattern detection tool for cryptocurrency transactions.
Supports Ethereum and Bitcoin, multiple data input methods, and provides
both CLI and library interfaces.

Example usage:

    from chain_scanner import Scanner

    # Scan an address
    scanner = Scanner(chain="ethereum")
    result = scanner.scan_address("0x...")

    # Scan transactions from a file
    result = scanner.scan_file("transactions.json")

    # Access results
    print(f"Risk Score: {result.risk_score}")
    print(f"Risk Level: {result.risk_level}")
    for flag in result.flags:
        print(f"  - {flag.type}: {flag.details}")
"""

import logging

# Configure package-level logging
# Users can override this by configuring the 'chain_scanner' logger
_logger = logging.getLogger("chain_scanner")
_logger.addHandler(logging.NullHandler())  # Prevent "No handler found" warnings


def configure_logging(
    level: int = logging.WARNING,
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
) -> None:
    """Configure logging for chain-scanner.

    Args:
        level: Logging level (default: WARNING)
        format: Log message format
    """
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(format))
    _logger.addHandler(handler)
    _logger.setLevel(level)


from .scanner import Scanner, ScanResult
from .config import ScannerConfig
from .chains.base import Transaction, TransactionType, AddressInfo
from .detectors.base import Detector, DetectionResult, Flag, RiskLevel

__version__ = "0.1.0"
__author__ = "Chain Scanner Contributors"

__all__ = [
    # Main classes
    "Scanner",
    "ScanResult",
    "ScannerConfig",
    # Data models
    "Transaction",
    "TransactionType",
    "AddressInfo",
    # Detection
    "Detector",
    "DetectionResult",
    "Flag",
    "RiskLevel",
    # Utilities
    "configure_logging",
    # Metadata
    "__version__",
]
