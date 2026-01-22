"""Main Scanner class - primary API for chain-scanner."""

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .chains.base import ChainAdapter, Transaction
from .chains.ethereum import EthereumAdapter
from .chains.bitcoin import BitcoinAdapter
from .config import ScannerConfig, DEFAULT_CONFIG
from .detectors import DETECTOR_REGISTRY, Detector, DetectionResult, RiskLevel, Flag
from .sources.base import DataSource
from .sources.file_source import FileSource
from .sources.api_source import APISource


class ScanResult(BaseModel):
    """Complete scan result for an address or transaction set."""

    address: str | None = Field(default=None, description="Scanned address")
    chain: str = Field(description="Blockchain chain")

    risk_score: int = Field(description="Overall risk score (0-100)")
    risk_level: RiskLevel = Field(description="Risk classification")

    flags: list[Flag] = Field(default_factory=list, description="All detected flags")

    detector_results: list[DetectionResult] = Field(
        default_factory=list, description="Results from each detector"
    )

    transaction_count: int = Field(default=0, description="Number of transactions analyzed")

    summary: str = Field(default="", description="Human-readable summary")

    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class Scanner:
    """
    Main scanner class for AML pattern detection.

    Usage:
        scanner = Scanner(chain="ethereum")
        result = scanner.scan_address("0x...")
        result = scanner.scan_transactions(tx_list)
        result = scanner.scan_file("transactions.json")
    """

    # Chain adapter registry
    CHAIN_ADAPTERS: dict[str, type[ChainAdapter]] = {
        "ethereum": EthereumAdapter,
        "eth": EthereumAdapter,
        "bitcoin": BitcoinAdapter,
        "btc": BitcoinAdapter,
    }

    def __init__(
        self,
        chain: str = "ethereum",
        config: ScannerConfig | None = None,
        data_source: DataSource | None = None,
    ):
        """
        Initialize the scanner.

        Args:
            chain: Blockchain to scan ("ethereum", "eth", "bitcoin", "btc")
            config: Optional scanner configuration
            data_source: Optional custom data source
        """
        self.config = config or DEFAULT_CONFIG
        self.chain_name = chain.lower()

        # Initialize chain adapter
        if self.chain_name not in self.CHAIN_ADAPTERS:
            raise ValueError(
                f"Unsupported chain: {chain}. "
                f"Supported: {list(self.CHAIN_ADAPTERS.keys())}"
            )
        self.chain_adapter = self.CHAIN_ADAPTERS[self.chain_name]()

        # Initialize data source (default to API source)
        self.data_source = data_source

        # Initialize detectors
        self.detectors: list[Detector] = []
        for detector_name in self.config.enabled_detectors:
            if detector_name in DETECTOR_REGISTRY:
                detector_cls = DETECTOR_REGISTRY[detector_name]
                self.detectors.append(detector_cls(self.config))

    def scan_address(
        self,
        address: str,
        fetch_transactions: bool = True,
        limit: int | None = None,
    ) -> ScanResult:
        """
        Scan an address for AML risk patterns.

        Args:
            address: The blockchain address to scan
            fetch_transactions: Whether to fetch transactions from data source
            limit: Maximum number of transactions to fetch

        Returns:
            ScanResult with risk assessment

        Raises:
            ValueError: If address is None, empty, or invalid format
        """
        # Validate input
        if not address or not isinstance(address, str):
            raise ValueError("Address must be a non-empty string")

        address = address.strip()
        if not address:
            raise ValueError("Address must be a non-empty string")

        # Normalize address
        address = self.chain_adapter.normalize_address(address)

        # Validate address format
        if not self.chain_adapter.is_valid_address(address):
            raise ValueError(f"Invalid address format for {self.chain_name}: {address}")

        transactions: list[Transaction] = []

        # Fetch transactions if requested and data source available
        if fetch_transactions and self.data_source:
            transactions = list(
                self.data_source.get_transactions(address, limit=limit)
            )

        return self._run_scan(
            transactions=transactions,
            target_address=address,
        )

    def scan_transactions(
        self,
        transactions: list[Transaction | dict[str, Any]],
        target_address: str | None = None,
    ) -> ScanResult:
        """
        Scan a list of transactions for AML risk patterns.

        Args:
            transactions: List of Transaction objects or raw transaction dicts
            target_address: Optional address being investigated

        Returns:
            ScanResult with risk assessment

        Raises:
            TypeError: If transactions is not a list or contains invalid types
        """
        if transactions is None:
            transactions = []

        if not isinstance(transactions, list):
            raise TypeError(f"transactions must be a list, got {type(transactions)}")

        # Normalize transactions
        normalized_txs: list[Transaction] = []
        for i, tx in enumerate(transactions):
            if tx is None:
                continue  # Skip None entries
            if isinstance(tx, Transaction):
                normalized_txs.append(tx)
            elif isinstance(tx, dict):
                try:
                    normalized_txs.append(self.chain_adapter.parse_transaction(tx))
                except Exception as e:
                    # Log and skip malformed transactions instead of failing entirely
                    import logging
                    logging.warning(f"Failed to parse transaction at index {i}: {e}")
                    continue
            else:
                raise TypeError(f"Invalid transaction type at index {i}: {type(tx)}")

        return self._run_scan(
            transactions=normalized_txs,
            target_address=target_address,
        )

    def scan_file(
        self,
        file_path: str | Path,
        format: str | None = None,
        target_address: str | None = None,
    ) -> ScanResult:
        """
        Scan transactions from a file.

        Args:
            file_path: Path to JSON or CSV file
            format: File format ("json" or "csv"), auto-detected if not specified
            target_address: Optional address being investigated

        Returns:
            ScanResult with risk assessment
        """
        file_source = FileSource(
            file_path=file_path,
            format=format,
            chain_adapter=self.chain_adapter,
        )

        transactions = list(file_source.get_all_transactions())

        return self._run_scan(
            transactions=transactions,
            target_address=target_address,
        )

    def check_address(self, address: str, detector_name: str) -> DetectionResult:
        """
        Run a specific detector on an address.

        Args:
            address: The address to check
            detector_name: Name of the detector to run

        Returns:
            DetectionResult from the specified detector
        """
        if detector_name not in DETECTOR_REGISTRY:
            raise ValueError(f"Unknown detector: {detector_name}")

        detector = DETECTOR_REGISTRY[detector_name](self.config)
        return detector.analyze_address(address)

    def _run_scan(
        self,
        transactions: list[Transaction],
        target_address: str | None = None,
    ) -> ScanResult:
        """Run all enabled detectors and aggregate results."""
        all_flags: list[Flag] = []
        detector_results: list[DetectionResult] = []

        # Run each detector
        for detector in self.detectors:
            result = detector.analyze_transactions(
                transactions=transactions,
                target_address=target_address,
            )
            detector_results.append(result)
            all_flags.extend(result.flags)

        # Calculate risk score
        risk_score = self._calculate_risk_score(all_flags)
        risk_level = self._classify_risk_level(risk_score)

        # Generate summary
        summary = self._generate_summary(all_flags, risk_level)

        return ScanResult(
            address=target_address,
            chain=self.chain_adapter.chain_id,
            risk_score=risk_score,
            risk_level=risk_level,
            flags=all_flags,
            detector_results=detector_results,
            transaction_count=len(transactions),
            summary=summary,
        )

    def _calculate_risk_score(self, flags: list[Flag]) -> int:
        """Calculate overall risk score from flags."""
        if not flags:
            return 0

        # Sum up score contributions, cap at 100
        total_score = sum(flag.score_contribution for flag in flags)
        return min(100, int(total_score))

    def _classify_risk_level(self, score: int) -> RiskLevel:
        """Classify risk level based on score."""
        thresholds = self.config.risk_thresholds

        if score <= thresholds.low_max:
            return RiskLevel.LOW
        elif score <= thresholds.medium_max:
            return RiskLevel.MEDIUM
        elif score <= thresholds.high_max:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL

    def _generate_summary(self, flags: list[Flag], risk_level: RiskLevel) -> str:
        """Generate human-readable summary."""
        if not flags:
            return "No suspicious patterns detected."

        flag_types = set(flag.type for flag in flags)
        high_severity = [f for f in flags if f.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL)]

        parts = []

        if risk_level == RiskLevel.CRITICAL:
            parts.append("CRITICAL RISK:")
        elif risk_level == RiskLevel.HIGH:
            parts.append("High risk patterns detected:")
        elif risk_level == RiskLevel.MEDIUM:
            parts.append("Moderate risk indicators found:")
        else:
            parts.append("Minor risk indicators:")

        # Describe detected patterns
        pattern_descriptions = {
            "SANCTIONS": "sanctioned address interaction",
            "MIXER": "mixer/tumbler usage",
            "PRIVACY_COINS": "privacy coin interaction",
            "BRIDGES": "cross-chain bridge usage",
            "STRUCTURING": "potential structuring patterns",
            "LAYERING": "rapid fund layering",
        }

        detected_patterns = [
            pattern_descriptions.get(ft, ft.lower())
            for ft in flag_types
            if ft in pattern_descriptions
        ]

        if detected_patterns:
            parts.append(", ".join(detected_patterns))

        return " ".join(parts)

    def set_data_source(self, data_source: DataSource) -> None:
        """Set the data source for fetching transactions."""
        self.data_source = data_source

    def use_api_source(
        self,
        api_key: str | None = None,
        cache_enabled: bool = True,
    ) -> None:
        """Configure to use API data source (e.g., Etherscan)."""
        self.data_source = APISource(
            chain=self.chain_name,
            api_key=api_key or self.config.etherscan_api_key,
            chain_adapter=self.chain_adapter,
            cache_enabled=cache_enabled,
            cache_dir=self.config.cache.cache_dir,
        )
