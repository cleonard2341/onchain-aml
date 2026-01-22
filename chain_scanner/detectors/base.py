"""Abstract base class for pattern detectors."""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from ..chains.base import Transaction
from ..config import ScannerConfig


class RiskLevel(str, Enum):
    """Risk level classification."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Flag(BaseModel):
    """A single detection flag."""

    type: str = Field(description="Flag type (e.g., MIXER, SANCTIONS)")
    severity: RiskLevel = Field(description="Severity level")
    details: str = Field(description="Human-readable description")
    tx_hash: str | None = Field(default=None, description="Related transaction hash")
    address: str | None = Field(default=None, description="Related address")
    score_contribution: float = Field(
        default=0.0, description="Contribution to overall risk score"
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Additional detection metadata"
    )


class DetectionResult(BaseModel):
    """Result from a single detector."""

    detector_name: str = Field(description="Name of the detector")
    flags: list[Flag] = Field(default_factory=list, description="Detected flags")
    score_contribution: float = Field(
        default=0.0, description="Total contribution to risk score"
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Additional metadata"
    )

    @property
    def has_flags(self) -> bool:
        """Check if any flags were detected."""
        return len(self.flags) > 0


class Detector(ABC):
    """Abstract base class for pattern detectors."""

    # Detector identification
    name: str = ""
    description: str = ""

    # Default severity for flags from this detector
    default_severity: RiskLevel = RiskLevel.MEDIUM

    def __init__(self, config: ScannerConfig | None = None):
        """Initialize the detector with optional configuration."""
        self.config = config or ScannerConfig()

    @abstractmethod
    def analyze_transactions(
        self,
        transactions: list[Transaction],
        target_address: str | None = None,
    ) -> DetectionResult:
        """
        Analyze a list of transactions for suspicious patterns.

        Args:
            transactions: List of transactions to analyze
            target_address: Optional target address being investigated

        Returns:
            DetectionResult with any detected flags
        """
        pass

    def analyze_address(
        self,
        address: str,
        transactions: list[Transaction] | None = None,
    ) -> DetectionResult:
        """
        Analyze an address for suspicious patterns.

        Default implementation just calls analyze_transactions.
        Override for detectors that need address-specific logic.

        Args:
            address: The address to analyze
            transactions: Optional pre-fetched transactions

        Returns:
            DetectionResult with any detected flags
        """
        return self.analyze_transactions(transactions or [], target_address=address)

    def create_flag(
        self,
        details: str,
        severity: RiskLevel | None = None,
        tx_hash: str | None = None,
        address: str | None = None,
        score: float | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Flag:
        """Helper method to create a flag."""
        return Flag(
            type=self.name.upper(),
            severity=severity or self.default_severity,
            details=details,
            tx_hash=tx_hash,
            address=address,
            score_contribution=score or self._get_default_score(),
            metadata=metadata or {},
        )

    def _get_default_score(self) -> float:
        """Get the default score contribution for this detector."""
        weights = self.config.risk_weights
        weight_map = {
            "sanctions": weights.sanctions,
            "mixer": weights.mixer,
            "privacy_coins": weights.privacy_coin,
            "bridges": weights.bridge,
            "structuring": weights.structuring,
            "layering": weights.layering,
        }
        return weight_map.get(self.name, 50.0)

    def _empty_result(self) -> DetectionResult:
        """Return an empty result with no flags."""
        return DetectionResult(detector_name=self.name)
