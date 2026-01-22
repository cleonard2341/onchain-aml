"""Configuration and thresholds for chain-scanner."""

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


# Package paths
PACKAGE_DIR = Path(__file__).parent
DATA_DIR = PACKAGE_DIR / "data"


class StructuringConfig(BaseModel):
    """Configuration for structuring/smurfing detection."""

    threshold_usd: float = Field(
        default=10000.0, description="Reporting threshold in USD"
    )
    margin_percent: float = Field(
        default=5.0, description="Percentage below threshold to flag (e.g., 5% = $9,500-$9,999)"
    )
    min_transactions: int = Field(
        default=3, description="Minimum number of transactions to consider structuring"
    )
    time_window_hours: int = Field(
        default=24, description="Time window to analyze for structuring patterns"
    )


class LayeringConfig(BaseModel):
    """Configuration for layering/peel chain detection."""

    min_hops: int = Field(
        default=3, description="Minimum number of address hops to flag"
    )
    time_window_hours: int = Field(
        default=48, description="Time window for rapid fund movement"
    )
    min_transfer_percent: float = Field(
        default=80.0, description="Minimum percentage of funds transferred to next hop"
    )


class RiskScoreWeights(BaseModel):
    """Weights for calculating overall risk score."""

    sanctions: float = Field(default=100.0, description="Weight for sanctions match")
    mixer: float = Field(default=80.0, description="Weight for mixer interaction")
    privacy_coin: float = Field(default=60.0, description="Weight for privacy coin usage")
    bridge: float = Field(default=40.0, description="Weight for bridge usage")
    structuring: float = Field(default=50.0, description="Weight for structuring patterns")
    layering: float = Field(default=45.0, description="Weight for layering patterns")


class RiskThresholds(BaseModel):
    """Thresholds for risk level classification."""

    low_max: int = Field(default=25, description="Maximum score for LOW risk")
    medium_max: int = Field(default=50, description="Maximum score for MEDIUM risk")
    high_max: int = Field(default=75, description="Maximum score for HIGH risk")
    # Above high_max is CRITICAL


class CacheConfig(BaseModel):
    """Configuration for API caching."""

    enabled: bool = Field(default=True, description="Enable caching")
    ttl_seconds: int = Field(default=3600, description="Cache TTL in seconds")
    cache_dir: str = Field(
        default=".chain_scanner_cache", description="Cache directory path"
    )


class ScannerConfig(BaseModel):
    """Main configuration for the scanner."""

    # Detection configs
    structuring: StructuringConfig = Field(default_factory=StructuringConfig)
    layering: LayeringConfig = Field(default_factory=LayeringConfig)

    # Risk scoring
    risk_weights: RiskScoreWeights = Field(default_factory=RiskScoreWeights)
    risk_thresholds: RiskThresholds = Field(default_factory=RiskThresholds)

    # Caching
    cache: CacheConfig = Field(default_factory=CacheConfig)

    # API configuration
    etherscan_api_key: str | None = Field(default=None, description="Etherscan API key")
    blockcypher_api_key: str | None = Field(default=None, description="BlockCypher API key")

    # Node endpoints
    ethereum_rpc_url: str | None = Field(default=None, description="Ethereum node RPC URL")
    bitcoin_rpc_url: str | None = Field(default=None, description="Bitcoin node RPC URL")

    # Enabled detectors
    enabled_detectors: list[str] = Field(
        default_factory=lambda: [
            "sanctions",
            "mixer",
            "structuring",
            "layering",
            "privacy_coins",
            "bridges",
        ],
        description="List of enabled detector names",
    )

    @classmethod
    def from_file(cls, path: str | Path) -> "ScannerConfig":
        """Load configuration from a JSON file.

        Args:
            path: Path to the configuration file

        Returns:
            ScannerConfig instance (default if file doesn't exist or is invalid)

        Raises:
            ValueError: If the file exists but contains invalid JSON or config
        """
        import json
        import logging

        path = Path(path)
        if not path.exists():
            logging.info(f"Config file not found at {path}, using defaults")
            return cls()

        try:
            with open(path) as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in config file {path}: {e}")
        except IOError as e:
            logging.warning(f"Could not read config file {path}: {e}")
            return cls()

        try:
            return cls.model_validate(data)
        except Exception as e:
            raise ValueError(f"Invalid configuration in {path}: {e}")

    def to_file(self, path: str | Path) -> None:
        """Save configuration to a JSON file."""
        import json

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w") as f:
            json.dump(self.model_dump(), f, indent=2)


# Default configuration instance
DEFAULT_CONFIG = ScannerConfig()


def get_data_file(filename: str) -> Path:
    """Get path to a data file in the package data directory."""
    return DATA_DIR / filename


def load_json_data(filename: str) -> dict[str, Any] | list[Any]:
    """Load JSON data from the package data directory.

    Args:
        filename: Name of the data file to load

    Returns:
        Parsed JSON data, or empty dict if file doesn't exist or is invalid

    Note:
        Logs warnings on errors but doesn't raise exceptions to allow
        graceful degradation when data files are missing.
    """
    import json
    import logging

    path = get_data_file(filename)
    if not path.exists():
        logging.warning(f"Data file not found: {path}")
        return {}

    try:
        with open(path) as f:
            data = json.load(f)
            if data is None:
                return {}
            return data
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON in data file {path}: {e}")
        return {}
    except IOError as e:
        logging.error(f"Could not read data file {path}: {e}")
        return {}
