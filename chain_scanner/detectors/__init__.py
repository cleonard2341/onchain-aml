"""AML pattern detection modules."""

from .base import Detector, DetectionResult, RiskLevel, Flag
from .mixer import MixerDetector
from .structuring import StructuringDetector
from .layering import LayeringDetector
from .sanctions import SanctionsDetector
from .privacy_coins import PrivacyCoinsDetector
from .bridges import BridgesDetector

__all__ = [
    "Detector",
    "DetectionResult",
    "RiskLevel",
    "Flag",
    "MixerDetector",
    "StructuringDetector",
    "LayeringDetector",
    "SanctionsDetector",
    "PrivacyCoinsDetector",
    "BridgesDetector",
]


# Registry of available detectors
DETECTOR_REGISTRY: dict[str, type[Detector]] = {
    "mixer": MixerDetector,
    "structuring": StructuringDetector,
    "layering": LayeringDetector,
    "sanctions": SanctionsDetector,
    "privacy_coins": PrivacyCoinsDetector,
    "bridges": BridgesDetector,
}


def get_detector(name: str) -> type[Detector]:
    """Get a detector class by name."""
    if name not in DETECTOR_REGISTRY:
        raise ValueError(f"Unknown detector: {name}. Available: {list(DETECTOR_REGISTRY.keys())}")
    return DETECTOR_REGISTRY[name]


def create_all_detectors(config=None) -> list[Detector]:
    """Create instances of all available detectors."""
    return [detector_cls(config) for detector_cls in DETECTOR_REGISTRY.values()]
