"""JSON report formatter."""

import json
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from ..scanner import ScanResult


class DecimalEncoder(json.JSONEncoder):
    """JSON encoder that handles Decimal and datetime types."""

    def default(self, obj):
        if isinstance(obj, Decimal):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


class JSONReport:
    """JSON report generator for scan results."""

    def __init__(self, pretty: bool = True, include_metadata: bool = True):
        """
        Initialize JSON reporter.

        Args:
            pretty: Whether to format JSON with indentation
            include_metadata: Whether to include detailed metadata
        """
        self.pretty = pretty
        self.include_metadata = include_metadata

    def generate(self, result: ScanResult) -> str:
        """Generate JSON report from scan result."""
        report = self._build_report(result)
        indent = 2 if self.pretty else None
        return json.dumps(report, indent=indent, cls=DecimalEncoder)

    def save(self, result: ScanResult, path: str | Path) -> None:
        """Save JSON report to file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        content = self.generate(result)
        with open(path, "w") as f:
            f.write(content)

    def _build_report(self, result: ScanResult) -> dict[str, Any]:
        """Build the report dictionary."""
        report = {
            "scan_result": {
                "address": result.address,
                "chain": result.chain,
                "risk_score": result.risk_score,
                "risk_level": result.risk_level.value,
                "summary": result.summary,
                "transaction_count": result.transaction_count,
            },
            "flags": [self._format_flag(f) for f in result.flags],
            "generated_at": datetime.utcnow().isoformat() + "Z",
        }

        if self.include_metadata:
            report["detector_results"] = [
                self._format_detector_result(dr)
                for dr in result.detector_results
            ]
            report["metadata"] = result.metadata

        return report

    def _format_flag(self, flag) -> dict[str, Any]:
        """Format a single flag for JSON output."""
        return {
            "type": flag.type,
            "severity": flag.severity.value,
            "details": flag.details,
            "tx_hash": flag.tx_hash,
            "address": flag.address,
            "score_contribution": flag.score_contribution,
            "metadata": flag.metadata if self.include_metadata else {},
        }

    def _format_detector_result(self, result) -> dict[str, Any]:
        """Format a detector result for JSON output."""
        return {
            "detector": result.detector_name,
            "flag_count": len(result.flags),
            "score_contribution": result.score_contribution,
            "metadata": result.metadata,
        }
