"""CSV report formatter."""

import csv
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import Any

from ..scanner import ScanResult


class CSVReport:
    """CSV report generator for scan results."""

    def __init__(self, include_metadata: bool = False):
        """
        Initialize CSV reporter.

        Args:
            include_metadata: Whether to include metadata columns
        """
        self.include_metadata = include_metadata

    def generate(self, result: ScanResult) -> str:
        """Generate CSV report from scan result."""
        output = StringIO()
        writer = csv.writer(output)

        # Write header
        headers = self._get_headers()
        writer.writerow(headers)

        # Write summary row
        summary_row = self._format_summary_row(result)
        writer.writerow(summary_row)

        # Write empty row as separator
        writer.writerow([])

        # Write flags header and data
        writer.writerow(["--- FLAGS ---"])
        flag_headers = self._get_flag_headers()
        writer.writerow(flag_headers)

        for flag in result.flags:
            flag_row = self._format_flag_row(flag)
            writer.writerow(flag_row)

        return output.getvalue()

    def generate_flags_only(self, result: ScanResult) -> str:
        """Generate CSV with only the flags table."""
        output = StringIO()
        writer = csv.writer(output)

        # Write headers
        headers = self._get_flag_headers()
        writer.writerow(headers)

        # Write flag rows
        for flag in result.flags:
            row = self._format_flag_row(flag)
            writer.writerow(row)

        return output.getvalue()

    def save(self, result: ScanResult, path: str | Path) -> None:
        """Save CSV report to file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        content = self.generate(result)
        with open(path, "w", newline="") as f:
            f.write(content)

    def save_flags_only(self, result: ScanResult, path: str | Path) -> None:
        """Save CSV with only flags to file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        content = self.generate_flags_only(result)
        with open(path, "w", newline="") as f:
            f.write(content)

    def _get_headers(self) -> list[str]:
        """Get CSV headers for summary."""
        headers = [
            "address",
            "chain",
            "risk_score",
            "risk_level",
            "flag_count",
            "transaction_count",
            "summary",
            "generated_at",
        ]
        return headers

    def _get_flag_headers(self) -> list[str]:
        """Get CSV headers for flags."""
        headers = [
            "flag_type",
            "severity",
            "details",
            "tx_hash",
            "address",
            "score_contribution",
        ]

        if self.include_metadata:
            headers.append("metadata")

        return headers

    def _format_summary_row(self, result: ScanResult) -> list[Any]:
        """Format summary row."""
        return [
            result.address or "",
            result.chain,
            result.risk_score,
            result.risk_level.value,
            len(result.flags),
            result.transaction_count,
            result.summary,
            datetime.utcnow().isoformat() + "Z",
        ]

    def _format_flag_row(self, flag) -> list[Any]:
        """Format a flag row."""
        row = [
            flag.type,
            flag.severity.value,
            flag.details,
            flag.tx_hash or "",
            flag.address or "",
            flag.score_contribution,
        ]

        if self.include_metadata:
            import json
            row.append(json.dumps(flag.metadata))

        return row
