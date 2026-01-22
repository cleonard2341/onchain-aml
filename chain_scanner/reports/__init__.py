"""Report generation and output formatting."""

from .json_report import JSONReport
from .csv_report import CSVReport
from .terminal_report import TerminalReport

__all__ = [
    "JSONReport",
    "CSVReport",
    "TerminalReport",
]


def get_reporter(format: str):
    """Get a reporter by format name."""
    reporters = {
        "json": JSONReport,
        "csv": CSVReport,
        "terminal": TerminalReport,
        "console": TerminalReport,
    }

    format_lower = format.lower()
    if format_lower not in reporters:
        raise ValueError(f"Unknown format: {format}. Available: {list(reporters.keys())}")

    return reporters[format_lower]
