"""Terminal report formatter using Rich."""

from io import StringIO
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from ..scanner import ScanResult
from ..detectors.base import RiskLevel


class TerminalReport:
    """Rich terminal report generator for scan results."""

    # Color scheme for risk levels
    RISK_COLORS = {
        RiskLevel.LOW: "green",
        RiskLevel.MEDIUM: "yellow",
        RiskLevel.HIGH: "orange1",
        RiskLevel.CRITICAL: "red bold",
    }

    RISK_EMOJI = {
        RiskLevel.LOW: "[green]OK[/green]",
        RiskLevel.MEDIUM: "[yellow]!![/yellow]",
        RiskLevel.HIGH: "[orange1]!!![/orange1]",
        RiskLevel.CRITICAL: "[red]XXX[/red]",
    }

    def __init__(
        self,
        show_details: bool = True,
        max_flags: int | None = None,
        console: Console | None = None,
    ):
        """
        Initialize terminal reporter.

        Args:
            show_details: Whether to show detailed flag information
            max_flags: Maximum number of flags to display (None for all)
            console: Optional Rich console instance
        """
        self.show_details = show_details
        self.max_flags = max_flags
        self.console = console or Console()

    def generate(self, result: ScanResult) -> str:
        """Generate terminal report as string."""
        # Capture output to string
        string_io = StringIO()
        temp_console = Console(file=string_io, force_terminal=True)

        self._render_to_console(result, temp_console)

        return string_io.getvalue()

    def print(self, result: ScanResult) -> None:
        """Print report directly to terminal."""
        self._render_to_console(result, self.console)

    def _render_to_console(self, result: ScanResult, console: Console) -> None:
        """Render the report to a console."""
        # Risk score panel
        console.print()
        self._render_risk_panel(result, console)

        # Summary
        console.print()
        self._render_summary(result, console)

        # Flags table
        if result.flags:
            console.print()
            self._render_flags_table(result, console)

        # Detector breakdown
        if self.show_details and result.detector_results:
            console.print()
            self._render_detector_breakdown(result, console)

        console.print()

    def _render_risk_panel(self, result: ScanResult, console: Console) -> None:
        """Render the risk score panel."""
        risk_color = self.RISK_COLORS.get(result.risk_level, "white")

        # Create risk meter
        score = result.risk_score
        filled = int(score / 5)  # 20 segments for 0-100
        empty = 20 - filled

        if result.risk_level == RiskLevel.CRITICAL:
            bar_char = "[red]#[/red]"
        elif result.risk_level == RiskLevel.HIGH:
            bar_char = "[orange1]#[/orange1]"
        elif result.risk_level == RiskLevel.MEDIUM:
            bar_char = "[yellow]#[/yellow]"
        else:
            bar_char = "[green]#[/green]"

        meter = bar_char * filled + "[dim]-[/dim]" * empty

        # Build panel content
        content = Text()
        content.append(f"Risk Score: ", style="bold")
        content.append(f"{score}/100", style=f"bold {risk_color}")
        content.append(f"  [{meter}]")
        content.append(f"\n\nRisk Level: ", style="bold")
        content.append(f"{result.risk_level.value}", style=f"bold {risk_color}")

        if result.address:
            content.append(f"\n\nAddress: ", style="bold")
            content.append(result.address, style="cyan")

        content.append(f"\nChain: ", style="bold")
        content.append(result.chain)

        content.append(f"\nTransactions Analyzed: ", style="bold")
        content.append(str(result.transaction_count))

        panel = Panel(
            content,
            title="[bold]Scan Result[/bold]",
            border_style=risk_color,
            box=box.ROUNDED,
        )
        console.print(panel)

    def _render_summary(self, result: ScanResult, console: Console) -> None:
        """Render the summary section."""
        risk_color = self.RISK_COLORS.get(result.risk_level, "white")

        if result.flags:
            console.print(f"[{risk_color}]{result.summary}[/{risk_color}]")
        else:
            console.print("[green]No suspicious patterns detected.[/green]")

    def _render_flags_table(self, result: ScanResult, console: Console) -> None:
        """Render the flags table."""
        table = Table(
            title="Detected Flags",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold",
        )

        table.add_column("", width=3)  # Severity indicator
        table.add_column("Type", style="cyan")
        table.add_column("Severity")
        table.add_column("Details", max_width=50)
        table.add_column("Score", justify="right")

        flags = result.flags
        if self.max_flags and len(flags) > self.max_flags:
            flags = flags[:self.max_flags]
            show_more = True
        else:
            show_more = False

        for flag in flags:
            severity_color = self.RISK_COLORS.get(flag.severity, "white")
            indicator = self.RISK_EMOJI.get(flag.severity, " ")

            table.add_row(
                indicator,
                flag.type,
                f"[{severity_color}]{flag.severity.value}[/{severity_color}]",
                flag.details,
                f"+{flag.score_contribution:.0f}",
            )

        console.print(table)

        if show_more:
            remaining = len(result.flags) - self.max_flags
            console.print(f"[dim]... and {remaining} more flags[/dim]")

    def _render_detector_breakdown(self, result: ScanResult, console: Console) -> None:
        """Render detector breakdown table."""
        table = Table(
            title="Detector Breakdown",
            box=box.SIMPLE,
            show_header=True,
            header_style="bold dim",
        )

        table.add_column("Detector", style="dim")
        table.add_column("Flags", justify="right")
        table.add_column("Score", justify="right")

        for dr in result.detector_results:
            if dr.flags:  # Only show detectors that found something
                table.add_row(
                    dr.detector_name,
                    str(len(dr.flags)),
                    f"+{dr.score_contribution:.0f}",
                )

        if table.row_count > 0:
            console.print(table)

    def print_flags_only(self, result: ScanResult) -> None:
        """Print only the flags table."""
        if result.flags:
            self._render_flags_table(result, self.console)
        else:
            self.console.print("[green]No flags detected.[/green]")
