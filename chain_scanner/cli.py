"""CLI entry point for chain-scanner."""

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from .scanner import Scanner, ScanResult
from .config import ScannerConfig
from .detectors.sanctions import SanctionsDetector
from .reports import JSONReport, CSVReport, TerminalReport


console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="chain-scanner")
@click.option(
    "--config", "-c",
    type=click.Path(exists=True),
    help="Path to configuration file",
)
@click.pass_context
def main(ctx, config: Optional[str]):
    """
    Chain Scanner - On-Chain AML Pattern Detector

    Analyze cryptocurrency addresses and transactions for suspicious patterns
    including mixer usage, structuring, sanctions violations, and more.

    All analysis runs locally - no data is sent to external servers.
    """
    ctx.ensure_object(dict)

    # Load configuration
    if config:
        ctx.obj["config"] = ScannerConfig.from_file(config)
    else:
        ctx.obj["config"] = ScannerConfig()


@main.command()
@click.argument("address")
@click.option(
    "--chain", "-n",
    type=click.Choice(["ethereum", "eth", "bitcoin", "btc"]),
    default="ethereum",
    help="Blockchain network",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file path",
)
@click.option(
    "--format", "-f",
    type=click.Choice(["json", "csv", "terminal"]),
    default="terminal",
    help="Output format",
)
@click.option(
    "--api-key", "-k",
    envvar="ETHERSCAN_API_KEY",
    help="API key for data fetching (or set ETHERSCAN_API_KEY env var)",
)
@click.option(
    "--no-fetch",
    is_flag=True,
    help="Don't fetch transactions (check address only)",
)
@click.option(
    "--limit", "-l",
    type=int,
    default=100,
    help="Maximum transactions to fetch",
)
@click.pass_context
def scan(
    ctx,
    address: str,
    chain: str,
    output: Optional[str],
    format: str,
    api_key: Optional[str],
    no_fetch: bool,
    limit: int,
):
    """
    Scan a blockchain address for AML risk patterns.

    Examples:

        chain-scanner scan 0x742d35Cc6634C0532925a3b844Bc9e7595f...

        chain-scanner scan 0x... --chain eth --output report.json --format json
    """
    config = ctx.obj["config"]

    try:
        scanner = Scanner(chain=chain, config=config)

        if api_key and not no_fetch:
            scanner.use_api_source(api_key=api_key)

        with console.status(f"Scanning address {address[:20]}..."):
            result = scanner.scan_address(
                address,
                fetch_transactions=not no_fetch and api_key is not None,
                limit=limit,
            )

        _output_result(result, format, output)

    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@main.command("scan-file")
@click.argument("file_path", type=click.Path(exists=True))
@click.option(
    "--chain", "-n",
    type=click.Choice(["ethereum", "eth", "bitcoin", "btc"]),
    default="ethereum",
    help="Blockchain network",
)
@click.option(
    "--format", "-f",
    type=click.Choice(["json", "csv"]),
    help="Input file format (auto-detected if not specified)",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file path",
)
@click.option(
    "--output-format",
    type=click.Choice(["json", "csv", "terminal"]),
    default="terminal",
    help="Output format",
)
@click.option(
    "--address", "-a",
    help="Target address to analyze within the file",
)
@click.pass_context
def scan_file(
    ctx,
    file_path: str,
    chain: str,
    format: Optional[str],
    output: Optional[str],
    output_format: str,
    address: Optional[str],
):
    """
    Scan transactions from a JSON or CSV file.

    Examples:

        chain-scanner scan-file transactions.json

        chain-scanner scan-file data.csv --format csv --output report.json
    """
    config = ctx.obj["config"]

    try:
        scanner = Scanner(chain=chain, config=config)

        with console.status(f"Scanning file {Path(file_path).name}..."):
            result = scanner.scan_file(
                file_path,
                format=format,
                target_address=address,
            )

        _output_result(result, output_format, output)

    except FileNotFoundError:
        console.print(f"[red]Error:[/red] File not found: {file_path}")
        sys.exit(1)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@main.command("check-sanctions")
@click.argument("address")
@click.pass_context
def check_sanctions(ctx, address: str):
    """
    Check if an address is on the OFAC sanctions list.

    Examples:

        chain-scanner check-sanctions 0x8589427373D6D84E98730D7795D8f6f8731FDA16
    """
    config = ctx.obj["config"]
    detector = SanctionsDetector(config)

    if detector.is_sanctioned(address):
        info = detector.get_sanctions_info(address)
        console.print("[red bold]SANCTIONED ADDRESS[/red bold]")
        console.print()

        if info:
            console.print(f"[bold]Name:[/bold] {info.get('name', 'Unknown')}")
            console.print(f"[bold]Program:[/bold] {info.get('program', 'Unknown')}")
            console.print(f"[bold]Date Added:[/bold] {info.get('date_added', 'Unknown')}")

        sys.exit(1)
    else:
        console.print("[green]Address not found on sanctions list[/green]")
        sys.exit(0)


@main.command("update-lists")
@click.option(
    "--source",
    type=click.Choice(["ofac", "all"]),
    default="all",
    help="Which lists to update",
)
def update_lists(source: str):
    """
    Update local address lists (sanctions, mixers, etc.).

    Note: This is a placeholder - in production, this would fetch
    updated lists from authoritative sources.
    """
    console.print("[yellow]List updates not yet implemented.[/yellow]")
    console.print()
    console.print("Current lists are bundled with the package.")
    console.print("To update, install the latest version of chain-scanner.")


@main.command("list-detectors")
def list_detectors():
    """List all available detection modules."""
    from .detectors import DETECTOR_REGISTRY

    console.print("[bold]Available Detectors:[/bold]")
    console.print()

    for name, detector_cls in DETECTOR_REGISTRY.items():
        detector = detector_cls()
        console.print(f"  [cyan]{name}[/cyan]")
        console.print(f"    {detector.description}")
        console.print()


def _output_result(result: ScanResult, format: str, output_path: Optional[str]) -> None:
    """Output scan result in the specified format."""
    if format == "json":
        reporter = JSONReport()
        content = reporter.generate(result)

        if output_path:
            Path(output_path).write_text(content)
            console.print(f"[green]Report saved to {output_path}[/green]")
        else:
            console.print(content)

    elif format == "csv":
        reporter = CSVReport()
        content = reporter.generate(result)

        if output_path:
            Path(output_path).write_text(content)
            console.print(f"[green]Report saved to {output_path}[/green]")
        else:
            console.print(content)

    else:  # terminal
        reporter = TerminalReport()
        reporter.print(result)

        if output_path:
            # Also save JSON version
            json_reporter = JSONReport()
            Path(output_path).write_text(json_reporter.generate(result))
            console.print(f"[dim]Report also saved to {output_path}[/dim]")


if __name__ == "__main__":
    main()
