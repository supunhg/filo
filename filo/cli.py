import json
import logging
import sys
import re
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from filo import __version__
from filo.analyzer import Analyzer
from filo.formats import FormatDatabase
from filo.repair import RepairEngine
from filo.carver import CarverEngine
from filo.batch import BatchProcessor, BatchConfig
from filo.export import JSONExporter, SARIFExporter, export_to_file

from filo.profiler import Profiler
from filo.lineage import LineageTracker, OperationType
from filo.ml import MLDetector
from filo.stego import detect_steganography
from filo.pcap import analyze_pcap

console = Console()


def _print_hex_dump(data: bytes, width: int = 16) -> None:
    """Print hex dump of binary data."""
    for i in range(0, min(len(data), 256), width):
        # Offset
        offset = f"{i:08x}"

        # Hex bytes
        hex_part = " ".join(f"{b:02x}" for b in data[i : i + width])
        hex_part = hex_part.ljust(width * 3)

        # ASCII representation
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in data[i : i + width])

        console.print(f"  {offset}  {hex_part}  {ascii_part}")


def setup_logging(verbose: bool = False) -> None:
    """Configure logging based on verbosity."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


@click.group()
@click.version_option(version=__version__, prog_name="filo")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
def main(verbose: bool) -> None:
    """
    Filo - Forensic Intelligence & Ligation Orchestrator

    Battle-tested file forensics platform for security professionals.
    """
    setup_logging(verbose)


@main.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
@click.option("--deep", is_flag=True, help="Deep analysis (slower, more thorough)")
@click.option("--no-ml", is_flag=True, help="Disable ML-based detection")
@click.option("-a", "--all-evidence", is_flag=True, help="Show all detection evidence")
@click.option("-e", "--all-embedded", is_flag=True, help="Show all embedded artifacts")
@click.option("--explain", is_flag=True, help="Show detailed confidence breakdown")
@click.option("--entropy-viz", is_flag=True, help="Show entropy visualization chart")
@click.option(
    "--yara",
    "yara_rules",
    type=click.Path(exists=True),
    multiple=True,
    help="YARA rule file(s) to scan against",
)
def analyze(
    file_path: str,
    output_json: bool,
    deep: bool,
    no_ml: bool,
    all_evidence: bool,
    all_embedded: bool,
    explain: bool,
    entropy_viz: bool,
    yara_rules: tuple[str, ...],
) -> None:
    """
    Analyze a file to detect its format.

    FILE_PATH: Path to file to analyze
    """
    try:
        analyzer = Analyzer(use_ml=not no_ml, yara_rules=list(yara_rules) if yara_rules else None)
        result = analyzer.analyze_file(file_path)

        if output_json:
            # JSON output
            output = {
                "file": str(file_path),
                "format": result.primary_format,
                "confidence": result.confidence,
                "alternatives": [
                    {"format": fmt, "confidence": conf} for fmt, conf in result.alternative_formats
                ],
                "contradictions": [
                    {
                        "severity": c.severity,
                        "claimed_format": c.claimed_format,
                        "issue": c.issue,
                        "details": c.details,
                        "category": c.category,
                    }
                    for c in result.contradictions
                ],
                "embedded_objects": [
                    {
                        "offset": obj.offset,
                        "format": obj.format,
                        "confidence": obj.confidence,
                        "size": obj.size,
                        "description": obj.description,
                        "data_snippet": obj.data_snippet.hex() if obj.data_snippet else "",
                    }
                    for obj in result.embedded_objects
                ],
                "file_size": result.file_size,
                "entropy": result.entropy,
                "crypto_analysis": result.crypto_analysis,
                "checksum": result.checksum_sha256,
                "evidence": result.evidence_chain,
                "yara_matches": [
                    {
                        "rule": m.rule,
                        "namespace": m.namespace,
                        "tags": m.tags,
                        "meta": m.meta,
                        "description": m.description,
                    }
                    for m in result.yara_matches
                ],
                "office_macros": (
                    result.office_macros.model_dump() if result.office_macros else None
                ),
            }
            console.print_json(json.dumps(output, indent=2))
        else:
            # Rich formatted output
            console.print(
                Panel.fit(f"[bold cyan]File Analysis:[/bold cyan] {file_path}", border_style="cyan")
            )

            # Main result
            confidence_color = (
                "green"
                if result.confidence > 0.8
                else "yellow" if result.confidence > 0.5 else "red"
            )
            console.print(
                f"\n[bold]Detected Format:[/bold] [{confidence_color}]{result.primary_format}[/{confidence_color}]"
            )
            console.print(
                f"[bold]Confidence:[/bold] [{confidence_color}]{result.confidence:.1%}[/{confidence_color}]"
            )

            # Show extraction command for archives
            from filo.formats import FormatDatabase

            db = FormatDatabase()
            format_spec = db.get_format(result.primary_format)
            if format_spec and format_spec.extraction:
                console.print(
                    f"\n[bold cyan]📦 Extraction:[/bold cyan] [green]{format_spec.extraction}[/green]"
                )

            # Confidence breakdown (if --explain flag is used)
            if explain:
                console.print("\n[bold cyan]Confidence Breakdown:[/bold cyan]")

                # Group contributions by source type
                from collections import defaultdict

                grouped_contributions = defaultdict(list)

                # Collect contributions from evidence chain for the primary format
                for evidence in result.evidence_chain:
                    fmt = evidence.get("format", "")
                    if fmt == result.primary_format:
                        module = evidence.get("module", "unknown")
                        module_weight = evidence.get("weight", 1.0)

                        # Map module names to display names
                        source_map = {
                            "signature_analysis": "Signature",
                            "structural_analysis": "Structure",
                            "zip_container_analysis": "ZIP Container",
                            "ml_prediction": "ML Similarity",
                        }
                        source_name = source_map.get(module, module)

                        # Get contributions if they exist
                        contributions = evidence.get("contributions", [])
                        if contributions:
                            for contrib in contributions:
                                # Calculate weighted contribution based on module weight
                                if module == "signature_analysis":
                                    weighted_value = contrib["value"] * module_weight * 0.6
                                elif module == "structural_analysis":
                                    weighted_value = contrib["value"] * module_weight * 0.4
                                elif module == "zip_container_analysis":
                                    weighted_value = contrib["value"] * module_weight * 0.8
                                else:
                                    weighted_value = contrib["value"]

                                grouped_contributions[source_name].append(
                                    {
                                        "value": weighted_value,
                                        "description": contrib["description"],
                                        "is_penalty": contrib.get("is_penalty", False),
                                    }
                                )
                        else:
                            # Fallback: use module confidence * weight
                            conf = evidence.get("confidence", 0)
                            if module == "signature_analysis":
                                weighted_value = conf * module_weight * 0.6
                            elif module == "structural_analysis":
                                weighted_value = conf * module_weight * 0.4
                            elif module == "zip_container_analysis":
                                weighted_value = conf * module_weight * 0.8
                            elif module == "ml_prediction":
                                weighted_value = conf * 0.2
                            else:
                                weighted_value = conf

                            grouped_contributions[source_name].append(
                                {
                                    "value": weighted_value,
                                    "description": f"{source_name} match",
                                    "is_penalty": False,
                                }
                            )

                # Display contributions
                console.print(
                    f"\nPrimary: [bold]{result.primary_format.upper()}[/bold] ([cyan]{result.confidence:.1%}[/cyan])"
                )

                total_contrib = 0.0
                for source_name in ["Signature", "Structure", "ZIP Container", "ML Similarity"]:
                    if source_name in grouped_contributions:
                        for contrib in grouped_contributions[source_name]:
                            value = contrib["value"]
                            desc = contrib["description"]
                            is_penalty = contrib["is_penalty"]

                            total_contrib += value

                            if is_penalty:
                                console.print(f"  [red]-{abs(value):>5.1%}[/red]  {desc}")
                            else:
                                console.print(f"  [green]+{value:>5.1%}[/green]  {desc}")

            # Alternatives
            if result.alternative_formats:
                console.print("\n[bold]Alternative Possibilities:[/bold]")
                for fmt, conf in result.alternative_formats[:3]:
                    console.print(f"  • {fmt}: {conf:.1%}")

            # Contradictions (always show if present - security critical)
            if result.contradictions:
                console.print("\n[bold yellow]⚠ Structural Contradictions Detected:[/bold yellow]")
                for contradiction in result.contradictions:
                    severity_colors = {"warning": "yellow", "error": "orange3", "critical": "red"}
                    severity_icons = {"warning": "⚠", "error": "⚠", "critical": "🚨"}

                    color = severity_colors.get(contradiction.severity, "yellow")
                    icon = severity_icons.get(contradiction.severity, "⚠")

                    console.print(
                        f"\n  [{color}]{icon} {contradiction.severity.upper()}: {contradiction.issue}[/{color}]"
                    )
                    console.print(f"     [dim]Claims: {contradiction.claimed_format}[/dim]")
                    console.print(f"     [dim]{contradiction.details}[/dim]")
                    console.print(f"     [dim]Category: {contradiction.category}[/dim]")

            # Embedded objects (malware hunter candy)
            if result.embedded_objects:
                console.print("\n[bold magenta]🔍 Embedded Artifacts:[/bold magenta]")

                # Limit display unless --all-embedded flag is used
                objects_to_show = (
                    result.embedded_objects if all_embedded else result.embedded_objects[:3]
                )

                for obj in objects_to_show:
                    conf_color = (
                        "green"
                        if obj.confidence > 0.85
                        else "yellow" if obj.confidence > 0.70 else "red"
                    )

                    # Format size display
                    size_str = f"{obj.size:,} bytes" if obj.size else "unknown size"

                    console.print(
                        f"  • Offset [cyan]0x{obj.offset:X}[/cyan]: [{conf_color}]{obj.format.upper()}[/{conf_color}] (prob. {obj.confidence:.0%})"
                    )
                    console.print(f"    [dim]{size_str} - {obj.description}[/dim]")

                    # Show hex snippet
                    if obj.data_snippet:
                        hex_snippet = " ".join(f"{b:02x}" for b in obj.data_snippet[:8])
                        console.print(f"    [dim]Signature: {hex_snippet}...[/dim]")

                # Show message if embedded objects were truncated
                if not all_embedded and len(result.embedded_objects) > 3:
                    remaining = len(result.embedded_objects) - 3
                    console.print(
                        f"\n  [dim]... and {remaining} more embedded artifact{'s' if remaining != 1 else ''}[/dim]"
                    )
                    console.print("  [dim]Use -e or --all-embedded flag to show all[/dim]")

            # Tool/creator fingerprints
            if result.fingerprints:
                console.print("\n[bold blue]🔧 Tool Fingerprints:[/bold blue]")

                for fp in result.fingerprints:
                    conf_color = (
                        "green"
                        if fp.confidence > 0.85
                        else "yellow" if fp.confidence > 0.70 else "red"
                    )

                    parts = []
                    if fp.tool:
                        parts.append(f"{fp.tool}")
                    if fp.version:
                        parts.append(f"v{fp.version}")
                    if fp.os_hint:
                        parts.append(f"on {fp.os_hint}")
                    if fp.timestamp:
                        parts.append(f"at {fp.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")

                    main_text = " ".join(parts) if parts else fp.category

                    console.print(
                        f"  • [{conf_color}]{main_text}[/{conf_color}] (prob. {fp.confidence:.0%})"
                    )
                    console.print(f"    [dim]{fp.evidence}[/dim]")

            # Polyglot detections
            if result.polyglots:
                console.print("\n[bold red]⚠ Polyglot Detected:[/bold red]")

                for poly in result.polyglots:
                    risk_colors = {"high": "red", "medium": "yellow", "low": "green"}
                    risk_color = risk_colors.get(poly.risk_level, "white")
                    conf_color = (
                        "green"
                        if poly.confidence > 0.85
                        else "yellow" if poly.confidence > 0.70 else "red"
                    )

                    formats_str = " + ".join(f.upper() for f in poly.formats)

                    console.print(
                        f"  • [{conf_color}]{formats_str}[/{conf_color}] - {poly.description} (prob. {poly.confidence:.0%})"
                    )
                    console.print(
                        f"    [dim]Risk: [{risk_color}]{poly.risk_level.upper()}[/{risk_color}] | Pattern: {poly.pattern}[/dim]"
                    )
                    console.print(f"    [dim]{poly.evidence}[/dim]")

            # CPU Architecture (for executable files)
            if result.architecture:
                console.print("\n[bold cyan]🖥️  CPU Architecture:[/bold cyan]")
                arch = result.architecture
                console.print(
                    f"  • [green]{arch.architecture}[/green] ({arch.bits}, {arch.endian})"
                )
                console.print(
                    f"    [dim]Format: {arch.format} | Machine Code: 0x{arch.machine_code:04X}[/dim]"
                )

            # YARA matches
            if result.yara_matches:
                console.print(
                    f"\n[bold red]🐍 YARA Matches ({len(result.yara_matches)}):[/bold red]"
                )
                for match in result.yara_matches[:10]:
                    tags_str = f" [{','.join(match.tags)}]" if match.tags else ""
                    desc_str = f" — {match.description}" if match.description else ""
                    console.print(f"  • [red]{match.rule}[/red]{tags_str}{desc_str}")
                    if match.matched_strings:
                        for s in match.matched_strings[:3]:
                            offset = s.get("offset", 0)
                            data_hex = s.get("data", b"")[:8].hex()
                            console.print(f"    [dim]  @ 0x{offset:X}: {data_hex}[/dim]")
                if len(result.yara_matches) > 10:
                    console.print(f"    [dim]... and {len(result.yara_matches) - 10} more[/dim]")

            # Office macro analysis
            if result.office_macros:
                om = result.office_macros
                if om.has_macros or om.suspicious_keywords:
                    console.print("\n[bold yellow]📜 Office Macro Analysis:[/bold yellow]")
                    if om.app_name:
                        console.print(f"  Application: [cyan]{om.app_name}[/cyan]")
                    if om.is_encrypted:
                        console.print("  [red]🔒 Encrypted document[/red]")
                    if om.is_protected:
                        console.print("  [yellow]🔒 Write-protected[/yellow]")
                    if om.has_macros:
                        console.print(f"  Macros: [bold]{om.macro_count}[/bold] module(s)")
                    if om.auto_exec_macros:
                        console.print(
                            f"  Auto-exec macros: [red]{', '.join(om.auto_exec_macros)}[/red]"
                        )
                    if om.suspicious_keywords:
                        console.print(
                            f"  Suspicious keywords ({om.keyword_count}): [red]{', '.join(om.suspicious_keywords[:10])}[/red]"
                        )
                        if len(om.suspicious_keywords) > 10:
                            console.print(
                                f"    [dim]... and {len(om.suspicious_keywords) - 10} more[/dim]"
                            )

            # File info
            console.print(f"\n[bold]File Size:[/bold] {result.file_size:,} bytes")
            if result.entropy is not None:
                console.print(f"[bold]Entropy:[/bold] {result.entropy:.2f} bits/byte")

                # Show crypto analysis if available
                if result.crypto_analysis:
                    crypto = result.crypto_analysis
                    entropy_desc = crypto.get("entropy_interpretation", "")
                    console.print(f"  [dim]({entropy_desc})[/dim]")

                    if crypto.get("is_likely_encrypted"):
                        confidence = crypto.get("confidence", 0) * 100
                        console.print(
                            f"\n[bold yellow]🔐 Encryption Detected:[/bold yellow] [yellow]{confidence:.0f}% confidence[/yellow]"
                        )

                        indicators = crypto.get("encryption_indicators", [])
                        if indicators:
                            for indicator in indicators:
                                console.print(f"  • {indicator}")

                        cipher_hints = crypto.get("cipher_hints", [])
                        if cipher_hints:
                            console.print("\n[bold]Possible Cipher Types:[/bold]")
                            for hint in cipher_hints:
                                console.print(f"  • {hint}")

                        block_info = crypto.get("block_alignment")
                        if block_info and all_evidence:
                            console.print("\n[dim]Block Analysis:[/dim]")
                            if block_info.get("aes_aligned"):
                                console.print(
                                    f"  [dim]• AES blocks: {block_info.get('aes_block_count')}[/dim]"
                                )
                            if block_info.get("pkcs7_padding_possible"):
                                console.print("  [dim]• PKCS#7 padding possible[/dim]")
                    elif crypto.get("encryption_indicators"):
                        # Show indicators even if not highly confident
                        console.print(
                            f"  [dim]Crypto indicators: {', '.join(crypto.get('encryption_indicators', []))}[/dim]"
                        )

                if entropy_viz:
                    try:
                        from filo.analyzer import StatisticalAnalyzer

                        with open(file_path, "rb") as f:
                            file_data = f.read()
                        entropies = StatisticalAnalyzer.chunk_entropy(
                            file_data[:65536], chunk_size=256
                        )
                        if entropies:
                            bar = StatisticalAnalyzer.format_entropy_bar(entropies)
                            console.print(f"[bold]Entropy Map:[/bold] {bar}")
                            console.print("  [dim]█ low    █ medium    █ high    █ very high[/dim]")
                            console.print("  [dim](first 64KB, 256B chunks)[/dim]")
                    except Exception:
                        pass
            console.print(f"[bold]SHA256:[/bold] {result.checksum_sha256}")

            # Evidence
            if result.evidence_chain:
                console.print("\n[bold]Detection Evidence:[/bold]")

                # Limit evidence display unless --all-evidence flag is used
                evidence_to_show = (
                    result.evidence_chain if all_evidence else result.evidence_chain[:3]
                )

                for evidence in evidence_to_show:
                    module = evidence.get("module", "unknown")
                    conf = evidence.get("confidence", 0)
                    evid_list = evidence.get("evidence", [])

                    console.print(f"\n  [cyan]{module}[/cyan] (confidence: {conf:.1%})")
                    for e in evid_list:
                        console.print(f"    • {e}")

                # Show message if evidence was truncated
                if not all_evidence and len(result.evidence_chain) > 3:
                    remaining = len(result.evidence_chain) - 3
                    console.print(
                        f"\n  [dim]... and {remaining} more evidence item{'s' if remaining != 1 else ''}[/dim]"
                    )
                    console.print(
                        "  [dim]Use --all-evidence flag to show all detection evidence[/dim]"
                    )

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}", style="bold")
        sys.exit(1)


@main.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option("-f", "--format", "format_name", required=True, help="Correct format")
def teach(file_path: str, format_name: str) -> None:
    """
    Teach Filo the correct format for a file (ML learning).

    FILE_PATH: Path to file to learn from
    """
    try:
        analyzer = Analyzer(use_ml=True)

        with open(file_path, "rb") as f:
            data = f.read()

        analyzer.teach(data, format_name)

        console.print(f"[green]✓ Learned from {file_path} as {format_name}[/green]")
        model_path = analyzer.ml_detector.model_path if analyzer.ml_detector else None
        if model_path:
            console.print(f"[dim]Model saved to {model_path}[/dim]")

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}", style="bold")
        sys.exit(1)


@main.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option("-f", "--format", "format_name", required=True, help="Target format")
@click.option("-o", "--output", "output_path", type=click.Path(), help="Output file path")
@click.option("-s", "--strategy", default="auto", help="Repair strategy (auto, or specific)")
@click.option("--no-backup", is_flag=True, help="Don't create backup file")
@click.option("--dry-run", is_flag=True, help="Simulate repair without writing")
def repair(
    file_path: str,
    format_name: str,
    output_path: Optional[str],
    strategy: str,
    no_backup: bool,
    dry_run: bool,
) -> None:
    """
    Repair a corrupted file.

    FILE_PATH: Path to corrupted file
    """
    try:
        engine = RepairEngine()

        # Read file
        with open(file_path, "rb") as f:
            data = f.read()

        # Repair
        repaired_data, report = engine.repair(data, format_name, strategy)

        # Display results
        console.print(
            Panel.fit(f"[bold cyan]File Repair:[/bold cyan] {file_path}", border_style="cyan")
        )

        status_color = "green" if report.success else "red"
        status_text = "SUCCESS" if report.success else "FAILED"
        console.print(f"\n[{status_color}][bold]Status:[/bold] {status_text}[/{status_color}]")
        console.print(f"[bold]Strategy Used:[/bold] {report.strategy_used}")
        console.print(f"[bold]Original Size:[/bold] {report.original_size:,} bytes")
        console.print(f"[bold]Repaired Size:[/bold] {report.repaired_size:,} bytes")

        if report.changes_made:
            console.print("\n[bold]Changes Made:[/bold]")
            for change in report.changes_made:
                console.print(f"  • {change}")

        if report.warnings:
            console.print("\n[bold yellow]Warnings:[/bold yellow]")
            for warning in report.warnings:
                console.print(f"  ⚠ {warning}")

        # Write output
        if report.success and not dry_run:
            file_path_obj = Path(file_path)

            if output_path is None:
                # No output specified - replace original with repaired, backup original
                backup_path = Path(f"{file_path}.bak")

                if not no_backup:
                    # Backup original
                    backup_path.write_bytes(data)
                    console.print(f"\n[dim]✓ Original backed up to: {backup_path}[/dim]")

                # Write repaired to original location
                file_path_obj.write_bytes(repaired_data)
                console.print(f"[green]✓ Repaired file written to: {file_path}[/green]")

                # Suggest viewing the file if it's an image
                if format_name in ["bmp", "png", "jpeg", "gif", "tiff"]:
                    console.print(
                        f"\n[dim]💡 Tip: Open {file_path} in an image viewer to see the result[/dim]"
                    )
            else:
                # Output path specified - write repaired to new location, keep original
                out_path = Path(output_path)
                out_path.write_bytes(repaired_data)
                console.print(f"[green]✓ Repaired file written to: {out_path}[/green]")

                # Suggest viewing the file if it's an image
                if format_name in ["bmp", "png", "jpeg", "gif", "tiff"]:
                    console.print(
                        f"\n[dim]💡 Tip: Open {out_path} in an image viewer to see the result[/dim]"
                    )
        elif dry_run:
            console.print("\n[dim]Dry run - no files written[/dim]")

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}", style="bold")
        sys.exit(1)


@main.group()
def formats() -> None:
    """Manage format database."""
    pass


@formats.command("list")
@click.option("-c", "--category", help="Filter by category")
def formats_list(category: Optional[str]) -> None:
    """List all available formats."""
    db = FormatDatabase()

    if category:
        specs = db.get_formats_by_category(category)
    else:
        specs = [db.get_format(name) for name in db.list_formats()]

    if not specs:
        console.print("[yellow]No formats found[/yellow]")
        return

    # Create table
    table = Table(title="Available Formats")
    table.add_column("Format", style="cyan", no_wrap=True)
    table.add_column("Category", style="magenta")
    table.add_column("Extensions", style="green")
    table.add_column("Signatures", justify="right", style="blue")

    for spec in specs:
        if spec:
            table.add_row(
                spec.format,
                spec.category,
                ", ".join(spec.extensions[:3]),
                str(len(spec.signatures)),
            )

    console.print(table)
    console.print(f"\n[dim]Total: {len(specs)} formats[/dim]")


@formats.command("show")
@click.argument("format_name")
def formats_show(format_name: str) -> None:
    """Show detailed information about a format."""
    db = FormatDatabase()
    spec = db.get_format(format_name)

    if not spec:
        console.print(f"[red]Format not found:[/red] {format_name}")
        sys.exit(1)

    console.print(
        Panel.fit(
            f"[bold cyan]Format Specification:[/bold cyan] {spec.format}", border_style="cyan"
        )
    )

    console.print(f"\n[bold]Version:[/bold] {spec.version}")
    console.print(f"[bold]Category:[/bold] {spec.category}")
    console.print(f"[bold]MIME Types:[/bold] {', '.join(spec.mime)}")
    console.print(f"[bold]Extensions:[/bold] {', '.join(spec.extensions)}")

    if spec.description:
        console.print(f"\n[bold]Description:[/bold]\n{spec.description}")

    # Signatures
    console.print(f"\n[bold]Signatures ({len(spec.signatures)}):[/bold]")
    for sig in spec.signatures:
        console.print(f"  • Offset {sig.offset}: {sig.hex} - {sig.description}")

    # Footers
    if spec.footers:
        console.print(f"\n[bold]Footers ({len(spec.footers)}):[/bold]")
        for footer in spec.footers:
            console.print(f"  • {footer.hex} - {footer.description}")

    # Templates
    if spec.templates:
        console.print(f"\n[bold]Templates ({len(spec.templates)}):[/bold]")
        for name in spec.templates:
            console.print(f"  • {name}")

    # Repair strategies
    if spec.repair_strategies:
        console.print(f"\n[bold]Repair Strategies ({len(spec.repair_strategies)}):[/bold]")
        for strategy in sorted(spec.repair_strategies, key=lambda s: s.priority):
            console.print(f"  {strategy.priority}. {strategy.name}")


@main.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option("-f", "--formats", help="Comma-separated list of formats to carve")
@click.option("-o", "--output-dir", default="carved", help="Output directory")
@click.option("--min-size", type=int, default=512, help="Minimum file size in bytes")
@click.option("--max-size", type=int, help="Maximum file size in bytes")
def carve(
    file_path: str, formats: Optional[str], output_dir: str, min_size: int, max_size: Optional[int]
) -> None:
    """
    Carve embedded files from disk images or binary blobs.

    FILE_PATH: Path to disk image or binary file to carve from
    """
    from pathlib import Path

    source_path = Path(file_path)
    output_path = Path(output_dir)

    console.print(f"[cyan]Carving files from:[/cyan] {source_path}")
    console.print(f"[dim]Output directory: {output_path}[/dim]")
    console.print(f"[dim]Min size: {min_size} bytes, Max size: {max_size or 'unlimited'}[/dim]\n")

    try:
        carver = CarverEngine()
        carved_files = carver.carve_file(source_path, min_size=min_size, max_size=max_size)

        if not carved_files:
            console.print("[yellow]No files carved[/yellow]")
            return

        output_path.mkdir(parents=True, exist_ok=True)

        table = Table(title=f"Carved {len(carved_files)} Files")
        table.add_column("Offset", style="cyan")
        table.add_column("Size", style="green")
        table.add_column("Format", style="yellow")
        table.add_column("Confidence", style="magenta")
        table.add_column("Output File", style="blue")

        for i, carved in enumerate(carved_files):
            out_name = f"{source_path.stem}_carved_{i:04d}_{carved.format}.bin"
            out_file = output_path / out_name

            carved.save(out_file)

            table.add_row(
                f"0x{carved.offset:08x}",
                f"{carved.size:,} bytes",
                carved.format.upper(),
                f"{carved.confidence:.1%}",
                out_name,
            )

        console.print(table)
        console.print(f"\n[green]✓[/green] Saved {len(carved_files)} files to {output_path}")

    except Exception as e:
        console.print(f"[red]Error during carving: {e}[/red]")
        sys.exit(1)


@main.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False))
@click.option("--recursive/--no-recursive", default=True, help="Recursively process subdirectories")
@click.option("--workers", "-w", default=4, type=int, help="Number of parallel workers")
@click.option("--max-size", default=100, type=int, help="Max file size in MB")
@click.option("--export", type=click.Choice(["json", "sarif"]), help="Export results")
@click.option("--output", "-o", type=click.Path(), help="Output file for export")
def batch(
    directory: str,
    recursive: bool,
    workers: int,
    max_size: int,
    export: Optional[str],
    output: Optional[str],
) -> None:
    """
    Batch analyze all files in a directory.

    Examples:
        filo batch ./samples
        filo batch --workers=8 --export=json --output=results.json ./data
    """
    try:
        from pathlib import Path

        config = BatchConfig(
            max_workers=workers,
            max_file_size=max_size * 1024 * 1024,
            recursive=recursive,
            progress_callback=None,
        )

        processor = BatchProcessor(config)

        console.print(f"[bold]Batch Processing:[/bold] {directory}\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Analyzing files...", total=None)

            result = processor.process_directory(Path(directory))
            progress.update(task, completed=result.total_files, total=result.total_files)

        # Show summary
        console.print("\n[bold]Results Summary:[/bold]")
        console.print(f"Total files: {result.total_files}")
        console.print(f"[green]Analyzed: {result.analyzed_files}[/green]")
        console.print(f"[red]Failed: {result.failed_files}[/red]")
        console.print(f"[yellow]Skipped: {result.skipped_files}[/yellow]")
        console.print(f"Duration: {result.duration:.2f}s ({result.files_per_second:.1f} files/sec)")

        # Show format breakdown
        if result.results:
            format_counts = {}
            for path, res in result.results:
                fmt = res.format_name
                format_counts[fmt] = format_counts.get(fmt, 0) + 1

            table = Table(title="Format Distribution", show_header=True)
            table.add_column("Format", style="cyan")
            table.add_column("Count", justify="right", style="green")
            table.add_column("Percentage", justify="right")

            for fmt, count in sorted(format_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
                pct = count / result.analyzed_files * 100
                table.add_row(fmt, str(count), f"{pct:.1f}%")

            console.print(table)

        # Export if requested
        if export and result.results:
            if export == "json":
                exported = JSONExporter.export_batch(result.results, pretty=True)
            elif export == "sarif":
                exported = SARIFExporter.export_batch(result.results, pretty=True)

            if output:
                export_to_file(exported, Path(output), overwrite=True)
                console.print(f"\n[green]✓[/green] Exported to {output}")
            else:
                console.print("\n" + exported)

    except Exception as e:
        console.print(f"[red]Error during batch processing: {e}[/red]")
        sys.exit(1)


@main.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--profile/--no-profile", default=False, help="Enable performance profiling")
@click.option("--show-stats", is_flag=True, help="Show detailed profiling statistics")
def profile(file_path: str, profile: bool, show_stats: bool) -> None:
    """
    Profile performance of file analysis.

    Examples:
        filo profile large_file.bin
        filo profile --show-stats suspicious.dat
    """
    try:
        profiler = Profiler(enabled=True)
        profiler.start()

        # Run analysis
        analyzer = Analyzer(use_ml=False)

        with open(file_path, "rb") as f:
            data = f.read()

        with profiler.time_operation("analyze"):
            analyzer.analyze(data)

        report = profiler.stop()

        # Show results
        console.print(f"\n[bold]Performance Profile:[/bold] {file_path}\n")
        console.print(f"Total Duration: [cyan]{report.total_duration:.4f}s[/cyan]")

        if report.timings:
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Operation")
            table.add_column("Time (s)", justify="right")
            table.add_column("Calls", justify="right")
            table.add_column("Avg (s)", justify="right")

            for timing in report.get_sorted_timings()[:10]:
                table.add_row(
                    timing.name,
                    f"{timing.duration:.4f}",
                    str(timing.calls),
                    f"{timing.avg_duration:.6f}",
                )

            console.print(table)

        if show_stats and report.profile_data:
            console.print("\n[bold]Detailed Statistics:[/bold]")
            console.print(report.profile_data)

    except Exception as e:
        console.print(f"[red]Error during profiling: {e}[/red]")
        sys.exit(1)


@main.command()
@click.argument("file_hash")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format",
)
@click.option("--output", "-o", type=click.Path(), help="Save to file")
def lineage(file_hash: str, output_format: str, output: Optional[str]) -> None:
    """
    Show hash lineage chain-of-custody for a file.

    FILE_HASH: SHA-256 hash to query (first 8+ characters accepted)

    Examples:
        filo lineage abc123def456  # Show lineage for hash
        filo lineage abc123 --format json  # JSON output
        filo lineage abc123 --output report.txt  # Save to file
    """
    try:
        tracker = LineageTracker()

        # Support partial hash matching (minimum 8 chars)
        if len(file_hash) < 8:
            console.print("[red]Error: Hash must be at least 8 characters[/red]")
            sys.exit(1)

        # For partial hashes, query may return multiple results
        if len(file_hash) != 64:
            console.print("[yellow]Warning: Partial hash provided, results may be limited[/yellow]")
            console.print(
                "[yellow]For best results, provide full 64-character SHA-256 hash[/yellow]\n"
            )

        if output_format == "json":
            result = tracker.export_chain_json(file_hash)

            if output:
                Path(output).write_text(result)
                console.print(f"[green]✓ Lineage exported to {output}[/green]")
            else:
                console.print(result)
        else:
            result = tracker.export_chain_report(file_hash)

            if output:
                Path(output).write_text(result)
                console.print(f"[green]✓ Chain-of-custody report saved to {output}[/green]")
            else:
                console.print(result)

    except Exception as e:
        console.print(f"[red]Error querying lineage: {e}[/red]")
        sys.exit(1)


@main.command()
@click.option(
    "--operation",
    type=click.Choice(["repair", "carve", "extract", "export", "teach", "analyze"]),
    help="Filter by operation type",
)
@click.option("--limit", type=int, default=20, help="Maximum records to show")
def lineage_history(operation: Optional[str], limit: int) -> None:
    """
    Show recent lineage tracking history.

    Examples:
        filo lineage-history  # Show all recent operations
        filo lineage-history --operation repair  # Show only repairs
        filo lineage-history --limit 50  # Show 50 most recent
    """
    try:
        tracker = LineageTracker()

        if operation:
            op_type = OperationType(operation)
            records = tracker.get_by_operation(op_type)[:limit]
            title = f"Lineage History - {operation.upper()} operations"
        else:
            # Get stats to show overview
            stats = tracker.get_stats()

            console.print("\n[bold]Lineage Tracking Statistics[/bold]")
            console.print(f"Total Records: {stats['total_records']}")
            console.print(f"Database: {stats['database_path']}\n")

            if stats["total_records"] == 0:
                console.print("[yellow]No lineage records found[/yellow]")
                console.print(
                    "[dim]Lineage tracking records chain-of-custody for file transformations[/dim]"
                )
                console.print(
                    "[dim]Use 'filo repair' or 'filo carve' with lineage tracking enabled[/dim]"
                )
                return

            console.print("[bold]Records by Operation:[/bold]")
            for op, count in stats["by_operation"].items():
                if count > 0:
                    console.print(f"  {op}: {count}")

            console.print(f"\nOldest: {stats['oldest_record']}")
            console.print(f"Newest: {stats['newest_record']}\n")

            # Show recent records from all operations
            all_records = []
            for op in OperationType:
                all_records.extend(tracker.get_by_operation(op))

            # Sort by timestamp and take most recent
            all_records.sort(key=lambda r: r.timestamp, reverse=True)
            records = all_records[:limit]
            title = f"Recent Lineage Records (last {len(records)})"

        if not records:
            console.print(
                f"[yellow]No {operation} operations found[/yellow]"
                if operation
                else "[yellow]No records found[/yellow]"
            )
            return

        console.print(f"\n[bold]{title}[/bold]\n")

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Timestamp", width=20)
        table.add_column("Operation", width=10)
        table.add_column("Original Hash", width=16)
        table.add_column("Result Hash", width=16)
        table.add_column("Details", width=40)

        for record in records:
            # Truncate hashes for display
            orig_hash = record.original_hash[:14] + "..."
            result_hash = record.result_hash[:14] + "..."

            # Format metadata
            details = []
            if "format" in record.metadata:
                details.append(f"fmt={record.metadata['format']}")
            if "strategy" in record.metadata:
                details.append(f"strategy={record.metadata['strategy']}")
            if "offset" in record.metadata:
                details.append(f"offset={record.metadata['offset']}")
            details_str = ", ".join(details) if details else "-"

            table.add_row(
                record.timestamp[:19].replace("T", " "),
                record.operation.value,
                orig_hash,
                result_hash,
                details_str,
            )

        console.print(table)
        console.print("\n[dim]Use 'filo lineage <hash>' to see full chain-of-custody[/dim]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@main.command()
def lineage_stats() -> None:
    """Show lineage tracking statistics."""
    try:
        tracker = LineageTracker()
        stats = tracker.get_stats()

        console.print("\n[bold cyan]═══════════════════════════════════════════[/bold cyan]")
        console.print("[bold cyan]  Lineage Tracking Statistics              [/bold cyan]")
        console.print("[bold cyan]═══════════════════════════════════════════[/bold cyan]\n")

        console.print(f"[bold]Total Records:[/bold] {stats['total_records']}")
        console.print(f"[bold]Database Path:[/bold] {stats['database_path']}\n")

        if stats["total_records"] > 0:
            console.print("[bold]Operations:[/bold]")
            table = Table(show_header=False, box=None)
            for op, count in sorted(
                stats["by_operation"].items(), key=lambda x: x[1], reverse=True
            ):
                if count > 0:
                    table.add_row(f"  • {op.upper()}", f"{count} records")
            console.print(table)

            console.print("\n[bold]Time Range:[/bold]")
            console.print(f"  Oldest: {stats['oldest_record']}")
            console.print(f"  Newest: {stats['newest_record']}\n")
        else:
            console.print("[yellow]No lineage records found[/yellow]\n")
            console.print("[dim]Lineage tracking maintains chain-of-custody for:[/dim]")
            console.print("[dim]  • File repairs (original → repaired)[/dim]")
            console.print("[dim]  • File carving (container → extracted)[/dim]")
            console.print("[dim]  • File exports (source → exported format)[/dim]\n")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@main.command()
@click.option("-y", "--yes", is_flag=True, help="Skip confirmation prompt")
def reset_lineage(yes: bool) -> None:
    """Reset lineage tracking database (deletes all records)."""
    try:
        tracker = LineageTracker()
        db_path = tracker.db_path
        stats = tracker.get_stats()

        if stats["total_records"] == 0:
            console.print("[yellow]Lineage database is already empty[/yellow]")
            return

        if not yes:
            console.print(
                f"[yellow]Warning:[/yellow] This will delete {stats['total_records']} lineage records"
            )
            console.print(f"[dim]Database: {db_path}[/dim]\n")

            if not click.confirm("Are you sure you want to reset the lineage database?"):
                console.print("[dim]Cancelled[/dim]")
                return

        tracker.close()
        db_path.unlink(missing_ok=True)

        console.print("[green]✓ Lineage database reset[/green]")
        console.print(f"[dim]Deleted {stats['total_records']} records from {db_path}[/dim]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@main.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option("-a", "--all", "show_all", is_flag=True, help="Show all methods (slower)")
@click.option(
    "-E",
    "--extract",
    "extract_method",
    help="Extract data from specific method (e.g., 'b1,rgba,lsb,xy')",
)
@click.option(
    "-o", "--output", "output_path", type=click.Path(), help="Save extracted data to file"
)
@click.option("--limit", default=256, type=int, help="Limit bytes checked (0 = no limit)")
def stego(
    file_path: str,
    show_all: bool,
    extract_method: Optional[str],
    output_path: Optional[str],
    limit: int,
) -> None:
    """
    Detect steganography in files (LSB analysis, metadata, etc.).

    Supports:
    - PNG/BMP: LSB analysis (zsteg-compatible)
    - PDF: Metadata analysis

    Examples:
        filo stego image.png
        filo stego document.pdf
        filo stego image.png --extract="b1,rgba,lsb,xy" -o output.txt
    """
    try:
        if extract_method:
            # Extract specific method
            with open(file_path, "rb") as f:
                data = f.read()

            from filo.stego import PNGStegoDetector, BMPStegoDetector, BitOrder

            if data.startswith(b"\x89PNG"):
                detector = PNGStegoDetector()
            elif data.startswith(b"BM"):
                detector = BMPStegoDetector()
            else:
                console.print("[red]File is not a PNG or BMP image[/red]")
                sys.exit(1)

            # Parse method string (e.g., "b1,rgba,lsb,xy")
            parts = extract_method.split(",")
            if len(parts) < 4:
                console.print(
                    "[red]Invalid method format. Use: 'bits,channels,order,pixelorder'[/red]"
                )
                console.print("[dim]Example: b1,rgba,lsb,xy[/dim]")
                sys.exit(1)

            bits_str = parts[0]
            bits = int(bits_str.lstrip("b").rstrip("b"))
            parts[1]
            bit_order = parts[2]
            parts[3]

            # Extract data using Python implementation
            png_info = detector.parse_png(data)
            if png_info and png_info["clean_pixels"]:
                image_data = png_info["clean_pixels"]
            else:
                console.print("[red]Failed to parse image[/red]")
                sys.exit(1)

            extracted = detector.extractor.extract_bits(
                image_data, bits=bits, order=BitOrder.LSB if bit_order == "lsb" else BitOrder.MSB
            )

            if output_path:
                with open(output_path, "wb") as f:
                    f.write(extracted)
                console.print(f"[green]✓ Extracted {len(extracted)} bytes to {output_path}[/green]")
            else:
                # Try to display as text
                try:
                    text = extracted.decode("utf-8", errors="ignore")
                    console.print(text)
                except Exception:
                    # Show hex dump
                    console.print(f"[dim]Binary data ({len(extracted)} bytes):[/dim]")
                    _print_hex_dump(extracted[:256])

            return

        # Normal detection mode
        console.print(
            Panel.fit(
                f"[bold cyan]Steganography Analysis:[/bold cyan] {file_path}", border_style="cyan"
            )
        )

        with open(file_path, "rb") as f:
            data = f.read()

        results = detect_steganography(data)

        if not results:
            console.print("\n[yellow]No steganography detected[/yellow]")
            return

        # Filter results: By default, hide metadata results (tEXt, iTXt, zTXt, tIME)
        # and imagedata results unless --all is specified
        if not show_all:
            # Only show LSB/MSB extraction results (the core stego results)
            filtered_results = [
                r
                for r in results
                if not (
                    r.channel in ("tEXt", "iTXt", "zTXt", "tIME", "pixels")
                    or r.method.startswith("meta")
                    or r.method == "imagedata"
                )
            ]

            # If we have no LSB results, show everything
            if filtered_results:
                results = filtered_results

        console.print(f"\nFound {len(results)} results:\n")

        # Display results in zsteg-like format
        for i, result in enumerate(results):
            if not show_all and i >= 50:  # zsteg shows up to ~50 results by default
                remaining = len(results) - 50
                console.print(f"\n[dim]... and {remaining} more (use --all to show)[/dim]")
                break

            # Format: method .. description (like zsteg)
            # e.g., "b1,rgb,lsb,xy       .. text: \"picoCTF{...}\""
            method_str = f"{result.method:23}"  # Left-aligned, 23 chars wide

            # Color based on data type
            if (
                "FLAG" in result.description
                or result.data_type == "flag"
                or "picoCTF" in result.description
            ):
                color = "bright_green"
            elif result.data_type == "text":
                color = "white"
            elif result.data_type in ("file", "zlib"):
                color = "cyan"
            elif result.data_type in ("metadata", "trailing"):
                color = "yellow"
            else:
                color = "dim"

            console.print(f"[{color}]{method_str}[/{color}] .. {result.description}")

        console.print("\n[dim]Tip: Use --extract=METHOD to extract specific data[/dim]")
        console.print(
            f'[dim]Example: filo stego {file_path} --extract="b1,rgba,lsb,xy" -o output.txt[/dim]'
        )

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        import traceback

        if "--verbose" in sys.argv or "-v" in sys.argv:
            traceback.print_exc()
        sys.exit(1)


@main.command()
@click.argument("file_path", type=click.Path(exists=True))
def pcap(file_path: str) -> None:
    """
    Analyze PCAP network capture files.

    Quick triage for CTF challenges:
    - Packet statistics
    - Protocol breakdown
    - String extraction
    - Base64 data detection
    - Flag pattern search
    - HTTP requests

    Examples:
        filo pcap capture.pcap
        filo pcap network.pcapng
    """
    try:
        console.print(Panel(f"PCAP Analysis: {Path(file_path).name}", style="bold cyan"))

        stats = analyze_pcap(file_path)

        if not stats:
            console.print("[red]Error: Not a valid PCAP file[/red]")
            console.print("[dim]Supported: .pcap files (libpcap format)[/dim]")
            sys.exit(1)

        # Display statistics
        console.print("\n[bold]📊 Statistics[/bold]")
        console.print(f"  Packets: {stats.packet_count:,}")
        console.print(f"  Total bytes: {stats.total_bytes:,}")
        console.print(f"  File size: {stats.file_size:,} bytes")

        # Protocol breakdown
        if stats.protocols:
            console.print("\n[bold]🔌 Protocols[/bold]")
            for protocol, count in stats.protocols.most_common(10):
                console.print(f"  {protocol}: {count:,} packets")

        # Flags found
        if stats.flags:
            console.print(f"\n[bold green]🚩 FLAGS FOUND ({len(stats.flags)})[/bold green]")
            for flag in stats.flags:
                console.print(f"  [red bold]{flag}[/red bold]")

        # Base64 data
        if stats.base64_data:
            console.print(f"\n[bold]📝 Base64 Data ({len(stats.base64_data)} found)[/bold]")
            for raw, decoded in stats.base64_data[:10]:
                console.print(f"  [cyan]{raw}...[/cyan]")
                console.print(f"  → {decoded[:100]}")
                console.print()

        # HTTP requests
        if stats.http_requests:
            console.print(f"\n[bold]🌐 HTTP Requests ({len(stats.http_requests)} found)[/bold]")
            for req in stats.http_requests[:15]:
                console.print(f"  {req}")

        # Interesting strings
        if stats.strings:
            console.print(f"\n[bold]💬 Interesting Strings ({len(stats.strings)} found)[/bold]")
            for s in stats.strings[:15]:
                # Truncate long strings
                display = s[:80] + "..." if len(s) > 80 else s
                console.print(f"  {display}")

        # Recommendations
        console.print("\n[bold]💡 Next Steps[/bold]")
        console.print("  • Open in Wireshark for detailed protocol analysis")
        console.print(f"  • Use 'tshark -r {file_path}' for packet inspection")
        console.print(
            f"  • Export HTTP objects: tshark -r {file_path} --export-objects http,./output"
        )

        if stats.flags:
            console.print(
                f"\n[bold green]✓ Found {len(stats.flags)} flag(s) - check above![/bold green]"
            )

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        import traceback

        if "--verbose" in sys.argv or "-v" in sys.argv:
            traceback.print_exc()
        sys.exit(1)


@main.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), help="Output directory for extracted files")
@click.option(
    "-r",
    "--recursive",
    is_flag=True,
    default=True,
    help="Recursively extract nested archives (default: on)",
)
@click.option("--max-depth", type=int, default=10, help="Maximum nesting depth (default: 10)")
def extract(file_path: str, output: Optional[str], recursive: bool, max_depth: int) -> None:
    """
    Extract nested archives and polyglots recursively.

    Automatically detects and extracts:
    - ZIP archives embedded in images (polyglots)
    - Nested archives (zip in zip, etc.)
    - Trailing data after image markers

    Perfect for CTF challenges like Matryoshka dolls!

    Examples:
        filo extract dolls.jpg
        filo extract polyglot.png -o extracted/
        filo extract nested.zip --max-depth 5
    """
    import zipfile
    from pathlib import Path

    try:
        file_path = Path(file_path)

        # Set output directory
        if output:
            output_dir = Path(output)
        else:
            output_dir = Path.cwd() / f"{file_path.stem}_extracted"

        output_dir.mkdir(parents=True, exist_ok=True)

        console.print(
            Panel(
                f"[bold cyan]Recursive Extraction:[/bold cyan] {file_path.name}",
                border_style="cyan",
            )
        )

        extracted_count = 0
        files_to_process = [(file_path, output_dir, 0)]
        processed_hashes = set()

        while files_to_process:
            current_file, current_output, depth = files_to_process.pop(0)

            if depth > max_depth:
                console.print(f"[yellow]⚠ Max depth ({max_depth}) reached, stopping[/yellow]")
                break

            # Avoid processing the same file twice
            import hashlib

            with open(current_file, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            if file_hash in processed_hashes:
                continue
            processed_hashes.add(file_hash)

            # Analyze the file
            analyzer = Analyzer()
            result = analyzer.analyze_file(current_file)

            indent = "  " * depth
            console.print(
                f"\n{indent}[cyan]→[/cyan] {current_file.name} ({result.primary_format}, {result.confidence:.1%})"
            )

            # Check for polyglots
            extracted_from_polyglot = False
            if result.polyglots:
                for polyglot in result.polyglots:
                    if "zip" in polyglot.formats:
                        console.print(
                            f"{indent}  [yellow]📦 Polyglot detected:[/yellow] {' + '.join(polyglot.formats)}"
                        )

                        # Try to extract as ZIP
                        try:
                            with zipfile.ZipFile(current_file, "r") as zf:
                                for member in zf.namelist():
                                    extracted_path = current_output / member
                                    extracted_path.parent.mkdir(parents=True, exist_ok=True)

                                    with (
                                        zf.open(member) as source,
                                        open(extracted_path, "wb") as target,
                                    ):
                                        target.write(source.read())

                                    console.print(
                                        f"{indent}    [green]✓[/green] Extracted: {member}"
                                    )
                                    extracted_count += 1

                                    # Add to processing queue if recursive
                                    if recursive and extracted_path.suffix.lower() in [
                                        ".jpg",
                                        ".jpeg",
                                        ".png",
                                        ".zip",
                                        ".gz",
                                        ".bz2",
                                        ".tar",
                                    ]:
                                        files_to_process.append(
                                            (extracted_path, extracted_path.parent, depth + 1)
                                        )

                                    extracted_from_polyglot = True
                        except zipfile.BadZipFile:
                            console.print(f"{indent}    [red]✗[/red] Failed to extract ZIP data")
                        except Exception as e:
                            console.print(f"{indent}    [red]✗[/red] Error: {e}")

            # Check for regular archives
            if not extracted_from_polyglot and result.primary_format in [
                "zip",
                "tar",
                "gzip",
                "bzip2",
                "7z",
                "rar",
            ]:
                console.print(
                    f"{indent}  [yellow]📦 Archive detected:[/yellow] {result.primary_format}"
                )

                # Extract based on format
                try:
                    if result.primary_format == "zip":
                        with zipfile.ZipFile(current_file, "r") as zf:
                            for member in zf.namelist():
                                extracted_path = current_output / member
                                extracted_path.parent.mkdir(parents=True, exist_ok=True)

                                with (
                                    zf.open(member) as source,
                                    open(extracted_path, "wb") as target,
                                ):
                                    target.write(source.read())

                                console.print(f"{indent}    [green]✓[/green] Extracted: {member}")
                                extracted_count += 1

                                if recursive:
                                    files_to_process.append(
                                        (extracted_path, extracted_path.parent, depth + 1)
                                    )

                    # Add support for other formats if needed

                except Exception as e:
                    console.print(f"{indent}    [red]✗[/red] Error: {e}")

        console.print("\n[bold green]✓ Extraction complete![/bold green]")
        console.print(f"  Total files extracted: {extracted_count}")
        console.print(f"  Output directory: {output_dir}")

        # Search for flags in extracted text files
        flag_pattern = re.compile(rb"(picoCTF|flag|ctf|HTB)\{[^}]+\}", re.IGNORECASE)
        flags_found = []

        for txt_file in output_dir.rglob("*.txt"):
            try:
                with open(txt_file, "rb") as f:
                    content = f.read()
                    matches = flag_pattern.findall(content)
                    for match in matches:
                        flag_text = match.decode("utf-8", errors="ignore")
                        # Find the full flag including prefix
                        full_match = re.search(rb"[a-zA-Z0-9_]+\{[^}]+\}", content)
                        if full_match:
                            flag_text = full_match.group(0).decode("utf-8", errors="ignore")
                        flags_found.append((txt_file.relative_to(output_dir), flag_text))
            except Exception:
                pass

        if flags_found:
            console.print("\n[bold yellow]🚩 Flags found:[/bold yellow]")
            for filename, flag in flags_found:
                console.print(f"  [green]{filename}:[/green] {flag}")

        if extracted_count == 0:
            console.print("\n[yellow]No archives or polyglots found to extract[/yellow]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if "--debug" in sys.argv:
            import traceback

            traceback.print_exc()
        sys.exit(1)


@main.command(name="meta")
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
@click.option(
    "-s", "--sus", "suspicious_only", is_flag=True, help="Only show suspicious/hidden metadata"
)
def metadata(file_path: str, output_json: bool, suspicious_only: bool) -> None:
    """
    Extract metadata from image files (JPEG, PNG).

    Similar to exiftool - extracts EXIF, IPTC, XMP, ICC profiles, and other metadata.
    Automatically flags suspicious content like base64-encoded data.

    Examples:
        filo meta photo.jpg
        filo meta image.png -s
        filo meta file.jpg --json
    """
    try:
        from filo.metadata import extract_metadata

        with open(file_path, "rb") as f:
            data = f.read()

        result = extract_metadata(data)

        if output_json:
            # JSON output
            output = {
                "file": str(file_path),
                "format": result.format,
                "metadata": [
                    {
                        "group": field.group,
                        "key": field.key,
                        "value": str(field.value),
                        "tag_id": field.tag_id,
                        "description": field.description,
                    }
                    for field in result.fields
                ],
                "warnings": result.warnings,
                "has_suspicious": result.has_suspicious,
                "suspicious_fields": result.suspicious_fields,
            }
            console.print_json(data=output)
            return

        # Rich console output
        console.print(f"\n[bold]File:[/bold] {file_path}")
        console.print(f"[bold]Format:[/bold] {result.format}\n")

        if result.warnings:
            console.print("[yellow]Warnings:[/yellow]")
            for warning in result.warnings:
                console.print(f"  ⚠ {warning}")
            console.print()

        # Group metadata by category
        grouped = {}
        for field in result.fields:
            if field.group not in grouped:
                grouped[field.group] = []
            grouped[field.group].append(field)

        # Filter to suspicious only if requested
        if suspicious_only and result.has_suspicious:
            console.print("[bold yellow]🚨 Suspicious Metadata Found:[/bold yellow]\n")
            for field in result.fields:
                if field.key in result.suspicious_fields:
                    console.print(f"[yellow]{field.group}:{field.key}:[/yellow]")
                    console.print(f"  {field.value}\n")
        else:
            # Show all metadata grouped
            for group, fields in sorted(grouped.items()):
                console.print(f"[bold cyan]{group}[/bold cyan]")

                for field in fields:
                    # Highlight suspicious fields
                    if field.key in result.suspicious_fields:
                        console.print(f"  [yellow]⚠ {field.key}:[/yellow] {field.value}")
                    else:
                        console.print(f"  {field.key}: {field.value}")

                    # Show tag ID if present
                    if field.tag_id is not None:
                        console.print(f"    [dim]Tag ID: 0x{field.tag_id:04X}[/dim]")

                console.print()

        # Summary for suspicious content
        if result.has_suspicious:
            console.print(
                f"[bold yellow]⚠ {len(result.suspicious_fields)} suspicious field(s) detected[/bold yellow]"
            )
            console.print(
                "[dim]These may contain encoded/hidden data (e.g., base64, steghide passwords)[/dim]"
            )
            console.print("[dim]Use -s or --sus to filter suspicious fields only[/dim]\n")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if "--debug" in sys.argv:
            import traceback

            traceback.print_exc()
        sys.exit(1)


@main.command()
@click.option("-y", "--yes", is_flag=True, help="Skip confirmation prompt")
def reset_ml(yes: bool) -> None:
    """Reset ML model (deletes all learned patterns)."""
    try:
        model_path = Path.home() / ".filo" / "learned_patterns.pkl"

        if not model_path.exists():
            console.print("[yellow]ML model does not exist (nothing to reset)[/yellow]")
            return

        detector = MLDetector(model_path)
        pattern_count = len(detector.pattern_weights) + len(detector.negative_patterns)

        if pattern_count == 0:
            console.print("[yellow]ML model is already empty[/yellow]")
            return

        if not yes:
            console.print(
                f"[yellow]Warning:[/yellow] This will delete {pattern_count} learned patterns"
            )
            console.print(f"[dim]Model: {model_path}[/dim]\n")

            if not click.confirm("Are you sure you want to reset the ML model?"):
                console.print("[dim]Cancelled[/dim]")
                return

        model_path.unlink()

        console.print("[green]✓ ML model reset[/green]")
        console.print(f"[dim]Deleted {pattern_count} patterns from {model_path}[/dim]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


def _extract_strings(data: bytes, min_len: int = 4) -> list[dict]:
    results = []
    # ASCII strings
    current = bytearray()
    offset = 0
    for i, byte in enumerate(data):
        if 32 <= byte < 127:
            if not current:
                offset = i
            current.append(byte)
        else:
            if len(current) >= min_len:
                results.append(
                    {
                        "type": "ascii",
                        "offset": offset,
                        "data": bytes(current),
                        "length": len(current),
                    }
                )
            current = bytearray()
    if len(current) >= min_len:
        results.append(
            {
                "type": "ascii",
                "offset": len(data) - len(current),
                "data": bytes(current),
                "length": len(current),
            }
        )

    # Unicode (UTF-16LE) strings
    current = bytearray()
    offset = 0
    i = 0
    while i < len(data) - 1:
        if data[i + 1] == 0 and 32 <= data[i] < 127:
            if not current:
                offset = i
            current.extend(data[i : i + 2])
            i += 2
        else:
            if len(current) >= min_len * 2:
                results.append(
                    {
                        "type": "unicode",
                        "offset": offset,
                        "data": bytes(current),
                        "length": len(current) // 2,
                    }
                )
            current = bytearray()
            i += 1
    if len(current) >= min_len * 2:
        results.append(
            {
                "type": "unicode",
                "offset": len(data) - len(current),
                "data": bytes(current),
                "length": len(current) // 2,
            }
        )

    results.sort(key=lambda r: r["offset"])
    return results


def _string_entropy(s: bytes) -> float:
    if not s:
        return 0.0
    freq = [0] * 256
    for b in s:
        freq[b] += 1
    import math

    entropy = 0.0
    for f in freq:
        if f > 0:
            p = f / len(s)
            entropy -= p * math.log2(p)
    return entropy


def _detect_encoding(s: bytes) -> Optional[str]:
    import base64

    try:
        decoded = base64.b64decode(s, validate=True)
        if len(decoded) > 2 and len(decoded) <= len(s) * 3 // 4:
            return f"base64 ({len(decoded)} bytes)"
    except Exception:
        pass
    printable_count = sum(1 for b in s if 32 <= b < 127)
    if len(s) > 0 and printable_count / len(s) > 0.8:
        try:
            s.decode("utf-8")
            return "utf-8"
        except Exception:
            pass
    if len(s) > 0 and printable_count / len(s) > 0.5:
        try:
            s.decode("utf-16-le")
            return "utf-16le"
        except Exception:
            pass
    return None


@main.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option("-n", "--min-len", default=4, type=int, help="Minimum string length")
@click.option("-e", "--entropy", "min_entropy", type=float, help="Minimum entropy filter")
@click.option("--encode-detect", is_flag=True, help="Detect encoding (base64, utf-8)")
@click.option("--regex", help="Regex pattern to search for")
@click.option(
    "--type",
    "string_type",
    type=click.Choice(["ascii", "unicode", "all"]),
    default="all",
    help="String type to extract",
)
@click.option("-c", "--count", type=int, default=0, help="Limit number of strings shown (0 = all)")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
@click.option("--offsets/--no-offsets", default=True, help="Show byte offsets")
@click.option("--entropy-colors/--no-entropy-colors", default=True, help="Color by entropy")
def strings_cmd(
    file_path: str,
    min_len: int,
    min_entropy: float,
    encode_detect: bool,
    regex: str,
    string_type: str,
    count: int,
    output_json: bool,
    offsets: bool,
    entropy_colors: bool,
) -> None:
    """
    Extract strings from binary files with advanced filtering.

    Supports ASCII and Unicode strings, entropy filtering, encoding detection,
    and regex pattern matching.

    Examples:
        filo strings file.bin
        filo strings file.bin -n 8                     # Minimum 8 chars
        filo strings file.bin -e 5.0                   # Only high-entropy strings
        filo strings file.bin --encode-detect          # Show encoding detection
        filo strings file.bin --regex "picoCTF\\{.*\\}"  # Search for CTF flags
        filo strings file.bin --type unicode           # Unicode only
        filo strings file.bin -c 20 --json             # Top 20 as JSON
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        all_strings = _extract_strings(data, min_len)

        # Filter by type
        if string_type == "ascii":
            all_strings = [s for s in all_strings if s["type"] == "ascii"]
        elif string_type == "unicode":
            all_strings = [s for s in all_strings if s["type"] == "unicode"]

        # Filter by regex
        if regex:
            import re as re_module

            try:
                pattern = re_module.compile(regex.encode())
                all_strings = [s for s in all_strings if pattern.search(s["data"])]
            except re_module.error as e:
                console.print(f"[red]Invalid regex: {e}[/red]")
                sys.exit(1)

        # Filter by entropy
        if min_entropy is not None:
            filtered = []
            for s in all_strings:
                e = _string_entropy(s["data"])
                if e >= min_entropy:
                    filtered.append(s)
            all_strings = filtered

        # Limit count
        if count > 0:
            all_strings = all_strings[:count]

        if output_json:
            import json as json_module

            output = []
            for s in all_strings:
                entry = {
                    "offset": s["offset"],
                    "type": s["type"],
                    "length": s["length"],
                    "string": s["data"].decode("utf-8", errors="replace"),
                    "entropy": round(_string_entropy(s["data"]), 2),
                }
                if encode_detect:
                    entry["encoding"] = _detect_encoding(s["data"])
                output.append(entry)
            console.print(json_module.dumps(output, indent=2))
        else:
            if not all_strings:
                console.print("[yellow]No strings found matching criteria[/yellow]")
                return

            console.print(f"\n[bold]Strings in:[/bold] {file_path}")
            console.print(
                f"[dim]{len(all_strings)} string(s) found (min length: {min_len})[/dim]\n"
            )

            for s in all_strings:
                entropy = _string_entropy(s["data"])
                text = s["data"].decode("utf-8", errors="replace")
                text = text.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")

                # Truncate long strings for display
                display = text[:200] + "..." if len(text) > 200 else text

                # Color by entropy
                if entropy_colors:
                    if entropy > 6.5:
                        color = "red"
                    elif entropy > 5.0:
                        color = "yellow"
                    elif entropy > 3.5:
                        color = "cyan"
                    else:
                        color = "white"
                else:
                    color = "white"

                parts = []
                if offsets:
                    parts.append(f"[dim]0x{s['offset']:08x}[/dim]")
                parts.append(f"[{color}]{display}[/{color}]")

                if encode_detect:
                    enc = _detect_encoding(s["data"])
                    if enc:
                        parts.append(f"[green]({enc})[/green]")

                console.print("  ".join(parts))

            console.print("\n[dim]Use --json for machine-readable output[/dim]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
