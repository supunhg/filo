#!/usr/bin/env python3
"""
Comprehensive demo of all new Filo features:
- Batch Processing
- Export (JSON/SARIF)
- Container Detection
- Performance Profiling
- Better CLI Output
"""

import tempfile
from pathlib import Path
import io
import zipfile

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from filo.batch import analyze_directory
from filo.export import JSONExporter, SARIFExporter
from filo.container import analyze_archive
from filo.profiler import profile_session
from filo.analyzer import Analyzer

console = Console()


def create_sample_files():
    """Create sample files for testing."""
    tmpdir = Path(tempfile.mkdtemp())

    # Create various file types
    (tmpdir / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
    (tmpdir / "photo.jpg").write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 100)
    (tmpdir / "document.pdf").write_bytes(b"%PDF-1.7\n" + b"\x00" * 100)

    # Create subdirectory
    subdir = tmpdir / "archives"
    subdir.mkdir()

    # Create a ZIP archive
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("README.txt", b"Hello, World!")
        zf.writestr("data.bin", b"\x00" * 50)

    (subdir / "archive.zip").write_bytes(zip_buffer.getvalue())

    return tmpdir


def demo_batch_processing():
    """Demonstrate batch directory analysis."""
    console.print(
        Panel.fit(
            "[bold cyan]Feature 1: Batch Processing[/bold cyan]\n"
            "Efficiently analyze entire directories with parallel processing",
            border_style="cyan",
        )
    )

    # Create sample files
    tmpdir = create_sample_files()

    console.print(f"\n[bold]Analyzing directory:[/bold] {tmpdir}")

    # Batch process
    result = analyze_directory(tmpdir, max_workers=4, recursive=True)

    # Show results
    table = Table(title="Batch Processing Results", show_header=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right", style="green")

    table.add_row("Total Files", str(result.total_files))
    table.add_row("Analyzed", str(result.analyzed_files))
    table.add_row("Failed", str(result.failed_files))
    table.add_row("Duration", f"{result.duration:.2f}s")
    table.add_row("Speed", f"{result.files_per_second:.1f} files/sec")

    console.print(table)

    # Show format distribution
    if result.results:
        formats = {}
        for path, res in result.results:
            fmt = res.primary_format
            formats[fmt] = formats.get(fmt, 0) + 1

        console.print("\n[bold]Format Distribution:[/bold]")
        for fmt, count in formats.items():
            console.print(f"  • {fmt}: {count}")

    return tmpdir, result


def demo_export(batch_result):
    """Demonstrate JSON and SARIF export."""
    console.print("\n")
    console.print(
        Panel.fit(
            "[bold cyan]Feature 2: Export Reports[/bold cyan]\n"
            "Export analysis results to JSON and SARIF formats",
            border_style="cyan",
        )
    )

    tmpdir, result = batch_result

    # JSON Export
    console.print("\n[bold]JSON Export:[/bold]")
    json_output = JSONExporter.export_batch(result.results, pretty=True)
    console.print(f"  Size: {len(json_output):,} bytes")
    console.print(f"  Preview: {json_output[:200]}...")

    # SARIF Export
    console.print("\n[bold]SARIF Export:[/bold]")
    sarif_output = SARIFExporter.export_batch(result.results, pretty=True)
    console.print(f"  Size: {len(sarif_output):,} bytes")
    console.print(f"  Format: Static Analysis Results Interchange Format (SARIF) 2.1.0")
    console.print(f"  Compatible with: GitHub Advanced Security, VS Code, etc.")


def demo_container_detection(tmpdir):
    """Demonstrate container file detection and analysis."""
    console.print("\n")
    console.print(
        Panel.fit(
            "[bold cyan]Feature 3: Container Detection[/bold cyan]\n"
            "Detect and recursively analyze ZIP/TAR/ISO archives",
            border_style="cyan",
        )
    )

    # Analyze the ZIP file
    zip_path = tmpdir / "archives" / "archive.zip"
    console.print(f"\n[bold]Analyzing container:[/bold] {zip_path.name}")

    with open(zip_path, "rb") as f:
        data = f.read()

    result = analyze_archive(data, recursive=True)

    if result:
        table = Table(show_header=True)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Container Type", result.container_format.upper())
        table.add_row("Total Entries", str(result.total_entries))
        table.add_row("Analyzed", str(result.analyzed_entries))

        console.print(table)

        # Show entries
        if result.entries:
            console.print("\n[bold]Container Contents:[/bold]")
            entries_table = Table(show_header=True)
            entries_table.add_column("Path")
            entries_table.add_column("Size", justify="right")
            entries_table.add_column("Type")

            for entry in result.entries:
                if not entry.is_dir:
                    entries_table.add_row(
                        entry.path, f"{entry.size:,} bytes", "dir" if entry.is_dir else "file"
                    )

            console.print(entries_table)


def demo_performance_profiling(tmpdir):
    """Demonstrate performance profiling."""
    console.print("\n")
    console.print(
        Panel.fit(
            "[bold cyan]Feature 4: Performance Profiling[/bold cyan]\n"
            "Identify bottlenecks in large file analysis",
            border_style="cyan",
        )
    )

    console.print("\n[bold]Profiling file analysis...[/bold]")

    # Profile analysis of multiple files
    with profile_session() as profiler:
        analyzer = Analyzer(use_ml=False)

        for file_path in tmpdir.glob("**/*"):
            if file_path.is_file():
                with profiler.time_operation(f"analyze_{file_path.suffix}"):
                    with open(file_path, "rb") as f:
                        data = f.read()
                    analyzer.analyze(data)

    report = profiler.report

    # Show results
    console.print(f"\n[bold]Profiling Results:[/bold]")
    console.print(f"Total Duration: [cyan]{report.total_duration:.4f}s[/cyan]")

    table = Table(show_header=True)
    table.add_column("Operation", style="cyan")
    table.add_column("Time (s)", justify="right", style="green")
    table.add_column("Calls", justify="right")
    table.add_column("Avg (s)", justify="right", style="yellow")

    for timing in report.get_sorted_timings()[:5]:
        table.add_row(
            timing.name, f"{timing.duration:.4f}", str(timing.calls), f"{timing.avg_duration:.6f}"
        )

    console.print(table)


def demo_better_output():
    """Demonstrate enhanced CLI output."""
    console.print("\n")
    console.print(
        Panel.fit(
            "[bold cyan]Feature 5: Better CLI Output[/bold cyan]\n"
            "Color-coded confidence, hex dumps, repair suggestions",
            border_style="cyan",
        )
    )

    # Create sample file
    data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100

    analyzer = Analyzer(use_ml=False)
    result = analyzer.analyze(data)

    console.print("\n[bold]Enhanced Analysis Output:[/bold]")

    table = Table(show_header=True)
    table.add_column("Property", style="cyan")
    table.add_column("Value")

    table.add_row("Format", f"[cyan]{result.primary_format}[/cyan]")

    # Color-coded confidence
    conf_color = (
        "green" if result.confidence >= 0.8 else "yellow" if result.confidence >= 0.5 else "red"
    )
    table.add_row("Confidence", f"[{conf_color}]{result.confidence:.1%}[/{conf_color}]")

    table.add_row("File Size", f"{result.file_size:,} bytes")
    table.add_row("Entropy", f"{result.entropy:.4f}" if result.entropy else "—")
    table.add_row("Checksum", result.checksum_sha256)

    console.print(table)

    # Hex dump
    console.print("\n[bold]Hex Dump (first 64 bytes):[/bold]")
    for i in range(0, min(64, len(data)), 16):
        offset = f"{i:08x}"
        hex_part = " ".join(f"{b:02x}" for b in data[i : i + 16])
        hex_part = hex_part.ljust(48)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in data[i : i + 16])
        console.print(f"  {offset}  {hex_part}  {ascii_part}")

    # Repair suggestion
    if result.confidence < 0.8:
        console.print("\n[bold cyan]💡 Repair Suggestions:[/bold cyan]")
        console.print(
            f"  Try: [green]filo repair --format={result.primary_format} file.bin[/green]"
        )


def main():
    """Run all demonstrations."""
    console.print(
        Panel.fit(
            "[bold white]Filo Features Demonstration[/bold white]\n"
            "Showcasing 5 powerful new features",
            border_style="bold white",
            title="[bold]🔍 FILO[/bold]",
        )
    )

    # Run demos
    tmpdir, batch_result = demo_batch_processing()
    demo_export((tmpdir, batch_result))
    demo_container_detection(tmpdir)
    demo_performance_profiling(tmpdir)
    demo_better_output()

    console.print("\n")
    console.print(
        Panel.fit(
            "[bold green]✓ All demonstrations completed successfully![/bold green]\n\n"
            "Ready to use in production:\n"
            "  • filo batch ./directory\n"
            "  • filo analyze --export=json --output=report.json file.bin\n"
            "  • filo analyze --container archive.zip\n"
            "  • filo profile large_file.dat\n"
            "  • filo analyze --hex-dump suspicious.bin",
            border_style="green",
            title="[bold]Summary[/bold]",
        )
    )

    # Cleanup
    import shutil

    shutil.rmtree(tmpdir)


if __name__ == "__main__":
    main()
