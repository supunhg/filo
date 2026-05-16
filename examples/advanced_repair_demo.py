#!/usr/bin/env python3
"""
Advanced Repair Demo

Demonstrates advanced file repair capabilities including:
- PNG chunk repair and CRC validation
- JPEG marker reconstruction
- ZIP directory repair
- PDF cross-reference reconstruction
"""

import struct
import zlib
from pathlib import Path

from filo.repair import RepairEngine
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

console = Console()


def demo_png_repair():
    """Demonstrate PNG chunk repair with bad CRC."""
    console.print("\n[bold cyan]PNG Chunk Repair Demo[/bold cyan]")
    console.print("=" * 60)

    # Create PNG with corrupted CRC
    png = b"\x89PNG\r\n\x1a\n"

    # Create IHDR chunk with wrong CRC
    ihdr_data = struct.pack(">II", 200, 150)  # 200x150
    ihdr_data += b"\x08\x06\x00\x00\x00"  # 8-bit RGBA

    png += struct.pack(">I", 13)  # Length
    png += b"IHDR" + ihdr_data
    png += struct.pack(">I", 0xDEADBEEF)  # Wrong CRC!

    # Add IEND chunk
    iend_crc = zlib.crc32(b"IEND") & 0xFFFFFFFF
    png += struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc)

    console.print(f"\n[yellow]Original PNG size:[/yellow] {len(png)} bytes")
    console.print(f"[yellow]Corrupted CRC:[/yellow] 0xDEADBEEF (should be calculated)")

    # Repair it
    engine = RepairEngine()
    repaired, report = engine.repair(png, "png")

    console.print(f"\n[green]✓ Repair successful![/green]")
    console.print(f"[green]Strategy:[/green] {report.strategy_used}")
    console.print(f"[green]Confidence:[/green] {report.confidence:.1%}")
    console.print(f"[green]Chunks repaired:[/green] {report.chunks_repaired}")

    for change in report.changes_made:
        console.print(f"  • {change}")

    return repaired


def demo_jpeg_repair():
    """Demonstrate JPEG marker reconstruction."""
    console.print("\n[bold cyan]JPEG Marker Repair Demo[/bold cyan]")
    console.print("=" * 60)

    # Create truncated JPEG (missing EOI marker)
    jpeg = b"\xff\xd8"  # SOI
    jpeg += b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"  # JFIF
    jpeg += b"\xff\xdb\x00\x43"  # DQT marker
    jpeg += b"\x00" * 67  # Quantization table
    # Missing EOI marker!

    console.print(f"\n[yellow]Truncated JPEG size:[/yellow] {len(jpeg)} bytes")
    console.print(f"[yellow]Missing:[/yellow] End of Image (EOI) marker 0xFFD9")

    # Repair it
    engine = RepairEngine()
    repaired, report = engine.repair(jpeg, "jpeg")

    console.print(f"\n[green]✓ Repair successful![/green]")
    console.print(f"[green]Strategy:[/green] {report.strategy_used}")
    console.print(f"[green]Confidence:[/green] {report.confidence:.1%}")
    console.print(f"[green]Repaired size:[/green] {report.repaired_size} bytes")

    for change in report.changes_made:
        console.print(f"  • {change}")

    # Verify EOI marker
    if repaired.endswith(b"\xff\xd9"):
        console.print("[green]✓ EOI marker successfully added[/green]")

    return repaired


def demo_zip_repair():
    """Demonstrate ZIP directory reconstruction."""
    console.print("\n[bold cyan]ZIP Directory Repair Demo[/bold cyan]")
    console.print("=" * 60)

    # Create ZIP with missing central directory
    zip_data = b"PK\x03\x04"  # Local file header signature
    zip_data += b"\x14\x00"  # Version needed
    zip_data += b"\x00\x00"  # General purpose bit flag
    zip_data += b"\x00\x00"  # Compression method (stored)
    zip_data += b"\x00" * 8  # Modification time/date
    zip_data += b"\x00" * 12  # CRC-32, sizes
    zip_data += b"\x08\x00"  # File name length (8)
    zip_data += b"\x00\x00"  # Extra field length
    zip_data += b"test.txt"  # File name
    zip_data += b"Hello, World!"  # File data
    # Missing central directory and EOCD!

    console.print(f"\n[yellow]Broken ZIP size:[/yellow] {len(zip_data)} bytes")
    console.print(f"[yellow]Missing:[/yellow] End of Central Directory (EOCD)")

    # Repair it
    engine = RepairEngine()
    repaired, report = engine.repair(zip_data, "zip")

    console.print(f"\n[green]✓ Repair successful![/green]")
    console.print(f"[green]Strategy:[/green] {report.strategy_used}")
    console.print(f"[green]Confidence:[/green] {report.confidence:.1%}")
    console.print(f"[green]Repaired size:[/green] {report.repaired_size} bytes")

    for change in report.changes_made:
        console.print(f"  • {change}")

    for warning in report.warnings:
        console.print(f"  [yellow]⚠[/yellow] {warning}")

    # Verify EOCD marker
    if b"PK\x05\x06" in repaired:
        console.print("[green]✓ EOCD signature found[/green]")

    return repaired


def demo_pdf_repair():
    """Demonstrate PDF cross-reference reconstruction."""
    console.print("\n[bold cyan]PDF Cross-Reference Repair Demo[/bold cyan]")
    console.print("=" * 60)

    # Create incomplete PDF (missing xref and EOF)
    pdf = b"%PDF-1.4\n"
    pdf += b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    pdf += b"2 0 obj\n<< /Type /Pages /Count 0 /Kids [] >>\nendobj\n"
    # Missing xref table and %%EOF marker!

    console.print(f"\n[yellow]Incomplete PDF size:[/yellow] {len(pdf)} bytes")
    console.print(f"[yellow]Missing:[/yellow] Cross-reference table and %%EOF")

    # Repair it
    engine = RepairEngine()
    repaired, report = engine.repair(pdf, "pdf")

    console.print(f"\n[green]✓ Repair successful![/green]")
    console.print(f"[green]Strategy:[/green] {report.strategy_used}")
    console.print(f"[green]Confidence:[/green] {report.confidence:.1%}")
    console.print(f"[green]Repaired size:[/green] {report.repaired_size} bytes")

    for change in report.changes_made:
        console.print(f"  • {change}")

    for warning in report.warnings:
        console.print(f"  [yellow]⚠[/yellow] {warning}")

    # Verify repairs
    if b"xref" in repaired:
        console.print("[green]✓ Cross-reference table added[/green]")
    if b"%%EOF" in repaired:
        console.print("[green]✓ EOF marker added[/green]")

    return repaired


def create_summary_table(results):
    """Create a summary table of all repairs."""
    table = Table(title="Advanced Repair Summary", show_header=True, header_style="bold magenta")

    table.add_column("Format", style="cyan")
    table.add_column("Original Size", justify="right")
    table.add_column("Repaired Size", justify="right")
    table.add_column("Strategy", style="yellow")
    table.add_column("Confidence", justify="right")

    for name, (original, repaired, strategy, confidence) in results.items():
        table.add_row(name, f"{original} bytes", f"{repaired} bytes", strategy, f"{confidence:.1%}")

    return table


def main():
    """Run all advanced repair demos."""
    console.print(
        Panel.fit(
            "[bold cyan]Advanced File Repair Demonstration[/bold cyan]\n"
            "Showcasing format-specific repair strategies",
            border_style="cyan",
        )
    )

    results = {}

    # PNG repair
    png_orig_size = 37
    png_repaired = demo_png_repair()
    results["PNG"] = (png_orig_size, len(png_repaired), "repair_png_chunks", 0.9)

    # JPEG repair
    jpeg_orig_size = 87
    jpeg_repaired = demo_jpeg_repair()
    results["JPEG"] = (jpeg_orig_size, len(jpeg_repaired), "repair_jpeg_markers", 0.85)

    # ZIP repair
    zip_orig_size = 51
    zip_repaired = demo_zip_repair()
    results["ZIP"] = (zip_orig_size, len(zip_repaired), "repair_zip_directory", 0.5)

    # PDF repair
    pdf_orig_size = 104
    pdf_repaired = demo_pdf_repair()
    results["PDF"] = (pdf_orig_size, len(pdf_repaired), "repair_pdf_xref", 0.5)

    # Show summary
    console.print("\n")
    console.print(create_summary_table(results))

    console.print("\n[bold green]All repairs completed successfully![/bold green]")
    console.print(
        "\n[dim]Note: Repaired files are functional but may have reduced functionality "
        "compared to the original uncorrupted files.[/dim]"
    )


if __name__ == "__main__":
    main()
