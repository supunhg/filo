#!/usr/bin/env python3
"""
Contradiction Detection Demonstration

Shows how Filo detects format contradictions, embedded malware,
and structural anomalies for security analysis and malware triage.

Usage:
    python examples/contradiction_demo.py
"""

import io
import os
import sys
import zipfile
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from filo.analyzer import Analyzer
from filo.models import Contradiction
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

console = Console()


def create_demo_files():
    """Create demonstration files in /tmp directory"""
    demo_dir = Path("/tmp/filo_contradiction_demos")
    demo_dir.mkdir(exist_ok=True)

    # 1. PNG with invalid compression
    png_invalid = demo_dir / "corrupted.png"
    png_data = (
        b"\x89PNG\r\n\x1a\n"  # PNG signature
        b"\x00\x00\x00\x0dIHDR"  # IHDR chunk
        b"\x00\x00\x00\x10\x00\x00\x00\x10\x08\x02\x00\x00\x00"  # IHDR data
        b"\x90\x91\x68\x36"  # CRC
        b"\x00\x00\x00\x0cIDAT"  # IDAT chunk
        b"INVALID_ZLIB"  # Invalid zlib data
        b"\x00\x00\x00\x00"  # CRC
        b"\x00\x00\x00\x00IEND"  # IEND chunk
        b"\xae\x42\x60\x82"  # CRC
    )
    png_invalid.write_bytes(png_data)

    # 2. DOCX missing _rels/.rels
    docx_malformed = demo_dir / "malformed.docx"
    with zipfile.ZipFile(docx_malformed, "w") as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types/>')
        zf.writestr("word/document.xml", '<?xml version="1.0"?><document/>')
        # Missing _rels/.rels - will trigger warning

    # 3. DOCX with embedded ELF executable
    docx_malicious = demo_dir / "malicious.docx"
    elf_payload = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56  # ELF header
    with zipfile.ZipFile(docx_malicious, "w") as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types/>')
        zf.writestr("_rels/.rels", '<?xml version="1.0"?><Relationships/>')
        zf.writestr("word/document.xml", '<?xml version="1.0"?><document/>')
        zf.writestr("word/media/exploit.dll", elf_payload)  # Embedded ELF

    # 4. DOCX with embedded PE executable
    docx_pe = demo_dir / "suspicious.docx"
    pe_payload = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00"  # PE header
    with zipfile.ZipFile(docx_pe, "w") as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types/>')
        zf.writestr("_rels/.rels", '<?xml version="1.0"?><Relationships/>')
        zf.writestr("word/document.xml", '<?xml version="1.0"?><document/>')
        zf.writestr("word/media/payload.exe", pe_payload)  # Embedded PE

    # 5. ZIP with shell script
    zip_script = demo_dir / "weaponized.zip"
    script_payload = b"#!/bin/bash\nrm -rf /"  # Malicious script
    with zipfile.ZipFile(zip_script, "w") as zf:
        zf.writestr("data.txt", "Normal content")
        zf.writestr("scripts/install.sh", script_payload)  # Embedded script

    # 6. PDF missing EOF
    pdf_truncated = demo_dir / "truncated.pdf"
    pdf_data = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"xref\n0 1\n"
        # Missing %%EOF
    )
    pdf_truncated.write_bytes(pdf_data)

    # 7. JPEG missing SOS marker
    jpeg_incomplete = demo_dir / "incomplete.jpg"
    jpeg_data = (
        b"\xff\xd8"  # JPEG SOI
        b"\xff\xc0\x00\x11\x08\x00\x10\x00\x10\x03\x01\x22\x00\x02\x11\x01\x03\x11\x01"  # SOF
        # Missing SOS marker
        b"\xff\xd9"  # JPEG EOI
    )
    jpeg_incomplete.write_bytes(jpeg_data)

    # 8. Valid PNG (no contradictions)
    png_valid = demo_dir / "valid.png"
    import zlib

    width_height = b"\x00\x00\x00\x10" * 2  # 16x16 pixels
    ihdr_data = width_height + b"\x08\x02\x00\x00\x00"  # RGB, no interlace
    ihdr_crc = b"\x90\x91\x68\x36"  # Pre-calculated

    # Create valid IDAT with zlib compression
    raw_image = b"\x00" + (b"\x00" * 16 * 3) * 16  # Blank 16x16 RGB
    compressed = zlib.compress(raw_image)
    idat_crc = b"\x00\x00\x00\x00"  # Simplified

    png_valid_data = (
        b"\x89PNG\r\n\x1a\n"
        b"\x00\x00\x00\x0dIHDR"
        + ihdr_data
        + ihdr_crc
        + bytes(
            [
                len(compressed) >> 24,
                len(compressed) >> 16 & 0xFF,
                len(compressed) >> 8 & 0xFF,
                len(compressed) & 0xFF,
            ]
        )
        + b"IDAT"
        + compressed
        + idat_crc
        + b"\x00\x00\x00\x00IEND\xae\x42\x60\x82"
    )
    png_valid.write_bytes(png_valid_data)

    return demo_dir


def display_header(title: str, description: str):
    """Display a formatted section header"""
    console.print()
    console.print(
        Panel(f"[bold cyan]{title}[/bold cyan]\n[dim]{description}[/dim]", border_style="cyan")
    )


def display_contradictions(contradictions: list[Contradiction]):
    """Display contradictions in a formatted table"""
    if not contradictions:
        console.print("[green]✓ No contradictions detected[/green]\n")
        return

    console.print(f"\n[yellow]⚠ {len(contradictions)} Contradiction(s) Detected:[/yellow]\n")

    table = Table(show_header=True, header_style="bold magenta", border_style="dim")
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Issue", width=40)
    table.add_column("Details", width=50)
    table.add_column("Category", width=12)

    for c in contradictions:
        # Color coding by severity
        severity_style = {
            "warning": "[yellow]⚠ WARNING[/yellow]",
            "error": "[orange3]⚠ ERROR[/orange3]",
            "critical": "[red]🚨 CRITICAL[/red]",
        }.get(c.severity, c.severity.upper())

        table.add_row(severity_style, c.issue, c.details, c.category)

    console.print(table)
    console.print()


def demo_1_png_corruption():
    """Demo 1: PNG with invalid compression"""
    display_header(
        "Demo 1: PNG Compression Validation",
        "Detects PNG files with invalid zlib compression (corruption or steganography)",
    )

    demo_dir = Path("/tmp/filo_contradiction_demos")
    file_path = demo_dir / "corrupted.png"

    console.print(f"[bold]Analyzing:[/bold] {file_path}")
    console.print(
        "[dim]File has PNG signature and IHDR chunk, but IDAT contains invalid zlib data[/dim]\n"
    )

    analyzer = Analyzer()
    result = analyzer.analyze_file(file_path)

    console.print(
        f"[bold]Detected Format:[/bold] {result.primary_format} ({result.confidence:.1f}% confidence)"
    )
    console.print(
        f"[bold]Evidence:[/bold] {', '.join(str(e.get('module', '')) for e in result.evidence_chain[:2])}"
    )

    display_contradictions(result.contradictions)

    console.print("[cyan]💡 Interpretation:[/cyan]")
    console.print("  - PNG structure is valid (signature + IHDR)")
    console.print("  - Compression stream is corrupted or intentionally malformed")
    console.print("  - Could indicate: steganography, manual editing, or file corruption")
    console.print("  - [yellow]Action: Investigate origin, check for hidden data[/yellow]\n")


def demo_2_ooxml_structure():
    """Demo 2: DOCX with missing mandatory files"""
    display_header(
        "Demo 2: OOXML Structure Validation",
        "Detects Office documents missing mandatory relationship files",
    )

    demo_dir = Path("/tmp/filo_contradiction_demos")
    file_path = demo_dir / "malformed.docx"

    console.print(f"[bold]Analyzing:[/bold] {file_path}")
    console.print("[dim]DOCX file missing required '_rels/.rels' file[/dim]\n")

    analyzer = Analyzer()
    result = analyzer.analyze_file(file_path)

    console.print(
        f"[bold]Detected Format:[/bold] {result.primary_format} ({result.confidence:.1f}% confidence)"
    )
    console.print(
        f"[bold]Evidence:[/bold] {', '.join(str(e.get('module', '')) for e in result.evidence_chain[:2])}"
    )

    display_contradictions(result.contradictions)

    console.print("[cyan]💡 Interpretation:[/cyan]")
    console.print("  - File is valid ZIP and contains OOXML markers")
    console.print("  - Missing '_rels/.rels' - required for all Office Open XML files")
    console.print("  - Could indicate: manual ZIP creation, incomplete extraction, or malware")
    console.print(
        "  - [yellow]Action: Verify file origin, check if intentionally crafted[/yellow]\n"
    )


def demo_3_embedded_elf():
    """Demo 3: DOCX with embedded ELF executable"""
    display_header(
        "Demo 3: Embedded Executable Detection (ELF)",
        "Detects Linux executables hidden in Office documents - CRITICAL malware indicator",
    )

    demo_dir = Path("/tmp/filo_contradiction_demos")
    file_path = demo_dir / "malicious.docx"

    console.print(f"[bold]Analyzing:[/bold] {file_path}")
    console.print("[dim]DOCX file contains embedded ELF executable in ZIP member[/dim]\n")

    analyzer = Analyzer()
    result = analyzer.analyze_file(file_path)

    console.print(
        f"[bold]Detected Format:[/bold] {result.primary_format} ({result.confidence:.1f}% confidence)"
    )
    console.print(
        f"[bold]Evidence:[/bold] {', '.join(str(e.get('module', '')) for e in result.evidence_chain[:2])}"
    )

    display_contradictions(result.contradictions)

    console.print("[red][bold]🚨 CRITICAL ALERT[/bold][/red]")
    console.print("[cyan]💡 Interpretation:[/cyan]")
    console.print("  - Legitimate Office documents NEVER contain executable binaries")
    console.print("  - ELF signature detected in ZIP member 'word/media/exploit.dll'")
    console.print("  - [red][bold]HIGH PROBABILITY OF MALWARE[/bold][/red]")
    console.print("  - Could be: payload, dropper, or APT technique")
    console.print(
        "  - [red][bold]Action: QUARANTINE IMMEDIATELY - Full malware analysis required[/bold][/red]\n"
    )


def demo_4_embedded_pe():
    """Demo 4: DOCX with embedded PE executable"""
    display_header(
        "Demo 4: Embedded Executable Detection (PE)",
        "Detects Windows executables hidden in Office documents",
    )

    demo_dir = Path("/tmp/filo_contradiction_demos")
    file_path = demo_dir / "suspicious.docx"

    console.print(f"[bold]Analyzing:[/bold] {file_path}")
    console.print("[dim]DOCX file contains embedded PE/DOS executable[/dim]\n")

    analyzer = Analyzer()
    result = analyzer.analyze_file(file_path)

    console.print(
        f"[bold]Detected Format:[/bold] {result.primary_format} ({result.confidence:.1f}% confidence)"
    )
    console.print(
        f"[bold]Evidence:[/bold] {', '.join(str(e.get('module', '')) for e in result.evidence_chain[:2])}"
    )

    display_contradictions(result.contradictions)

    console.print("[red][bold]🚨 CRITICAL ALERT[/bold][/red]")
    console.print("[cyan]💡 Interpretation:[/cyan]")
    console.print("  - PE (Portable Executable) signature detected")
    console.print("  - Windows executable embedded in document file")
    console.print("  - [red][bold]Strong indicator of malicious activity[/bold][/red]")
    console.print("  - [red][bold]Action: Do not open - Submit to malware analysis[/bold][/red]\n")


def demo_5_embedded_script():
    """Demo 5: ZIP with embedded shell script"""
    display_header("Demo 5: Embedded Script Detection", "Detects shell scripts in archive files")

    demo_dir = Path("/tmp/filo_contradiction_demos")
    file_path = demo_dir / "weaponized.zip"

    console.print(f"[bold]Analyzing:[/bold] {file_path}")
    console.print("[dim]ZIP file contains shell script with suspicious shebang[/dim]\n")

    analyzer = Analyzer()
    result = analyzer.analyze_file(file_path)

    console.print(
        f"[bold]Detected Format:[/bold] {result.primary_format} ({result.confidence:.1f}% confidence)"
    )
    console.print(
        f"[bold]Evidence:[/bold] {', '.join(str(e.get('module', '')) for e in result.evidence_chain[:2])}"
    )

    display_contradictions(result.contradictions)

    console.print("[cyan]💡 Interpretation:[/cyan]")
    console.print("  - Bash script detected in ZIP archive")
    console.print("  - Shell scripts can be legitimate (installers, automation)")
    console.print("  - [yellow]Context matters:[/yellow]")
    console.print("    • Expected in software packages ✓")
    console.print("    • Unexpected in email attachments ✗")
    console.print("  - [yellow]Action: Review script content before execution[/yellow]\n")


def demo_6_pdf_truncation():
    """Demo 6: PDF missing EOF marker"""
    display_header("Demo 6: PDF Structure Validation", "Detects truncated or incomplete PDF files")

    demo_dir = Path("/tmp/filo_contradiction_demos")
    file_path = demo_dir / "truncated.pdf"

    console.print(f"[bold]Analyzing:[/bold] {file_path}")
    console.print("[dim]PDF file missing required '%%EOF' marker[/dim]\n")

    analyzer = Analyzer()
    result = analyzer.analyze_file(file_path)

    console.print(
        f"[bold]Detected Format:[/bold] {result.primary_format} ({result.confidence:.1f}% confidence)"
    )
    console.print(
        f"[bold]Evidence:[/bold] {', '.join(str(e.get('module', '')) for e in result.evidence_chain[:2])}"
    )

    display_contradictions(result.contradictions)

    console.print("[cyan]💡 Interpretation:[/cyan]")
    console.print("  - PDF signature present but structure incomplete")
    console.print("  - Missing '%%EOF' indicates file truncation")
    console.print("  - Could indicate: incomplete download, corruption, or manual editing")
    console.print("  - [yellow]Action: Re-download or verify file integrity[/yellow]\n")


def demo_7_jpeg_incomplete():
    """Demo 7: JPEG missing SOS marker"""
    display_header(
        "Demo 7: JPEG Structure Validation", "Detects JPEG files with incomplete marker sequence"
    )

    demo_dir = Path("/tmp/filo_contradiction_demos")
    file_path = demo_dir / "incomplete.jpg"

    console.print(f"[bold]Analyzing:[/bold] {file_path}")
    console.print("[dim]JPEG has SOF (Start of Frame) but missing SOS (Start of Scan)[/dim]\n")

    analyzer = Analyzer()
    result = analyzer.analyze_file(file_path)

    console.print(
        f"[bold]Detected Format:[/bold] {result.primary_format} ({result.confidence:.1f}% confidence)"
    )
    console.print(
        f"[bold]Evidence:[/bold] {', '.join(str(e.get('module', '')) for e in result.evidence_chain[:2])}"
    )

    display_contradictions(result.contradictions)

    console.print("[cyan]💡 Interpretation:[/cyan]")
    console.print("  - JPEG structure started but incomplete")
    console.print("  - SOF marker defines image dimensions")
    console.print("  - Missing SOS marker means no actual image data")
    console.print("  - Could indicate: file corruption or manual manipulation")
    console.print("  - [yellow]Action: File cannot be rendered, verify integrity[/yellow]\n")


def demo_8_valid_file():
    """Demo 8: Valid PNG (no contradictions)"""
    display_header(
        "Demo 8: Valid File Validation", "Confirms no false positives on correctly formatted files"
    )

    demo_dir = Path("/tmp/filo_contradiction_demos")
    file_path = demo_dir / "valid.png"

    console.print(f"[bold]Analyzing:[/bold] {file_path}")
    console.print("[dim]Properly formatted PNG with valid zlib compression[/dim]\n")

    analyzer = Analyzer()
    result = analyzer.analyze_file(file_path)

    console.print(
        f"[bold]Detected Format:[/bold] {result.primary_format} ({result.confidence:.1f}% confidence)"
    )
    console.print(
        f"[bold]Evidence:[/bold] {', '.join(str(e.get('module', '')) for e in result.evidence_chain[:2])}"
    )

    display_contradictions(result.contradictions)

    console.print("[green]✓ File structure is valid and complete[/green]")
    console.print("[cyan]💡 Interpretation:[/cyan]")
    console.print("  - All structural checks passed")
    console.print("  - No embedded executables or scripts detected")
    console.print("  - Compression streams are valid")
    console.print("  - [green]Action: File is likely benign and correctly formatted[/green]\n")


def demo_9_json_output():
    """Demo 9: JSON output for automation"""
    display_header(
        "Demo 9: JSON Output for Automation",
        "Shows structured contradiction data for security tools integration",
    )

    demo_dir = Path("/tmp/filo_contradiction_demos")
    file_path = demo_dir / "malicious.docx"

    console.print(f"[bold]Analyzing:[/bold] {file_path}")
    console.print("[dim]Demonstrating JSON export for automated malware triage[/dim]\n")

    analyzer = Analyzer()
    result = analyzer.analyze_file(file_path)

    # Convert to JSON-like structure
    import json

    json_output = {
        "file": str(file_path),
        "format": result.primary_format,
        "confidence": result.confidence,
        "evidence": [
            {
                "module": e.get("module", "unknown"),
                "confidence": e.get("confidence", 0),
                "evidence": e.get("evidence", [])[:2],  # First 2 evidence items only
            }
            for e in result.evidence_chain[:3]  # First 3 modules only
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
    }

    syntax = Syntax(json.dumps(json_output, indent=2), "json", theme="monokai", line_numbers=True)
    console.print(syntax)

    console.print("\n[cyan]💡 Integration Example:[/cyan]")
    console.print("  [dim]# Filter for critical contradictions[/dim]")
    console.print("  $ filo analyze suspicious.docx --json | \\")
    console.print("    jq '.contradictions[] | select(.severity == \"critical\")'")
    console.print()
    console.print("  [dim]# Batch scan and quarantine[/dim]")
    console.print("  $ for file in *.docx; do")
    console.print('      critical=$(filo analyze "$file" --json | \\')
    console.print("                jq '.contradictions[] | select(.severity == \"critical\")')")
    console.print('      [ -n "$critical" ] && mv "$file" /quarantine/')
    console.print("    done\n")


def main():
    """Run all contradiction detection demonstrations"""
    console.print("[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold cyan]  Filo Format Contradiction Detection - Demonstrations [/bold cyan]")
    console.print("[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]")
    console.print()
    console.print(
        "[dim]This demo shows how Filo detects malware, polyglots, and structural anomalies[/dim]"
    )
    console.print("[dim]for security analysis and malware triage.[/dim]")

    # Create demonstration files
    console.print("\n[yellow]Creating demonstration files...[/yellow]")
    demo_dir = create_demo_files()
    console.print(f"[green]✓ Demo files created in: {demo_dir}[/green]")

    # Run demonstrations
    demos = [
        demo_1_png_corruption,
        demo_2_ooxml_structure,
        demo_3_embedded_elf,
        demo_4_embedded_pe,
        demo_5_embedded_script,
        demo_6_pdf_truncation,
        demo_7_jpeg_incomplete,
        demo_8_valid_file,
        demo_9_json_output,
    ]

    for demo in demos:
        try:
            demo()
        except Exception as e:
            console.print(f"[red]Error in demo: {e}[/red]\n")

    # Summary
    console.print("[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold cyan]  Summary: Contradiction Detection Capabilities        [/bold cyan]")
    console.print("[bold cyan]═══════════════════════════════════════════════════════[/bold cyan]")
    console.print()

    summary_table = Table(show_header=True, header_style="bold magenta", border_style="cyan")
    summary_table.add_column("Detection Type", style="bold", width=25)
    summary_table.add_column("Formats", width=30)
    summary_table.add_column("Use Case", width=40)

    summary_table.add_row(
        "Compression Validation", "PNG (zlib streams)", "Detects corruption, steganography"
    )
    summary_table.add_row(
        "Structure Validation",
        "OOXML (DOCX/XLSX/PPTX)",
        "Identifies incomplete/malformed documents",
    )
    summary_table.add_row(
        "Embedded Executables", "All ZIP-based formats", "[red]CRITICAL: Malware detection[/red]"
    )
    summary_table.add_row(
        "Embedded Scripts", "ZIP archives", "Security: Identifies executable scripts"
    )
    summary_table.add_row("PDF Structure", "PDF files", "Detects truncation, corruption")
    summary_table.add_row("JPEG Structure", "JPEG files", "Validates marker sequence")

    console.print(summary_table)
    console.print()

    console.print("[bold green]✓ All demonstrations complete![/bold green]")
    console.print()
    console.print("[cyan]Next Steps:[/cyan]")
    console.print("  • Review docs/CONTRADICTION_DETECTION.md for detailed documentation")
    console.print("  • Try analyzing real files: filo analyze <file>")
    console.print("  • Use --json flag for automation and integration")
    console.print("  • Implement contradiction-based alerting in your security pipeline")
    console.print()
    console.print(f"[dim]Demo files location: {demo_dir}[/dim]")
    console.print("[dim]Feel free to analyze them with: filo analyze <file>[/dim]\n")


if __name__ == "__main__":
    main()
