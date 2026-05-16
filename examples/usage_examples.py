"""
Example usage scripts for Filo
"""

from filo import Analyzer, RepairEngine, FormatDatabase


def example_basic_analysis():
    """Basic file analysis example."""
    print("=== Basic File Analysis ===\n")

    # Create analyzer
    analyzer = Analyzer()

    # Create sample PNG data
    png_data = bytes.fromhex("89504E470D0A1A0A0000000D49484452")
    png_data += b"\x00" * 100

    # Analyze
    result = analyzer.analyze(png_data)

    print(f"Detected Format: {result.primary_format}")
    print(f"Confidence: {result.confidence:.1%}")
    print(f"File Size: {result.file_size} bytes")
    print(f"Entropy: {result.entropy:.2f} bits/byte")
    print(f"SHA256: {result.checksum_sha256}")

    if result.alternative_formats:
        print("\nAlternative Possibilities:")
        for fmt, conf in result.alternative_formats:
            print(f"  - {fmt}: {conf:.1%}")

    print("\nEvidence Chain:")
    for evidence in result.evidence_chain:
        print(f"  Module: {evidence['module']}")
        print(f"  Confidence: {evidence['confidence']:.1%}")
        for e in evidence.get("evidence", []):
            print(f"    • {e}")


def example_repair():
    """File repair example."""
    print("\n\n=== File Repair ===\n")

    # Create repair engine
    engine = RepairEngine()

    # Corrupted PDF (missing header)
    corrupted_pdf = b"1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"

    print(f"Original data: {corrupted_pdf[:50]}...")

    # Repair
    repaired, report = engine.repair(corrupted_pdf, "pdf", strategy="auto")

    print(f"\nRepair Status: {'SUCCESS' if report.success else 'FAILED'}")
    print(f"Strategy Used: {report.strategy_used}")
    print(f"Changes Made:")
    for change in report.changes_made:
        print(f"  • {change}")

    print(f"\nRepaired data: {repaired[:50]}...")


def example_format_database():
    """Format database query example."""
    print("\n\n=== Format Database ===\n")

    db = FormatDatabase()

    print(f"Total formats loaded: {db.count()}")

    # Get specific format
    png_spec = db.get_format("png")
    if png_spec:
        print(f"\nPNG Format:")
        print(f"  Version: {png_spec.version}")
        print(f"  Category: {png_spec.category}")
        print(f"  MIME Types: {', '.join(png_spec.mime)}")
        print(f"  Extensions: {', '.join(png_spec.extensions)}")
        print(f"  Signatures: {len(png_spec.signatures)}")
        print(f"  Repair Strategies: {len(png_spec.repair_strategies)}")

    # List by category
    print("\nImage Formats:")
    image_formats = db.get_formats_by_category("raster_image")
    for spec in image_formats:
        print(f"  • {spec.format} ({', '.join(spec.extensions)})")

    # List by extension
    print("\nFormats using .pdf extension:")
    pdf_formats = db.get_formats_by_extension("pdf")
    for spec in pdf_formats:
        print(f"  • {spec.format}")


def example_multi_format_detection():
    """Detect multiple file formats."""
    print("\n\n=== Multi-Format Detection ===\n")

    analyzer = Analyzer()

    test_files = {
        "PNG": bytes.fromhex("89504E470D0A1A0A"),
        "JPEG": bytes.fromhex("FFD8FFE0"),
        "PDF": b"%PDF-1.7\r\n",
        "ZIP": bytes.fromhex("504B0304"),
        "ELF": bytes.fromhex("7F454C46"),
    }

    for name, data in test_files.items():
        # Pad with some data
        padded_data = data + b"\x00" * 100
        result = analyzer.analyze(padded_data)

        status = "✓" if result.confidence > 0.7 else "?"
        print(f"{status} {name:8s} -> {result.primary_format:10s} ({result.confidence:.1%})")


if __name__ == "__main__":
    example_basic_analysis()
    example_repair()
    example_format_database()
    example_multi_format_detection()
