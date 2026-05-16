#!/usr/bin/env python3
"""Filo v0.2.5 - Polyglot Detection Examples"""

import sys
from pathlib import Path
from filo.analyzer import Analyzer
from filo.polyglot import PolyglotDetector


def example_1_basic_polyglot_detection():
    """Basic polyglot detection using the detector directly."""
    print("=" * 70)
    print("Example 1: Basic Polyglot Detection")
    print("=" * 70)

    # Create a simple polyglot detector
    detector = PolyglotDetector()

    # Read a suspicious file
    demo_file = Path("demo/gifar_malware.gif")
    if not demo_file.exists():
        print("⚠ Demo file not found. Run: python demo/create_polyglot_files.py")
        return

    with open(demo_file, "rb") as f:
        data = f.read()

    # Detect polyglots
    polyglots = detector.detect_polyglots(data, primary_format="gif")

    print(f"\n📁 File: {demo_file}")
    print(f"📊 Size: {len(data)} bytes")
    print(f"\n⚠ Polyglots detected: {len(polyglots)}")

    for i, p in enumerate(polyglots, 1):
        print(f"\n{i}. {' + '.join(p.formats).upper()}")
        print(f"   Pattern: {p.pattern}")
        print(f"   Description: {p.description}")
        print(f"   Confidence: {p.confidence:.1%}")
        print(f"   Risk Level: {p.risk_level.upper()}")
        print(f"   Evidence: {p.evidence}")


def example_2_analyzer_integration():
    """Polyglot detection integrated with the full analyzer."""
    print("\n" + "=" * 70)
    print("Example 2: Analyzer Integration")
    print("=" * 70)

    demo_file = Path("demo/malicious_document.pdf")
    if not demo_file.exists():
        print("⚠ Demo file not found. Run: python demo/create_polyglot_files.py")
        return

    # Create analyzer with polyglot detection enabled (default)
    analyzer = Analyzer(detect_polyglots=True)

    # Analyze file - read data first
    with open(demo_file, "rb") as f:
        data = f.read()

    result = analyzer.analyze(data, file_path=str(demo_file))

    print(f"\n📁 File: {demo_file}")
    print(f"🎯 Primary Format: {result.primary_format}")
    print(f"📊 Confidence: {result.confidence:.1%}")

    if result.polyglots:
        print(f"\n⚠ Polyglots detected: {len(result.polyglots)}")
        for p in result.polyglots:
            print(f"\n  • {' + '.join(p.formats).upper()}")
            print(f"    {p.description}")
            print(f"    Risk: {p.risk_level.upper()} | Confidence: {p.confidence:.1%}")
    else:
        print("\n✓ No polyglots detected")


def example_3_format_validation():
    """Individual format validation."""
    print("\n" + "=" * 70)
    print("Example 3: Individual Format Validation")
    print("=" * 70)

    demo_file = Path("demo/polyglot_advanced.png")
    if not demo_file.exists():
        print("⚠ Demo file not found. Run: python demo/create_polyglot_files.py")
        return

    with open(demo_file, "rb") as f:
        data = f.read()

    detector = PolyglotDetector()

    print(f"\n📁 File: {demo_file}")
    print(f"📊 Size: {len(data)} bytes")
    print("\n🔍 Format Validation Results:")

    # Test multiple formats
    formats_to_test = {
        "PNG": detector._validate_png,
        "GIF": detector._validate_gif,
        "JPEG": detector._validate_jpeg,
        "ZIP": detector._validate_zip,
        "PDF": detector._validate_pdf,
        "PE": detector._validate_pe,
    }

    for format_name, validator in formats_to_test.items():
        is_valid = validator(data)
        status = "✓ VALID" if is_valid else "✗ Invalid"
        print(f"  {format_name:8} {status}")

    # Get all valid formats
    valid_formats = detector._get_valid_formats(data)
    print(f"\n✓ File is valid as: {', '.join(valid_formats).upper()}")


def example_4_javascript_detection():
    """JavaScript payload detection in PDFs."""
    print("\n" + "=" * 70)
    print("Example 4: JavaScript Payload Detection")
    print("=" * 70)

    demo_file = Path("demo/malicious_document.pdf")
    if not demo_file.exists():
        print("⚠ Demo file not found. Run: python demo/create_polyglot_files.py")
        return

    with open(demo_file, "rb") as f:
        data = f.read()

    detector = PolyglotDetector()

    print(f"\n📁 File: {demo_file}")

    # Check if it's a valid PDF
    is_pdf = detector._validate_pdf(data)
    print(f"📄 Valid PDF: {is_pdf}")

    if is_pdf:
        # Check for JavaScript payload
        has_js = detector._has_js_payload(data)
        print(f"⚠ JavaScript Detected: {has_js}")

        if has_js:
            # Look for specific indicators
            js_indicators = [
                b"/JavaScript",
                b"/JS",
                b"/AA",
                b"/OpenAction",
                b"eval(",
                b"unescape(",
                b"String.fromCharCode",
            ]

            print("\n🔍 JavaScript Indicators Found:")
            for indicator in js_indicators:
                if indicator in data:
                    print(f"  ✓ {indicator.decode('latin1', errors='ignore')}")


def example_5_security_filtering():
    """Security-focused polyglot filtering."""
    print("\n" + "=" * 70)
    print("Example 5: Security Filtering")
    print("=" * 70)

    print("\n🛡️ Security Policy: Block HIGH risk polyglots\n")

    test_files = [
        ("demo/gifar_malware.gif", "GIFAR Attack"),
        ("demo/polyglot_advanced.png", "PNG+ZIP Steganography"),
        ("demo/malicious_document.pdf", "PDF with JavaScript"),
        ("demo/executable_archive.exe", "PE+ZIP Hybrid"),
    ]

    analyzer = Analyzer(detect_polyglots=True)

    for file_path, description in test_files:
        demo_file = Path(file_path)
        if not demo_file.exists():
            continue

        with open(demo_file, "rb") as f:
            data = f.read()

        result = analyzer.analyze(data, file_path=str(demo_file))

        print(f"\n📁 {demo_file.name} - {description}")

        # Check for high-risk polyglots
        high_risk = [p for p in result.polyglots if p.risk_level == "high"]
        medium_risk = [p for p in result.polyglots if p.risk_level == "medium"]
        low_risk = [p for p in result.polyglots if p.risk_level == "low"]

        if high_risk:
            print(f"  🚫 BLOCKED - High risk polyglot detected!")
            for p in high_risk:
                print(f"     Pattern: {p.pattern} ({p.confidence:.0%} confidence)")
        elif medium_risk:
            print(f"  ⚠️  WARNING - Medium risk polyglot detected")
            for p in medium_risk:
                print(f"     Pattern: {p.pattern} ({p.confidence:.0%} confidence)")
        elif low_risk:
            print(f"  ℹ️  INFO - Low risk polyglot (benign)")
        else:
            print(f"  ✅ ALLOWED - No polyglots detected")


def example_6_batch_analysis():
    """Batch polyglot analysis of multiple files."""
    print("\n" + "=" * 70)
    print("Example 6: Batch Polyglot Analysis")
    print("=" * 70)

    demo_dir = Path("demo")
    if not demo_dir.exists():
        print("⚠ Demo directory not found")
        return

    analyzer = Analyzer(detect_polyglots=True)

    # Find all demo polyglot files
    polyglot_files = [
        "gifar_malware.gif",
        "polyglot_advanced.png",
        "malicious_document.pdf",
        "image_with_archive.jpg",
        "executable_archive.exe",
    ]

    print("\n📊 Analyzing demo polyglot files...\n")

    results = []
    for filename in polyglot_files:
        file_path = demo_dir / filename
        if not file_path.exists():
            continue

        with open(file_path, "rb") as f:
            data = f.read()

        result = analyzer.analyze(data, file_path=str(file_path))
        results.append((filename, result))

    # Summary statistics
    total_files = len(results)
    files_with_polyglots = sum(1 for _, r in results if r.polyglots)
    high_risk_count = sum(1 for _, r in results for p in r.polyglots if p.risk_level == "high")

    print(f"📁 Total files analyzed: {total_files}")
    print(f"⚠️  Files with polyglots: {files_with_polyglots}")
    print(f"🚨 High-risk detections: {high_risk_count}")

    print("\n📋 Detailed Results:\n")
    for filename, result in results:
        print(f"  {filename}")
        print(f"    Format: {result.primary_format}")
        if result.polyglots:
            for p in result.polyglots:
                risk_symbol = {"high": "🚨", "medium": "⚠️", "low": "ℹ️"}[p.risk_level]
                print(f"    {risk_symbol} {p.pattern}: {' + '.join(p.formats)}")
        else:
            print(f"    ✓ No polyglots")
        print()


def main():
    """Run all examples."""
    print("\n" + "=" * 70)
    print(" " * 10 + "Filo v0.2.5 - Polyglot Detection Examples")
    print("=" * 70)

    # Check if demo files exist
    demo_dir = Path("demo")
    if not demo_dir.exists() or not (demo_dir / "gifar_malware.gif").exists():
        print("\n⚠️  Demo files not found!")
        print("Please run first: python demo/create_polyglot_files.py\n")
        return 1

    try:
        example_1_basic_polyglot_detection()
        example_2_analyzer_integration()
        example_3_format_validation()
        example_4_javascript_detection()
        example_5_security_filtering()
        example_6_batch_analysis()

        print("\n" + "=" * 70)
        print("✅ All examples completed successfully!")
        print("=" * 70)
        print("\nFor more information, see:")
        print("  - docs/POLYGLOT_DETECTION.md")
        print("  - RELEASE_v0.2.5.md")
        print("=" * 70 + "\n")

        return 0

    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
