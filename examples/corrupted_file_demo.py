"""
Demonstration of Filo's ability to detect corrupted file formats.

This example shows how Filo can detect JPEG files even when the standard
magic bytes are corrupted, using fallback signature detection.
"""

from filo.analyzer import Analyzer


def demo_corrupted_jpeg_detection():
    """Demonstrate detection of JPEG with corrupted header."""
    print("=" * 70)
    print("Corrupted JPEG Detection Demo")
    print("=" * 70)

    analyzer = Analyzer(use_ml=False)  # Disable ML for clearer demonstration

    # Case 1: Normal JPEG with proper magic bytes
    print("\n1. Normal JPEG (proper magic bytes):")
    print("   Bytes: FF D8 FF E0 00 10 J F I F ...")

    normal_jpeg = bytes.fromhex(
        "FFD8FFE000104A4649460001010000010001000000" "FFDB004300080606070605080707070909080A0C"
    )

    result = analyzer.analyze(normal_jpeg)
    print(f"   → Detected: {result.primary_format}")
    print(f"   → Confidence: {result.confidence:.1%}")
    print(f"   → Evidence: Exact magic byte match at offset 0")

    # Case 2: Corrupted JPEG - missing SOI (FF D8) but has JFIF marker
    print("\n2. Corrupted JPEG (missing SOI marker, but JFIF present):")
    print("   Bytes: 5C 78 FF E0 00 10 J F I F ...")

    corrupted_jpeg = bytes.fromhex(
        "5C78FFE000104A4649460001010000010001000000" "FFDB004300080606070605080707070909080A0C"
    )

    result = analyzer.analyze(corrupted_jpeg)
    print(f"   → Detected: {result.primary_format}")
    print(f"   → Confidence: {result.confidence:.1%}")

    if result.evidence_chain:
        print("   → Evidence:")
        for evidence in result.evidence_chain:
            if evidence.get("module") == "signature_analysis":
                for detail in evidence.get("evidence", []):
                    print(f"      • {detail}")

    # Case 3: Heavily corrupted - only quantization table visible
    print("\n3. Heavily corrupted JPEG (only internal markers visible):")
    print("   Bytes: 00 00 00 00 FF DB 00 43 ...")

    heavily_corrupted = bytes.fromhex(
        "00000000FFDB004300080606070605080707070909" "080A0C140D0C0B0B0C1912130F141D1A1F1E1D1A"
    )

    result = analyzer.analyze(heavily_corrupted)
    print(f"   → Detected: {result.primary_format}")
    print(f"   → Confidence: {result.confidence:.1%}")

    if result.primary_format == "unknown":
        print("   → Note: Too corrupted for reliable detection")

    print("\n" + "=" * 70)
    print("Key Takeaways:")
    print("=" * 70)
    print("• Filo can detect files even when standard magic bytes are corrupted")
    print("• Fallback signatures scan for characteristic patterns in header region")
    print("• Confidence scores reflect the strength of evidence found")
    print("• Repair tools can then fix the corrupted headers")
    print()


def demo_repair_workflow():
    """Show the complete workflow: detect → repair."""
    print("=" * 70)
    print("Detection + Repair Workflow")
    print("=" * 70)
    print("\nNote: For a complete repair demo, see 'examples/advanced_repair_demo.py'")
    print("      or use the CLI: filo repair <file> -f jpeg")
    print("\n" + "=" * 70)


if __name__ == "__main__":
    demo_corrupted_jpeg_detection()
    print("\n")
    demo_repair_workflow()
