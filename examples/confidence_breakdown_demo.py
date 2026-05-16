#!/usr/bin/env python3
"""
Confidence Breakdown Demo

This example demonstrates the new confidence decomposition feature that makes
Filo's detection decisions auditable and transparent - perfect for forensic
analysis where courts and analysts require explainable results.
"""

import io
import zipfile
from filo.analyzer import Analyzer


def demo_docx_detection():
    """Demonstrate confidence breakdown for DOCX detection."""
    print("=" * 70)
    print("Demo 1: DOCX Detection with Container Analysis")
    print("=" * 70)

    # Create a minimal DOCX structure
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>',
        )
        zf.writestr(
            "word/document.xml",
            '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"></w:document>',
        )
        zf.writestr(
            "_rels/.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>',
        )
        zf.writestr(
            "docProps/core.xml",
            '<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"></cp:coreProperties>',
        )

    analyzer = Analyzer(use_ml=False)
    result = analyzer.analyze(zip_buffer.getvalue())

    print(f"\nDetected Format: {result.primary_format.upper()}")
    print(f"Confidence: {result.confidence:.1%}\n")

    print("Confidence Breakdown:")
    print("-" * 70)

    # Display contributions for primary format
    for evidence in result.evidence_chain:
        if evidence["format"] == result.primary_format and "contributions" in evidence:
            module = evidence["module"]
            module_weight = evidence.get("weight", 1.0)

            module_names = {
                "signature_analysis": "Signature",
                "structural_analysis": "Structure",
                "zip_container_analysis": "ZIP Container",
                "ml_prediction": "ML",
            }

            print(f"\n{module_names.get(module, module)}:")

            for contrib in evidence["contributions"]:
                # Apply module weighting
                if module == "signature_analysis":
                    weighted = contrib["value"] * module_weight * 0.6
                elif module == "structural_analysis":
                    weighted = contrib["value"] * module_weight * 0.4
                elif module == "zip_container_analysis":
                    weighted = contrib["value"] * module_weight * 0.8
                else:
                    weighted = contrib["value"]

                sign = "-" if contrib.get("is_penalty", False) else "+"
                print(f"  {sign}{weighted:>5.1%}  {contrib['description']}")

    print("\n")


def demo_corrupted_jpeg():
    """Demonstrate confidence breakdown with fallback signatures."""
    print("=" * 70)
    print("Demo 2: Corrupted JPEG with Fallback Signature Detection")
    print("=" * 70)

    # Create a corrupted JPEG (magic bytes corrupted, but JFIF marker present)
    corrupted_jpeg = bytes.fromhex("5c78ffd8ffe000104a46494600") + b"\xff\xdb" + b"\x00" * 100

    analyzer = Analyzer(use_ml=False)
    result = analyzer.analyze(corrupted_jpeg)

    print(f"\nDetected Format: {result.primary_format.upper()}")
    print(f"Confidence: {result.confidence:.1%}\n")

    print("Confidence Breakdown:")
    print("-" * 70)

    # Display contributions
    for evidence in result.evidence_chain:
        if evidence["format"] == result.primary_format and "contributions" in evidence:
            module = evidence["module"]
            module_weight = evidence.get("weight", 1.0)

            module_names = {
                "signature_analysis": "Signature",
                "structural_analysis": "Structure",
                "zip_container_analysis": "ZIP Container",
                "ml_prediction": "ML",
            }

            print(f"\n{module_names.get(module, module)}:")

            for contrib in evidence["contributions"]:
                # Apply module weighting
                if module == "signature_analysis":
                    weighted = contrib["value"] * module_weight * 0.6
                elif module == "structural_analysis":
                    weighted = contrib["value"] * module_weight * 0.4
                elif module == "zip_container_analysis":
                    weighted = contrib["value"] * module_weight * 0.8
                else:
                    weighted = contrib["value"]

                sign = "-" if contrib.get("is_penalty", False) else "+"
                print(f"  {sign}{weighted:>5.1%}  {contrib['description']}")

    print("\n" + "=" * 70)
    print("Note: Fallback signatures allow detection of corrupted files!")
    print("=" * 70 + "\n")


def demo_with_penalties():
    """Demonstrate penalty tracking for incomplete files."""
    print("=" * 70)
    print("Demo 3: PNG with Missing Structure (Penalties)")
    print("=" * 70)

    # Create PNG with valid signature but incomplete structure
    png_header = bytes.fromhex("89504E470D0A1A0A")  # PNG signature
    png_ihdr_start = bytes.fromhex("0000000D49484452")  # Partial IHDR
    incomplete_png = png_header + png_ihdr_start

    analyzer = Analyzer(use_ml=False)
    result = analyzer.analyze(incomplete_png)

    print(f"\nDetected Format: {result.primary_format.upper()}")
    print(f"Confidence: {result.confidence:.1%}\n")

    print("Confidence Breakdown:")
    print("-" * 70)

    # Display contributions including penalties
    for evidence in result.evidence_chain:
        if evidence["format"] == result.primary_format and "contributions" in evidence:
            module = evidence["module"]
            module_weight = evidence.get("weight", 1.0)

            module_names = {
                "signature_analysis": "Signature",
                "structural_analysis": "Structure",
                "zip_container_analysis": "ZIP Container",
                "ml_prediction": "ML",
            }

            print(f"\n{module_names.get(module, module)}:")

            for contrib in evidence["contributions"]:
                # Apply module weighting
                if module == "signature_analysis":
                    weighted = contrib["value"] * module_weight * 0.6
                elif module == "structural_analysis":
                    weighted = contrib["value"] * module_weight * 0.4
                elif module == "zip_container_analysis":
                    weighted = contrib["value"] * module_weight * 0.8
                else:
                    weighted = contrib["value"]

                sign = "-" if contrib.get("is_penalty", False) else "+"
                color = "\033[91m" if contrib.get("is_penalty") else "\033[92m"
                reset = "\033[0m"
                print(f"  {color}{sign}{weighted:>5.1%}{reset}  {contrib['description']}")

    print("\n")


def demo_json_output():
    """Show JSON output with contributions."""
    print("=" * 70)
    print("Demo 4: JSON Output with Confidence Breakdown")
    print("=" * 70)

    # Create a simple PNG
    png_data = bytes.fromhex("89504E470D0A1A0A0000000D494844520000001000000010080200000090916836")

    analyzer = Analyzer(use_ml=False)
    result = analyzer.analyze(png_data)

    print("\nSample evidence chain entry (JSON):\n")

    # Show first evidence item with contributions
    for evidence in result.evidence_chain:
        if "contributions" in evidence and len(evidence["contributions"]) > 0:
            import json

            print(json.dumps(evidence, indent=2))
            break

    print("\nThis structure is perfect for:")
    print("  • Automated analysis pipelines")
    print("  • Court documentation")
    print("  • Research data collection")
    print("  • ML training datasets\n")


if __name__ == "__main__":
    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 15 + "FILO CONFIDENCE BREAKDOWN DEMO" + " " * 23 + "║")
    print("╚" + "=" * 68 + "╝")
    print("\nMaking detection decisions auditable and transparent\n")

    demo_docx_detection()
    demo_corrupted_jpeg()
    demo_with_penalties()
    demo_json_output()

    print("=" * 70)
    print("CLI Usage:")
    print("=" * 70)
    print("\n  filo analyze file.bin --explain")
    print("  filo analyze file.bin --explain --all-evidence")
    print("  filo analyze file.bin --json\n")
    print("See docs/CONFIDENCE_BREAKDOWN.md for full documentation\n")
