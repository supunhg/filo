#!/usr/bin/env python3
"""
Comprehensive Feature Test - Demonstrate All Filo Capabilities

Tests all major features in sequence with clear output.
"""

import subprocess
import sys
from pathlib import Path


def run_cmd(cmd: str, description: str) -> None:
    """Run command and display results."""
    print(f"\n{'='*70}")
    print(f"TEST: {description}")
    print(f"{'='*70}")
    print(f"$ {cmd}\n")

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    print(result.stdout)
    if result.stderr and "ResourceWarning" not in result.stderr:
        print(f"[stderr]: {result.stderr}")

    if result.returncode != 0:
        print(f"\n⚠ Command failed with exit code {result.returncode}")

    return result.returncode == 0


def main():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║  Filo v0.2.5 - Comprehensive Feature Test Suite                 ║
║  Testing all major capabilities in realistic scenarios          ║
╚══════════════════════════════════════════════════════════════════╝
""")

    results = []

    # Test 1: Create demo files
    print("\n📁 Step 1: Creating sophisticated test files...")
    results.append(
        run_cmd(
            "python demo/create_test_files.py",
            "Generate malware dropper, polyglots, steganography files",
        )
    )

    # Test 2: Basic analysis
    results.append(
        run_cmd(
            "filo analyze demo/polyglot_png_zip.png",
            "Basic analysis - polyglot file (valid PNG + ZIP)",
        )
    )

    # Test 3: Embedded detection with -e flag
    results.append(
        run_cmd(
            "filo analyze demo/malware_dropper.exe -e",
            "Embedded detection - ZIP hidden in PE executable",
        )
    )

    # Test 4: Tool fingerprinting
    results.append(
        run_cmd(
            "filo analyze demo/zip_with_overlay.zip",
            "Tool fingerprinting - identify creator tool/OS",
        )
    )

    # Test 5: Steganography detection
    results.append(
        run_cmd(
            "filo analyze demo/stego_jpeg_zip.jpg -e",
            "Steganography - ZIP hidden after JPEG EOF marker",
        )
    )

    # Test 6: Weaponized document
    results.append(
        run_cmd(
            "filo analyze demo/weaponized_document.pdf -e",
            "Weaponized document - PDF with embedded PE",
        )
    )

    # Test 7: Full transparency mode
    results.append(
        run_cmd(
            "filo analyze demo/polyglot_png_zip.png --explain -a -e",
            "Full transparency - explain + all evidence + all embedded",
        )
    )

    # Test 8: JSON output
    results.append(
        run_cmd(
            "filo analyze demo/malware_dropper.exe --json | head -30",
            "JSON output for automation/scripting",
        )
    )

    # Test 9: ML teaching
    results.append(
        run_cmd("filo teach demo/zip_with_overlay.zip -f zip", "ML teaching - train on ZIP file")
    )

    # Test 10: Lineage stats
    results.append(run_cmd("filo lineage-stats", "Lineage statistics - chain-of-custody tracking"))

    # Test 11: Batch processing
    results.append(
        run_cmd("filo batch demo/ --max-workers 2", "Batch processing - analyze all demo files")
    )

    # Summary
    print(f"\n{'='*70}")
    print("SUMMARY")
    print(f"{'='*70}")

    passed = sum(results)
    total = len(results)

    print(f"\n✓ Passed: {passed}/{total}")
    print(f"✗ Failed: {total - passed}/{total}")

    if passed == total:
        print("\n🎉 All tests passed! Filo is working perfectly.")
        return 0
    else:
        print("\n⚠ Some tests failed. Check output above for details.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
