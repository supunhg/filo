#!/usr/bin/env python3
"""
Embedded Object Detection Demo

Demonstrates finding files hidden inside other files - malware hunter candy.

Examples:
- ZIP inside EXE (malware droppers)
- PNG appended after EOF (steganography)
- PDF with embedded executables (exploits)
- Polyglot files (valid as multiple formats)

Author: Filo Forensics Team
"""

from filo import Analyzer
from filo.embedded import EmbeddedDetector


def demo_zip_in_exe():
    """Demo: ZIP archive embedded in EXE (malware dropper pattern)."""
    print("\n" + "=" * 70)
    print("DEMO 1: ZIP Inside EXE (Malware Dropper)")
    print("=" * 70)

    # Create fake EXE with embedded ZIP
    exe_header = b"MZ" + b"\x00" * 58
    exe_header += b"\x80\x00\x00\x00"  # PE offset
    exe_padding = b"\x00" * (0x80 - len(exe_header))
    exe_sig = b"PE\x00\x00"
    exe_body = b"\x00" * 1000

    # Embedded ZIP at offset 0x500
    zip_data = b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"\x00" * 500

    malware = exe_header + exe_padding + exe_sig + exe_body + zip_data

    # Analyze
    detector = EmbeddedDetector()
    embedded = detector.detect_embedded(malware, skip_primary=True)

    print(f"\nFile size: {len(malware):,} bytes")
    print(f"Primary format: PE")
    print(f"\n🔍 Embedded Artifacts Found: {len(embedded)}")

    for obj in embedded:
        print(f"\n  • {obj.format.upper()} at offset {obj.offset:#x}")
        print(f"    Confidence: {obj.confidence:.0%}")
        if obj.size:
            print(f"    Size: {obj.size:,} bytes")
        hex_snippet = " ".join(f"{b:02x}" for b in obj.data_snippet[:8])
        print(f"    Signature: {hex_snippet}...")


def demo_polyglot():
    """Demo: File valid as multiple formats (polyglot)."""
    print("\n" + "=" * 70)
    print("DEMO 2: Polyglot Detection (Valid as Multiple Formats)")
    print("=" * 70)

    # Create polyglot: ZIP with embedded PE
    data = b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"\x00" * 200

    # Add PE signature at offset 256
    pe_header = b"MZ" + b"\x00" * 58
    pe_header += b"\x80\x00\x00\x00"

    polyglot = data + b"\x00" * (256 - len(data)) + pe_header

    # Analyze
    detector = EmbeddedDetector()
    embedded = detector.detect_embedded(polyglot, skip_primary=True, min_confidence=0.60)

    formats_found = {obj.format for obj in embedded}

    print(f"\nFile size: {len(polyglot):,} bytes")
    print(f"Primary format: ZIP")
    print(f"\n⚠ Polyglot Detected!")
    print(f"Valid as: {', '.join(formats_found)}")

    for obj in embedded:
        print(f"\n  • {obj.format.upper()} at {obj.offset:#x} ({obj.confidence:.0%})")


def demo_overlay():
    """Demo: Overlay detection (data after EOF)."""
    print("\n" + "=" * 70)
    print("DEMO 3: Overlay Detection (Data After EOF)")
    print("=" * 70)

    # Create ZIP with overlay
    zip_header = b"PK\x03\x04"
    zip_header += b"\x14\x00"  # Version
    zip_header += b"\x00\x00"  # Flags
    zip_header += b"\x00\x00"  # Compression
    zip_header += b"\x00\x00"  # Mod time
    zip_header += b"\x00\x00"  # Mod date
    zip_header += b"\x00\x00\x00\x00"  # CRC
    zip_header += b"\x00\x00\x00\x00"  # Compressed size
    zip_header += b"\x00\x00\x00\x00"  # Uncompressed size
    zip_header += b"\x04\x00"  # Filename length
    zip_header += b"\x00\x00"  # Extra field length
    zip_header += b"test"  # Filename

    # EOCD
    eocd = b"PK\x05\x06" + b"\x00" * 18

    zip_data = zip_header + eocd

    # Add overlay (hidden data after ZIP EOF)
    overlay_data = b"\x00" * 512 + b"SECRET PAYLOAD" + b"\x00" * 512

    full_file = zip_data + overlay_data

    # Detect overlay
    detector = EmbeddedDetector()
    overlay = detector.detect_overlay(full_file, "zip")

    print(f"\nFile size: {len(full_file):,} bytes")
    print(f"ZIP logical EOF: {len(zip_data)} bytes")

    if overlay:
        print(f"\n⚠ Overlay Detected!")
        print(f"  Starts at: {overlay.offset:#x}")
        print(f"  Size: {overlay.size:,} bytes")
        print(f"  Format: {overlay.format.upper()}")
    else:
        print("\n✓ No overlay detected")


def demo_full_analysis():
    """Demo: Full analysis with Analyzer class."""
    print("\n" + "=" * 70)
    print("DEMO 4: Full Analysis with Embedded Detection")
    print("=" * 70)

    # Create suspicious file with multiple embedded objects
    data = b"\x00" * 100

    # Add PNG
    data += bytes.fromhex("89504E470D0A1A0A") + b"\x00" * 100

    # Add ZIP
    data += b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"\x00" * 100

    # Add JPEG
    data += bytes.fromhex("FFD8FFE0") + b"\x00" * 100

    # Analyze
    analyzer = Analyzer()
    result = analyzer.analyze(data)

    print(f"\nPrimary Format: {result.primary_format.upper()}")
    print(f"Confidence: {result.confidence:.0%}")
    print(f"File Size: {result.file_size:,} bytes")

    if result.embedded_objects:
        print(f"\n🔍 Embedded Artifacts: {len(result.embedded_objects)}")

        for obj in result.embedded_objects:
            print(f"\n  • {obj.format.upper()} at offset {obj.offset:#x}")
            print(f"    Confidence: {obj.confidence:.0%}")
            hex_snippet = " ".join(f"{b:02x}" for b in obj.data_snippet[:8])
            print(f"    Signature: {hex_snippet}...")


def main():
    """Run all demos."""
    print("\n" + "=" * 70)
    print(" EMBEDDED OBJECT DETECTION DEMO")
    print(" Malware Hunter Candy 🍬")
    print("=" * 70)

    demo_zip_in_exe()
    demo_polyglot()
    demo_overlay()
    demo_full_analysis()

    print("\n" + "=" * 70)
    print(" All demos completed!")
    print("=" * 70)
    print("\nFor real-world usage:")
    print("  filo analyze suspicious.exe")
    print("  filo analyze --json malware.bin | jq '.embedded_objects'")
    print()


if __name__ == "__main__":
    main()
