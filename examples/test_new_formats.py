#!/usr/bin/env python3
"""Test new file formats"""

from filo import Analyzer

analyzer = Analyzer()

# Test Office formats
docx = bytes.fromhex("504B0304") + b"\x00" * 26 + b"word" + b"\x00" * 100
xlsx = bytes.fromhex("504B0304") + b"\x00" * 26 + b"xl" + b"\x00" * 100
rtf = bytes.fromhex("7B5C727466") + b"1 test" + b"\x00" * 50

# Test media formats
mkv = bytes.fromhex("1A45DFA3") + b"\x00" * 100
avi = bytes.fromhex("52494646") + b"\x00" * 4 + b"AVI " + b"\x00" * 100
midi = bytes.fromhex("4D546864") + b"\x00" * 100

# Test executables
java_class = bytes.fromhex("CAFEBABE") + b"\x00" * 100
macho = bytes.fromhex("FEEDFACE") + b"\x00" * 100

# Test archives
tar = b"\x00" * 257 + bytes.fromhex("7573746172") + b"\x00" * 100
cab = bytes.fromhex("4D534346") + b"\x00" * 100

tests = [
    ("DOCX", docx),
    ("XLSX", xlsx),
    ("RTF", rtf),
    ("MKV", mkv),
    ("AVI", avi),
    ("MIDI", midi),
    ("Java Class", java_class),
    ("Mach-O", macho),
    ("TAR", tar),
    ("CAB", cab),
]

print("=== Testing New File Formats ===\n")
for name, data in tests:
    result = analyzer.analyze(data)
    status = "✓" if result.primary_format else "✗"
    print(
        f'{status} {name:12s} → {result.primary_format.upper() if result.primary_format else "UNKNOWN":10s} ({result.confidence:.1%})'
    )
