#!/usr/bin/env python3
"""Generate polyglot test files for format detection."""

import struct
import zlib
from pathlib import Path


def create_gifar():
    """Create GIFAR (GIF + JAR) polyglot."""
    output = Path("demo/gifar_malware.gif")

    gif_data = bytearray(b"GIF89a")
    gif_data.extend(struct.pack("<HH", 100, 100))
    gif_data.extend(b"\x00")
    gif_data.extend(b"\x00" * 50)
    gif_data.extend(b";")

    jar_offset = len(gif_data)

    manifest = b"Manifest-Version: 1.0\nMain-Class: Malware\n\n"
    crc = zlib.crc32(manifest)

    gif_data.extend(b"PK\x03\x04")
    gif_data.extend(struct.pack("<H", 20))
    gif_data.extend(struct.pack("<H", 0))
    gif_data.extend(struct.pack("<H", 0))
    gif_data.extend(struct.pack("<H", 0))
    gif_data.extend(struct.pack("<H", 0))
    gif_data.extend(struct.pack("<I", crc))
    gif_data.extend(struct.pack("<I", len(manifest)))
    gif_data.extend(struct.pack("<I", len(manifest)))
    gif_data.extend(struct.pack("<H", 20))
    gif_data.extend(struct.pack("<H", 0))
    gif_data.extend(b"META-INF/MANIFEST.MF")
    gif_data.extend(manifest)

    cd_offset = len(gif_data) - jar_offset
    gif_data.extend(b"PK\x01\x02")
    gif_data.extend(struct.pack("<H", 20))
    gif_data.extend(struct.pack("<H", 20))
    gif_data.extend(struct.pack("<H", 0))
    gif_data.extend(struct.pack("<H", 0))
    gif_data.extend(struct.pack("<H", 0))
    gif_data.extend(struct.pack("<H", 0))
    gif_data.extend(struct.pack("<I", crc))
    gif_data.extend(struct.pack("<I", len(manifest)))
    gif_data.extend(struct.pack("<I", len(manifest)))
    gif_data.extend(struct.pack("<H", 20))
    gif_data.extend(struct.pack("<H", 0))
    gif_data.extend(struct.pack("<H", 0))
    gif_data.extend(struct.pack("<H", 0))
    gif_data.extend(struct.pack("<H", 0))
    gif_data.extend(struct.pack("<I", 0))
    gif_data.extend(struct.pack("<I", 0))
    gif_data.extend(b"META-INF/MANIFEST.MF")

    gif_data.extend(b"PK\x05\x06")
    gif_data.extend(struct.pack("<H", 0))
    gif_data.extend(struct.pack("<H", 0))
    gif_data.extend(struct.pack("<H", 1))
    gif_data.extend(struct.pack("<H", 1))
    gif_data.extend(struct.pack("<I", len(gif_data) - cd_offset - jar_offset))
    gif_data.extend(struct.pack("<I", cd_offset))
    gif_data.extend(struct.pack("<H", 0))

    output.write_bytes(gif_data)
    print(f"✓ Created {output} (GIFAR: valid GIF + JAR, JAR at offset {jar_offset:#x})")


def create_png_zip_polyglot():
    """Create PNG+ZIP polyglot - valid as both formats."""
    output = Path("demo/polyglot_advanced.png")

    png_data = bytearray(
        [
            0x89,
            0x50,
            0x4E,
            0x47,
            0x0D,
            0x0A,
            0x1A,
            0x0A,
        ]
    )

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    ihdr_crc = zlib.crc32(b"IHDR" + ihdr)
    png_data.extend(struct.pack(">I", len(ihdr)))
    png_data.extend(b"IHDR")
    png_data.extend(ihdr)
    png_data.extend(struct.pack(">I", ihdr_crc))

    idat_data = b"\x08\x1d\x01\x02\x00\xfd\xff\x00\x00\x00\x02\x00\x01"
    idat_crc = zlib.crc32(b"IDAT" + idat_data)
    png_data.extend(struct.pack(">I", len(idat_data)))
    png_data.extend(b"IDAT")
    png_data.extend(idat_data)
    png_data.extend(struct.pack(">I", idat_crc))

    iend_crc = zlib.crc32(b"IEND")
    png_data.extend(struct.pack(">I", 0))
    png_data.extend(b"IEND")
    png_data.extend(struct.pack(">I", iend_crc))

    zip_offset = len(png_data)

    filename = b"payload.txt"
    file_data = b"Polyglot payload data"
    crc = zlib.crc32(file_data)

    png_data.extend(b"PK\x03\x04")
    png_data.extend(struct.pack("<H", 20))
    png_data.extend(struct.pack("<H", 0))
    png_data.extend(struct.pack("<H", 0))
    png_data.extend(struct.pack("<H", 0))
    png_data.extend(struct.pack("<H", 0))
    png_data.extend(struct.pack("<I", crc))
    png_data.extend(struct.pack("<I", len(file_data)))
    png_data.extend(struct.pack("<I", len(file_data)))
    png_data.extend(struct.pack("<H", len(filename)))
    png_data.extend(struct.pack("<H", 0))
    png_data.extend(filename)
    png_data.extend(file_data)

    cd_offset = len(png_data) - zip_offset
    png_data.extend(b"PK\x01\x02")
    png_data.extend(struct.pack("<H", 20))
    png_data.extend(struct.pack("<H", 20))
    png_data.extend(struct.pack("<H", 0))
    png_data.extend(struct.pack("<H", 0))
    png_data.extend(struct.pack("<H", 0))
    png_data.extend(struct.pack("<H", 0))
    png_data.extend(struct.pack("<I", crc))
    png_data.extend(struct.pack("<I", len(file_data)))
    png_data.extend(struct.pack("<I", len(file_data)))
    png_data.extend(struct.pack("<H", len(filename)))
    png_data.extend(struct.pack("<H", 0))
    png_data.extend(struct.pack("<H", 0))
    png_data.extend(struct.pack("<H", 0))
    png_data.extend(struct.pack("<H", 0))
    png_data.extend(struct.pack("<I", 0))
    png_data.extend(struct.pack("<I", 0))
    png_data.extend(filename)

    png_data.extend(b"PK\x05\x06")
    png_data.extend(struct.pack("<H", 0))
    png_data.extend(struct.pack("<H", 0))
    png_data.extend(struct.pack("<H", 1))
    png_data.extend(struct.pack("<H", 1))
    png_data.extend(struct.pack("<I", len(png_data) - cd_offset - zip_offset))
    png_data.extend(struct.pack("<I", cd_offset))
    png_data.extend(struct.pack("<H", 0))

    output.write_bytes(png_data)
    print(f"✓ Created {output} (PNG+ZIP polyglot: valid as both PNG and ZIP)")


def create_pdf_with_javascript():
    """Create PDF with embedded JavaScript payload."""
    output = Path("demo/malicious_document.pdf")

    pdf_data = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [4 0 R] /Count 1 >>
endobj
3 0 obj
<< /S /JavaScript /JS (
  var payload = unescape("%75%6E%65%73%63%61%70%65");
  eval(String.fromCharCode(97,108,101,114,116));
) >>
endobj
4 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]
   /AA << /O 5 0 R >> >>
endobj
5 0 obj
<< /S /JavaScript /JS (app.alert('Payload executed');) >>
endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000074 00000 n 
0000000133 00000 n 
0000000290 00000 n 
0000000385 00000 n 
trailer
<< /Size 6 /Root 1 0 R >>
startxref
458
%%EOF
"""

    output.write_bytes(pdf_data)
    print(f"✓ Created {output} (PDF with JavaScript payload - HIGH RISK)")


def create_jpeg_zip_polyglot():
    """Create JPEG+ZIP polyglot."""
    output = Path("demo/image_with_archive.jpg")

    jpeg_data = bytearray(
        [
            0xFF,
            0xD8,  # SOI
            0xFF,
            0xE0,
            0x00,
            0x10,  # APP0 marker, length 16
            0x4A,
            0x46,
            0x49,
            0x46,
            0x00,  # "JFIF\0"
            0x01,
            0x01,
            0x00,
            0x00,
            0x01,
            0x00,
            0x01,
            0x00,
            0x00,
            0xFF,
            0xDB,
            0x00,
            0x42,  # DQT marker, length 66 (64 data + 2 for length)
        ]
        + [0x10] * 64
        + [
            0xFF,
            0xC0,
            0x00,
            0x0B,  # SOF marker
            0x08,
            0x00,
            0x01,
            0x00,
            0x01,
            0x01,
            0x01,
            0x11,
            0x00,
            0xFF,
            0xDA,
            0x00,
            0x08,  # SOS marker, length 8
            0x01,
            0x01,
            0x00,
            0x00,
            0x3F,
            0x00,
            0x00,  # minimal scan data
            0xFF,
            0xD9,  # EOI
        ]
    )

    zip_offset = len(jpeg_data)

    filename = b"hidden.txt"
    file_data = b"Hidden archive in JPEG"
    crc = zlib.crc32(file_data)

    jpeg_data.extend(b"PK\x03\x04")
    jpeg_data.extend(struct.pack("<H", 20))
    jpeg_data.extend(struct.pack("<H", 0))
    jpeg_data.extend(struct.pack("<H", 0))
    jpeg_data.extend(struct.pack("<H", 0))
    jpeg_data.extend(struct.pack("<H", 0))
    jpeg_data.extend(struct.pack("<I", crc))
    jpeg_data.extend(struct.pack("<I", len(file_data)))
    jpeg_data.extend(struct.pack("<I", len(file_data)))
    jpeg_data.extend(struct.pack("<H", len(filename)))
    jpeg_data.extend(struct.pack("<H", 0))
    jpeg_data.extend(filename)
    jpeg_data.extend(file_data)

    cd_offset = len(jpeg_data) - zip_offset
    jpeg_data.extend(b"PK\x01\x02")
    jpeg_data.extend(struct.pack("<H", 20))
    jpeg_data.extend(struct.pack("<H", 20))
    jpeg_data.extend(struct.pack("<H", 0))
    jpeg_data.extend(struct.pack("<H", 0))
    jpeg_data.extend(struct.pack("<H", 0))
    jpeg_data.extend(struct.pack("<H", 0))
    jpeg_data.extend(struct.pack("<I", crc))
    jpeg_data.extend(struct.pack("<I", len(file_data)))
    jpeg_data.extend(struct.pack("<I", len(file_data)))
    jpeg_data.extend(struct.pack("<H", len(filename)))
    jpeg_data.extend(struct.pack("<H", 0))
    jpeg_data.extend(struct.pack("<H", 0))
    jpeg_data.extend(struct.pack("<H", 0))
    jpeg_data.extend(struct.pack("<H", 0))
    jpeg_data.extend(struct.pack("<I", 0))
    jpeg_data.extend(struct.pack("<I", 0))
    jpeg_data.extend(filename)

    jpeg_data.extend(b"PK\x05\x06")
    jpeg_data.extend(struct.pack("<H", 0))
    jpeg_data.extend(struct.pack("<H", 0))
    jpeg_data.extend(struct.pack("<H", 1))
    jpeg_data.extend(struct.pack("<H", 1))
    jpeg_data.extend(struct.pack("<I", len(jpeg_data) - cd_offset - zip_offset))
    jpeg_data.extend(struct.pack("<I", cd_offset))
    jpeg_data.extend(struct.pack("<H", 0))

    output.write_bytes(jpeg_data)
    print(f"✓ Created {output} (JPEG+ZIP polyglot at offset {zip_offset:#x})")


def create_pe_zip_polyglot():
    """Create PE+ZIP polyglot."""
    output = Path("demo/executable_archive.exe")

    pe_data = bytearray(b"MZ")
    pe_data.extend(b"\x90" + b"\x00" * 57)
    pe_data.extend(struct.pack("<I", 64))
    pe_data.extend(b"PE\x00\x00")
    pe_data.extend(b"\x4c\x01\x01\x00")
    pe_data.extend(b"\x00" * 200)

    zip_offset = len(pe_data)

    filename = b"data.bin"
    file_data = b"Executable with embedded archive"
    crc = zlib.crc32(file_data)

    pe_data.extend(b"PK\x03\x04")
    pe_data.extend(struct.pack("<H", 20))
    pe_data.extend(struct.pack("<H", 0))
    pe_data.extend(struct.pack("<H", 0))
    pe_data.extend(struct.pack("<H", 0))
    pe_data.extend(struct.pack("<H", 0))
    pe_data.extend(struct.pack("<I", crc))
    pe_data.extend(struct.pack("<I", len(file_data)))
    pe_data.extend(struct.pack("<I", len(file_data)))
    pe_data.extend(struct.pack("<H", len(filename)))
    pe_data.extend(struct.pack("<H", 0))
    pe_data.extend(filename)
    pe_data.extend(file_data)

    cd_offset = len(pe_data) - zip_offset
    pe_data.extend(b"PK\x01\x02")
    pe_data.extend(struct.pack("<H", 20))
    pe_data.extend(struct.pack("<H", 20))
    pe_data.extend(struct.pack("<H", 0))
    pe_data.extend(struct.pack("<H", 0))
    pe_data.extend(struct.pack("<H", 0))
    pe_data.extend(struct.pack("<H", 0))
    pe_data.extend(struct.pack("<I", crc))
    pe_data.extend(struct.pack("<I", len(file_data)))
    pe_data.extend(struct.pack("<I", len(file_data)))
    pe_data.extend(struct.pack("<H", len(filename)))
    pe_data.extend(struct.pack("<H", 0))
    pe_data.extend(struct.pack("<H", 0))
    pe_data.extend(struct.pack("<H", 0))
    pe_data.extend(struct.pack("<H", 0))
    pe_data.extend(struct.pack("<I", 0))
    pe_data.extend(struct.pack("<I", 0))
    pe_data.extend(filename)

    pe_data.extend(b"PK\x05\x06")
    pe_data.extend(struct.pack("<H", 0))
    pe_data.extend(struct.pack("<H", 0))
    pe_data.extend(struct.pack("<H", 1))
    pe_data.extend(struct.pack("<H", 1))
    pe_data.extend(struct.pack("<I", len(pe_data) - cd_offset - zip_offset))
    pe_data.extend(struct.pack("<I", cd_offset))
    pe_data.extend(struct.pack("<H", 0))

    output.write_bytes(pe_data)
    print(f"✓ Created {output} (PE+ZIP polyglot - HIGH RISK)")


def main():
    Path("demo").mkdir(exist_ok=True)

    print("Creating sophisticated polyglot files...\n")

    create_gifar()
    create_png_zip_polyglot()
    create_pdf_with_javascript()
    create_jpeg_zip_polyglot()
    create_pe_zip_polyglot()

    print(f"\n✓ All polyglot files created in demo/")
    print("\n⚠ WARNING: These files demonstrate advanced evasion techniques")
    print("Test with:")
    print("  filo analyze demo/gifar_malware.gif")
    print("  filo analyze demo/polyglot_advanced.png")
    print("  filo analyze demo/malicious_document.pdf")
    print("  filo analyze demo/image_with_archive.jpg")
    print("  filo analyze demo/executable_archive.exe")


if __name__ == "__main__":
    main()
