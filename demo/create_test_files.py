#!/usr/bin/env python3
"""
Generate sophisticated test files for embedded detection testing.
Creates realistic scenarios: malware droppers, polyglots, stego files.
"""

import struct
import zlib
from pathlib import Path


def create_zip_in_exe():
    """Malware dropper: ZIP archive embedded in PE executable."""
    output = Path("demo/malware_dropper.exe")

    # Minimal PE executable header
    pe_header = bytes(
        [
            0x4D,
            0x5A,  # MZ signature
            0x90,
            0x00,
            0x03,
            0x00,
            0x00,
            0x00,
            0x04,
            0x00,
            0x00,
            0x00,
            0xFF,
            0xFF,
            0x00,
            0x00,
            0xB8,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x40,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ]
        + [0x00] * 32
        + [
            0x50,
            0x45,
            0x00,
            0x00,  # PE signature at offset 64
            0x4C,
            0x01,  # Machine (i386)
            0x01,
            0x00,  # Number of sections
        ]
        + [0x00] * 200
    )

    # Create a simple ZIP file
    zip_content = bytearray()

    # Local file header
    filename = b"payload.txt"
    file_data = b"This is hidden malware payload data"
    crc = zlib.crc32(file_data)

    zip_content.extend(b"PK\x03\x04")  # Local file header signature
    zip_content.extend(struct.pack("<H", 20))  # Version needed
    zip_content.extend(struct.pack("<H", 0))  # Flags
    zip_content.extend(struct.pack("<H", 0))  # Compression method (stored)
    zip_content.extend(struct.pack("<H", 0))  # Mod time
    zip_content.extend(struct.pack("<H", 0))  # Mod date
    zip_content.extend(struct.pack("<I", crc))  # CRC-32
    zip_content.extend(struct.pack("<I", len(file_data)))  # Compressed size
    zip_content.extend(struct.pack("<I", len(file_data)))  # Uncompressed size
    zip_content.extend(struct.pack("<H", len(filename)))  # Filename length
    zip_content.extend(struct.pack("<H", 0))  # Extra field length
    zip_content.extend(filename)
    zip_content.extend(file_data)

    # Central directory header
    cd_offset = len(zip_content)
    zip_content.extend(b"PK\x01\x02")  # Central directory signature
    zip_content.extend(struct.pack("<H", 20))  # Version made by
    zip_content.extend(struct.pack("<H", 20))  # Version needed
    zip_content.extend(struct.pack("<H", 0))  # Flags
    zip_content.extend(struct.pack("<H", 0))  # Compression
    zip_content.extend(struct.pack("<H", 0))  # Mod time
    zip_content.extend(struct.pack("<H", 0))  # Mod date
    zip_content.extend(struct.pack("<I", crc))
    zip_content.extend(struct.pack("<I", len(file_data)))
    zip_content.extend(struct.pack("<I", len(file_data)))
    zip_content.extend(struct.pack("<H", len(filename)))
    zip_content.extend(struct.pack("<H", 0))  # Extra field length
    zip_content.extend(struct.pack("<H", 0))  # Comment length
    zip_content.extend(struct.pack("<H", 0))  # Disk number
    zip_content.extend(struct.pack("<H", 0))  # Internal attributes
    zip_content.extend(struct.pack("<I", 0))  # External attributes
    zip_content.extend(struct.pack("<I", 0))  # Relative offset
    zip_content.extend(filename)

    # End of central directory
    zip_content.extend(b"PK\x05\x06")  # EOCD signature
    zip_content.extend(struct.pack("<H", 0))  # Disk number
    zip_content.extend(struct.pack("<H", 0))  # CD start disk
    zip_content.extend(struct.pack("<H", 1))  # Entries on this disk
    zip_content.extend(struct.pack("<H", 1))  # Total entries
    zip_content.extend(struct.pack("<I", len(zip_content) - cd_offset))  # CD size
    zip_content.extend(struct.pack("<I", cd_offset))  # CD offset
    zip_content.extend(struct.pack("<H", 0))  # Comment length

    # Combine PE header + some padding + ZIP
    combined = pe_header + bytes([0x00] * 100) + bytes(zip_content)

    output.write_bytes(combined)
    print(f"✓ Created {output} (ZIP embedded at offset {len(pe_header) + 100:#x})")


def create_polyglot_png_zip():
    """Polyglot file: valid PNG and valid ZIP simultaneously."""
    output = Path("demo/polyglot_png_zip.png")

    # PNG header
    png_data = bytearray(
        [
            0x89,
            0x50,
            0x4E,
            0x47,
            0x0D,
            0x0A,
            0x1A,
            0x0A,  # PNG signature
        ]
    )

    # IHDR chunk (1x1 red pixel)
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    ihdr_crc = zlib.crc32(b"IHDR" + ihdr)
    png_data.extend(struct.pack(">I", len(ihdr)))
    png_data.extend(b"IHDR")
    png_data.extend(ihdr)
    png_data.extend(struct.pack(">I", ihdr_crc))

    # IDAT chunk with ZIP embedded
    idat_data = b"\x08\x1d\x01\x02\x00\xfd\xff\x00\x00\x00\x02\x00\x01"
    idat_crc = zlib.crc32(b"IDAT" + idat_data)
    png_data.extend(struct.pack(">I", len(idat_data)))
    png_data.extend(b"IDAT")
    png_data.extend(idat_data)
    png_data.extend(struct.pack(">I", idat_crc))

    # IEND chunk
    iend_crc = zlib.crc32(b"IEND")
    png_data.extend(struct.pack(">I", 0))
    png_data.extend(b"IEND")
    png_data.extend(struct.pack(">I", iend_crc))

    # Append ZIP archive after PNG
    filename = b"secret.txt"
    file_data = b"Hidden data in polyglot file!"
    crc = zlib.crc32(file_data)

    zip_offset = len(png_data)

    # Local file header
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

    # Central directory
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

    # EOCD
    png_data.extend(b"PK\x05\x06")
    png_data.extend(struct.pack("<H", 0))
    png_data.extend(struct.pack("<H", 0))
    png_data.extend(struct.pack("<H", 1))
    png_data.extend(struct.pack("<H", 1))
    png_data.extend(struct.pack("<I", len(png_data) - cd_offset - zip_offset))
    png_data.extend(struct.pack("<I", cd_offset))
    png_data.extend(struct.pack("<H", 0))

    output.write_bytes(png_data)
    print(f"✓ Created {output} (polyglot: valid PNG + ZIP at offset {zip_offset:#x})")


def create_jpeg_with_trailing_zip():
    """Steganography: JPEG with ZIP appended after EOF marker."""
    output = Path("demo/stego_jpeg_zip.jpg")

    # Minimal JPEG
    jpeg_data = bytearray(
        [
            0xFF,
            0xD8,  # SOI
            0xFF,
            0xE0,  # APP0
            0x00,
            0x10,  # Length
            0x4A,
            0x46,
            0x49,
            0x46,
            0x00,  # "JFIF\0"
            0x01,
            0x01,  # Version 1.1
            0x00,  # Density units
            0x00,
            0x01,
            0x00,
            0x01,  # X/Y density
            0x00,
            0x00,  # Thumbnail
            0xFF,
            0xDB,  # DQT
            0x00,
            0x43,  # Length
        ]
        + [0x10] * 64
        + [  # Quantization table
            0xFF,
            0xC0,  # SOF0
            0x00,
            0x0B,  # Length
            0x08,  # Precision
            0x00,
            0x01,
            0x00,
            0x01,  # Dimensions 1x1
            0x01,  # Components
            0x01,
            0x11,
            0x00,  # Component info
            0xFF,
            0xDA,  # SOS
            0x00,
            0x08,  # Length
            0x01,
            0x01,
            0x00,
            0x00,
            0x3F,
            0x00,  # Scan header
            0x00,  # Minimal scan data
            0xFF,
            0xD9,  # EOI (end of JPEG)
        ]
    )

    # Append hidden ZIP
    filename = b"evidence.txt"
    file_data = b"Forensic evidence hidden in JPEG!"
    crc = zlib.crc32(file_data)

    zip_offset = len(jpeg_data)

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

    # Central directory
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

    # EOCD
    jpeg_data.extend(b"PK\x05\x06")
    jpeg_data.extend(struct.pack("<H", 0))
    jpeg_data.extend(struct.pack("<H", 0))
    jpeg_data.extend(struct.pack("<H", 1))
    jpeg_data.extend(struct.pack("<H", 1))
    jpeg_data.extend(struct.pack("<I", len(jpeg_data) - cd_offset - zip_offset))
    jpeg_data.extend(struct.pack("<I", cd_offset))
    jpeg_data.extend(struct.pack("<H", 0))

    output.write_bytes(jpeg_data)
    print(f"✓ Created {output} (ZIP hidden after JPEG EOF at offset {zip_offset:#x})")


def create_pdf_with_embedded_exe():
    """Weaponized document: PDF with embedded PE executable."""
    output = Path("demo/weaponized_document.pdf")

    # Minimal PDF structure
    pdf_data = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
trailer
<< /Size 4 /Root 1 0 R >>
startxref
187
%%EOF
"""

    # Append PE executable
    pe_offset = len(pdf_data)
    pe_data = bytes(
        [
            0x4D,
            0x5A,  # MZ signature
            0x90,
            0x00,
            0x03,
            0x00,
            0x00,
            0x00,
            0x04,
            0x00,
            0x00,
            0x00,
            0xFF,
            0xFF,
            0x00,
            0x00,
            0xB8,
            0x00,
        ]
        + [0x00] * 48
        + [
            0x50,
            0x45,
            0x00,
            0x00,  # PE signature
            0x4C,
            0x01,
            0x01,
            0x00,  # Machine + sections
        ]
        + [0x00] * 100
    )

    combined = pdf_data + pe_data
    output.write_bytes(combined)
    print(f"✓ Created {output} (PE embedded at offset {pe_offset:#x})")


def create_zip_with_overlay():
    """ZIP archive with overlay data (post-EOCD trailer)."""
    output = Path("demo/zip_with_overlay.zip")

    filename = b"readme.txt"
    file_data = b"Normal ZIP file content"
    crc = zlib.crc32(file_data)

    zip_data = bytearray()

    # Local file header
    zip_data.extend(b"PK\x03\x04")
    zip_data.extend(struct.pack("<H", 20))
    zip_data.extend(struct.pack("<H", 0))
    zip_data.extend(struct.pack("<H", 0))
    zip_data.extend(struct.pack("<H", 0))
    zip_data.extend(struct.pack("<H", 0))
    zip_data.extend(struct.pack("<I", crc))
    zip_data.extend(struct.pack("<I", len(file_data)))
    zip_data.extend(struct.pack("<I", len(file_data)))
    zip_data.extend(struct.pack("<H", len(filename)))
    zip_data.extend(struct.pack("<H", 0))
    zip_data.extend(filename)
    zip_data.extend(file_data)

    # Central directory
    cd_offset = len(zip_data)
    zip_data.extend(b"PK\x01\x02")
    zip_data.extend(struct.pack("<H", 20))
    zip_data.extend(struct.pack("<H", 20))
    zip_data.extend(struct.pack("<H", 0))
    zip_data.extend(struct.pack("<H", 0))
    zip_data.extend(struct.pack("<H", 0))
    zip_data.extend(struct.pack("<H", 0))
    zip_data.extend(struct.pack("<I", crc))
    zip_data.extend(struct.pack("<I", len(file_data)))
    zip_data.extend(struct.pack("<I", len(file_data)))
    zip_data.extend(struct.pack("<H", len(filename)))
    zip_data.extend(struct.pack("<H", 0))
    zip_data.extend(struct.pack("<H", 0))
    zip_data.extend(struct.pack("<H", 0))
    zip_data.extend(struct.pack("<H", 0))
    zip_data.extend(struct.pack("<I", 0))
    zip_data.extend(struct.pack("<I", 0))
    zip_data.extend(filename)

    # EOCD
    zip_data.extend(b"PK\x05\x06")
    zip_data.extend(struct.pack("<H", 0))
    zip_data.extend(struct.pack("<H", 0))
    zip_data.extend(struct.pack("<H", 1))
    zip_data.extend(struct.pack("<H", 1))
    zip_data.extend(struct.pack("<I", len(zip_data) - cd_offset))
    zip_data.extend(struct.pack("<I", cd_offset))
    zip_data.extend(struct.pack("<H", 0))

    # Add overlay data after EOCD
    overlay_offset = len(zip_data)
    overlay_data = b"OVERLAY_DATA_MALICIOUS_CODE_HERE" * 10
    zip_data.extend(overlay_data)

    output.write_bytes(zip_data)
    print(f"✓ Created {output} (overlay at offset {overlay_offset:#x}, {len(overlay_data)} bytes)")


def main():
    Path("demo").mkdir(exist_ok=True)

    print("Creating sophisticated embedded detection test files...\n")

    create_zip_in_exe()
    create_polyglot_png_zip()
    create_jpeg_with_trailing_zip()
    create_pdf_with_embedded_exe()
    create_zip_with_overlay()

    print(f"\n✓ All test files created in demo/")
    print("\nTest with:")
    print("  filo analyze demo/malware_dropper.exe")
    print("  filo analyze demo/polyglot_png_zip.png")
    print("  filo analyze demo/stego_jpeg_zip.jpg -e")
    print("  filo analyze demo/weaponized_document.pdf")
    print("  filo analyze demo/zip_with_overlay.zip")


if __name__ == "__main__":
    main()
