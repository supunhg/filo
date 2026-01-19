#!/usr/bin/env python3
"""
Generate test JPEG and PNG files with various metadata for testing.
Creates files in tests/fixtures/metadata/
"""

import struct
import zlib
from pathlib import Path

# Create fixtures directory
fixtures_dir = Path(__file__).parent.parent / "tests" / "fixtures" / "metadata"
fixtures_dir.mkdir(parents=True, exist_ok=True)

print(f"Creating test files in {fixtures_dir}")


def create_minimal_jpeg():
    """Create minimal JPEG with JFIF header"""
    jpeg_data = bytearray()
    
    # SOI marker
    jpeg_data.extend(b'\xFF\xD8')
    
    # APP0 - JFIF
    jfif_data = (
        b'JFIF\x00'  # Identifier
        b'\x01\x01'  # Version 1.01
        b'\x00'  # Density units: none
        b'\x00\x01'  # X density = 1
        b'\x00\x01'  # Y density = 1
        b'\x00\x00'  # Thumbnail size 0x0
    )
    jpeg_data.extend(b'\xFF\xE0')  # APP0 marker
    jpeg_data.extend(struct.pack('>H', len(jfif_data) + 2))
    jpeg_data.extend(jfif_data)
    
    # SOF0 - Start of Frame (Baseline DCT)
    sof_data = bytearray()
    sof_data.append(8)  # Bits per sample
    sof_data.extend(struct.pack('>H', 100))  # Height
    sof_data.extend(struct.pack('>H', 100))  # Width
    sof_data.append(3)  # Components
    # Y component
    sof_data.extend(b'\x01\x22\x00')
    # Cb component
    sof_data.extend(b'\x02\x11\x01')
    # Cr component
    sof_data.extend(b'\x03\x11\x01')
    
    jpeg_data.extend(b'\xFF\xC0')  # SOF0 marker
    jpeg_data.extend(struct.pack('>H', len(sof_data) + 2))
    jpeg_data.extend(sof_data)
    
    # EOI marker
    jpeg_data.extend(b'\xFF\xD9')
    
    output_file = fixtures_dir / "minimal.jpg"
    with open(output_file, 'wb') as f:
        f.write(jpeg_data)
    print(f"  ✓ Created {output_file.name}")


def create_jpeg_with_comment():
    """Create JPEG with suspicious base64 comment"""
    jpeg_data = bytearray()
    
    # SOI
    jpeg_data.extend(b'\xFF\xD8')
    
    # APP0 - JFIF
    jfif_data = b'JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
    jpeg_data.extend(b'\xFF\xE0')
    jpeg_data.extend(struct.pack('>H', len(jfif_data) + 2))
    jpeg_data.extend(jfif_data)
    
    # COM - Comment with base64
    comment_text = b"steghide:cEF6endvcmQ="  # base64 for "pAzzword"
    jpeg_data.extend(b'\xFF\xFE')  # COM marker
    jpeg_data.extend(struct.pack('>H', len(comment_text) + 2))
    jpeg_data.extend(comment_text)
    
    # SOF0
    sof_data = b'\x08\x00\x64\x00\x64\x03\x01\x11\x00\x02\x11\x01\x03\x11\x01'
    jpeg_data.extend(b'\xFF\xC0')
    jpeg_data.extend(struct.pack('>H', len(sof_data) + 2))
    jpeg_data.extend(sof_data)
    
    # EOI
    jpeg_data.extend(b'\xFF\xD9')
    
    output_file = fixtures_dir / "with_comment.jpg"
    with open(output_file, 'wb') as f:
        f.write(jpeg_data)
    print(f"  ✓ Created {output_file.name} (suspicious comment)")


def create_jpeg_with_icc_profile():
    """Create JPEG with ICC profile"""
    jpeg_data = bytearray()
    
    # SOI
    jpeg_data.extend(b'\xFF\xD8')
    
    # APP0 - JFIF
    jfif_data = b'JFIF\x00\x01\x01\x01\x00\x48\x00\x48\x00\x00'  # 72 DPI
    jpeg_data.extend(b'\xFF\xE0')
    jpeg_data.extend(struct.pack('>H', len(jfif_data) + 2))
    jpeg_data.extend(jfif_data)
    
    # APP2 - ICC Profile (minimal)
    icc_data = bytearray()
    icc_data.extend(b'ICC_PROFILE\x00')  # Identifier
    icc_data.append(1)  # Sequence number
    icc_data.append(1)  # Total sequences
    
    # Minimal ICC profile header
    icc_profile = bytearray(128)
    # Profile size (bytes 0-3)
    struct.pack_into('>I', icc_profile, 0, 128)
    # CMM Type (bytes 4-7)
    icc_profile[4:8] = b'Lino'
    # Profile version (bytes 8-11)
    icc_profile[8:11] = b'\x02\x10\x00'
    # Profile class (bytes 12-15)
    icc_profile[12:16] = b'mntr'
    # Color space (bytes 16-19)
    icc_profile[16:20] = b'RGB '
    # PCS (bytes 20-23)
    icc_profile[20:24] = b'XYZ '
    
    icc_data.extend(icc_profile)
    
    jpeg_data.extend(b'\xFF\xE2')  # APP2 marker
    jpeg_data.extend(struct.pack('>H', len(icc_data) + 2))
    jpeg_data.extend(icc_data)
    
    # SOF0
    sof_data = b'\x08\x00\xC8\x00\xC8\x03\x01\x22\x00\x02\x11\x01\x03\x11\x01'  # 200x200
    jpeg_data.extend(b'\xFF\xC0')
    jpeg_data.extend(struct.pack('>H', len(sof_data) + 2))
    jpeg_data.extend(sof_data)
    
    # EOI
    jpeg_data.extend(b'\xFF\xD9')
    
    output_file = fixtures_dir / "with_icc.jpg"
    with open(output_file, 'wb') as f:
        f.write(jpeg_data)
    print(f"  ✓ Created {output_file.name} (ICC profile)")


def create_png_with_text():
    """Create PNG with tEXt chunk"""
    png_data = bytearray()
    
    # PNG signature
    png_data.extend(b'\x89PNG\r\n\x1a\n')
    
    # IHDR chunk
    ihdr_data = struct.pack('>IIBBBBB', 150, 150, 8, 6, 0, 0, 0)  # 150x150 RGBA
    png_data.extend(struct.pack('>I', len(ihdr_data)))
    png_data.extend(b'IHDR')
    png_data.extend(ihdr_data)
    png_data.extend(struct.pack('>I', zlib.crc32(b'IHDR' + ihdr_data)))
    
    # tEXt chunk with normal comment
    text_data = b'Comment\x00Created by Filo test suite'
    png_data.extend(struct.pack('>I', len(text_data)))
    png_data.extend(b'tEXt')
    png_data.extend(text_data)
    png_data.extend(struct.pack('>I', zlib.crc32(b'tEXt' + text_data)))
    
    # IEND chunk
    png_data.extend(b'\x00\x00\x00\x00IEND\xAE\x42\x60\x82')
    
    output_file = fixtures_dir / "with_text.png"
    with open(output_file, 'wb') as f:
        f.write(png_data)
    print(f"  ✓ Created {output_file.name}")


def create_png_with_suspicious_text():
    """Create PNG with suspicious base64 in zTXt"""
    png_data = bytearray()
    
    # PNG signature
    png_data.extend(b'\x89PNG\r\n\x1a\n')
    
    # IHDR chunk
    ihdr_data = struct.pack('>IIBBBBB', 100, 100, 8, 2, 0, 0, 0)  # 100x100 RGB
    png_data.extend(struct.pack('>I', len(ihdr_data)))
    png_data.extend(b'IHDR')
    png_data.extend(ihdr_data)
    png_data.extend(struct.pack('>I', zlib.crc32(b'IHDR' + ihdr_data)))
    
    # zTXt chunk with compressed suspicious data
    keyword = b'Password'
    compressed_text = zlib.compress(b'c3RlZ2hpZGU6SGlkZGVuUGFzcw==')
    ztxt_data = keyword + b'\x00\x00' + compressed_text
    
    png_data.extend(struct.pack('>I', len(ztxt_data)))
    png_data.extend(b'zTXt')
    png_data.extend(ztxt_data)
    png_data.extend(struct.pack('>I', zlib.crc32(b'zTXt' + ztxt_data)))
    
    # IEND chunk
    png_data.extend(b'\x00\x00\x00\x00IEND\xAE\x42\x60\x82')
    
    output_file = fixtures_dir / "with_suspicious.png"
    with open(output_file, 'wb') as f:
        f.write(png_data)
    print(f"  ✓ Created {output_file.name} (suspicious data)")


def create_png_with_time():
    """Create PNG with tIME chunk"""
    png_data = bytearray()
    
    # PNG signature
    png_data.extend(b'\x89PNG\r\n\x1a\n')
    
    # IHDR chunk
    ihdr_data = struct.pack('>IIBBBBB', 80, 80, 8, 0, 0, 0, 0)  # 80x80 grayscale
    png_data.extend(struct.pack('>I', len(ihdr_data)))
    png_data.extend(b'IHDR')
    png_data.extend(ihdr_data)
    png_data.extend(struct.pack('>I', zlib.crc32(b'IHDR' + ihdr_data)))
    
    # tIME chunk - 2024-01-15 14:30:45
    time_data = struct.pack('>H', 2024) + bytes([1, 15, 14, 30, 45])
    png_data.extend(struct.pack('>I', len(time_data)))
    png_data.extend(b'tIME')
    png_data.extend(time_data)
    png_data.extend(struct.pack('>I', zlib.crc32(b'tIME' + time_data)))
    
    # IEND chunk
    png_data.extend(b'\x00\x00\x00\x00IEND\xAE\x42\x60\x82')
    
    output_file = fixtures_dir / "with_time.png"
    with open(output_file, 'wb') as f:
        f.write(png_data)
    print(f"  ✓ Created {output_file.name}")


# Generate all test files
print("\n🔧 Generating test image files...\n")
create_minimal_jpeg()
create_jpeg_with_comment()
create_jpeg_with_icc_profile()
create_png_with_text()
create_png_with_suspicious_text()
create_png_with_time()

print(f"\n✅ Created 6 test files in {fixtures_dir}")
print("\nTest these with:")
print(f"  filo meta {fixtures_dir}/*.jpg")
print(f"  filo meta {fixtures_dir}/*.png -s")
