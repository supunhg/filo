#!/usr/bin/env python3
"""
File Carving Demo
Demonstrates extracting embedded files from binary blobs
"""

from filo import CarverEngine, StreamCarver
from pathlib import Path


def demo_basic_carving():
    print("=== Basic File Carving ===\n")

    carver = CarverEngine()

    png = bytes.fromhex("89504E470D0A1A0A") + b"\x00" * 1000 + b"IEND\xae\x42\x60\x82"
    jpeg = bytes.fromhex("FFD8FFE000104A4649460001") + b"\x00" * 500 + b"\xff\xd9"

    junk_data = b"\xff" * 100
    combined = junk_data + png + junk_data + jpeg + junk_data

    print(f"Searching {len(combined)} bytes for embedded files...")

    carved = carver.carve_data(combined, min_size=100)

    print(f"\nFound {len(carved)} embedded files:\n")

    for i, file in enumerate(carved):
        print(f"  File {i+1}:")
        print(f"    Offset:     0x{file.offset:08x}")
        print(f"    Size:       {file.size:,} bytes")
        print(f"    Format:     {file.format.upper()}")
        print(f"    Confidence: {file.confidence:.1%}")
        print()


def demo_stream_carving():
    print("\n=== Stream Carving (Network Capture) ===\n")

    stream = StreamCarver(buffer_size=2048)

    png = bytes.fromhex("89504E470D0A1A0A") + b"\x00" * 500 + b"IEND\xae\x42\x60\x82"

    chunk1 = b"\x00" * 100 + png[:300]
    chunk2 = png[300:600]
    chunk3 = png[600:] + b"\x00" * 100

    print("Processing stream in 3 chunks...")

    result1 = stream.feed(chunk1)
    print(f"  Chunk 1 ({len(chunk1)} bytes): {len(result1)} files carved")

    result2 = stream.feed(chunk2)
    print(f"  Chunk 2 ({len(chunk2)} bytes): {len(result2)} files carved")

    result3 = stream.feed(chunk3)
    print(f"  Chunk 3 ({len(chunk3)} bytes): {len(result3)} files carved")

    final = stream.finalize()
    print(f"  Finalize: {len(final)} files carved")

    all_files = result1 + result2 + result3 + final
    print(f"\nTotal files carved from stream: {len(all_files)}")

    for file in all_files:
        print(f"  - {file.format.upper()} ({file.size:,} bytes, {file.confidence:.0%} confidence)")


def demo_file_carving():
    print("\n=== File Carving from Disk ===\n")

    import tempfile

    png1 = bytes.fromhex("89504E470D0A1A0A") + b"\x00" * 800 + b"IEND\xae\x42\x60\x82"
    png2 = bytes.fromhex("89504E470D0A1A0A") + b"\x00" * 600 + b"IEND\xae\x42\x60\x82"

    disk_image = b"\x00" * 512 + png1 + b"\xff" * 200 + png2 + b"\x00" * 512

    with tempfile.NamedTemporaryFile(delete=False, suffix=".dd") as f:
        f.write(disk_image)
        temp_path = Path(f.name)

    print(f"Created disk image: {temp_path}")
    print(f"Size: {temp_path.stat().st_size:,} bytes\n")

    carver = CarverEngine()
    carved = carver.carve_file(temp_path, min_size=500)

    print(f"Carved {len(carved)} files:")
    for i, file in enumerate(carved):
        print(f"  {i+1}. {file.format.upper()} at offset 0x{file.offset:08x} ({file.size:,} bytes)")

    temp_path.unlink()
    print(f"\nCleaned up {temp_path}")


if __name__ == "__main__":
    demo_basic_carving()
    demo_stream_carving()
    demo_file_carving()
