"""
Shared test fixtures
"""

import pytest
from pathlib import Path
import tempfile


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_png_data():
    """Sample PNG file data."""
    # PNG signature + minimal IHDR chunk
    return (
        bytes.fromhex(
            "89504E470D0A1A0A"  # PNG signature
            "0000000D49484452"  # IHDR chunk
            "00000010"  # Width: 16
            "00000010"  # Height: 16
            "08"  # Bit depth: 8
            "06"  # Color type: RGBA
            "00"  # Compression: deflate
            "00"  # Filter: adaptive
            "00"  # Interlace: none
        )
        + b"\x00" * 100
    )


@pytest.fixture
def sample_jpeg_data():
    """Sample JPEG file data."""
    return bytes.fromhex("FFD8FFE000104A46494600010101") + b"\x00" * 100


@pytest.fixture
def sample_pdf_data():
    """Sample PDF file data."""
    return b"%PDF-1.7\r\n%\xe2\xe3\xcf\xd3\r\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"


@pytest.fixture
def corrupted_pdf_data():
    """Corrupted PDF (missing header)."""
    return b"1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
