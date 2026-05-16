"""Tests for container detection and analysis."""

import io
import tarfile
import zipfile

import pytest

from filo.container import ContainerDetector, analyze_archive


@pytest.fixture
def zip_data():
    """Create sample ZIP archive."""
    buffer = io.BytesIO()

    with zipfile.ZipFile(buffer, "w") as zf:
        # Add a PNG file
        png_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        zf.writestr("image.png", png_data)

        # Add a text file
        zf.writestr("readme.txt", b"Hello, World!")

        # Add subdirectory
        jpeg_data = b"\xff\xd8\xff\xe0" + b"\x00" * 100
        zf.writestr("subdir/photo.jpg", jpeg_data)

    return buffer.getvalue()


@pytest.fixture
def tar_data():
    """Create sample TAR archive."""
    buffer = io.BytesIO()

    with tarfile.open(fileobj=buffer, mode="w") as tf:
        # Add PNG file
        png_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        info = tarfile.TarInfo(name="image.png")
        info.size = len(png_data)
        tf.addfile(info, io.BytesIO(png_data))

        # Add PDF file
        pdf_data = b"%PDF-1.7\n" + b"\x00" * 100
        info = tarfile.TarInfo(name="document.pdf")
        info.size = len(pdf_data)
        tf.addfile(info, io.BytesIO(pdf_data))

    return buffer.getvalue()


def test_detect_zip(zip_data):
    """Test ZIP detection."""
    detector = ContainerDetector()

    container_type = detector.is_container(zip_data)

    assert container_type == "zip"


def test_detect_tar(tar_data):
    """Test TAR detection."""
    detector = ContainerDetector()

    container_type = detector.is_container(tar_data)

    assert container_type == "tar"


def test_detect_non_container():
    """Test non-container detection."""
    detector = ContainerDetector()

    # Plain PNG data
    png_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100

    container_type = detector.is_container(png_data)

    assert container_type is None


def test_analyze_zip_container(zip_data):
    """Test ZIP container analysis."""
    detector = ContainerDetector()

    result = detector.analyze_container(zip_data, recursive=False)

    assert result is not None
    assert result.container_format == "zip"
    assert result.total_entries == 3
    assert result.analyzed_entries == 3


def test_analyze_tar_container(tar_data):
    """Test TAR container analysis."""
    detector = ContainerDetector()

    result = detector.analyze_container(tar_data, recursive=False)

    assert result is not None
    assert result.container_format == "tar"
    assert result.total_entries == 2
    assert result.analyzed_entries == 2


def test_container_entry_formats(zip_data):
    """Test that container entries are analyzed."""
    detector = ContainerDetector()

    result = detector.analyze_container(zip_data)

    # Find the PNG entry
    png_entry = next((e for e in result.entries if "image.png" in e.path), None)

    assert png_entry is not None
    assert png_entry.result is not None
    assert png_entry.result.primary_format == "png"


def test_nested_containers():
    """Test nested container detection."""
    # Create ZIP containing a ZIP
    inner_buffer = io.BytesIO()
    with zipfile.ZipFile(inner_buffer, "w") as inner_zf:
        inner_zf.writestr("test.txt", b"Hello")

    inner_data = inner_buffer.getvalue()

    outer_buffer = io.BytesIO()
    with zipfile.ZipFile(outer_buffer, "w") as outer_zf:
        outer_zf.writestr("inner.zip", inner_data)

    outer_data = outer_buffer.getvalue()

    detector = ContainerDetector(max_depth=2)
    result = detector.analyze_container(outer_data, recursive=True)

    assert result is not None
    assert result.container_format == "zip"
    # Should have warning about nested container
    assert any("Nested" in w for w in result.warnings)


def test_analyze_archive_convenience(zip_data):
    """Test convenience function."""
    result = analyze_archive(zip_data)

    assert result is not None
    assert result.container_format == "zip"


def test_corrupted_zip():
    """Test handling of corrupted ZIP."""
    # Incomplete ZIP data
    corrupted = b"PK\x03\x04" + b"\x00" * 10

    detector = ContainerDetector()
    result = detector.analyze_container(corrupted)

    # Should still detect as ZIP but have warnings
    assert result is not None
    assert result.container_format == "zip"
    assert len(result.warnings) > 0
