"""Tests for batch processing functionality."""

import pytest

from filo.batch import BatchProcessor, BatchConfig, analyze_directory


@pytest.fixture
def test_files(temp_dir):
    """Create test files for batch processing."""
    # Create some test files
    files = []

    # PNG file
    png_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
    png_file = temp_dir / "test.png"
    png_file.write_bytes(png_data)
    files.append(png_file)

    # JPEG file
    jpeg_data = b"\xff\xd8\xff\xe0" + b"\x00" * 100
    jpeg_file = temp_dir / "test.jpg"
    jpeg_file.write_bytes(jpeg_data)
    files.append(jpeg_file)

    # PDF file
    pdf_data = b"%PDF-1.7\n" + b"\x00" * 100
    pdf_file = temp_dir / "test.pdf"
    pdf_file.write_bytes(pdf_data)
    files.append(pdf_file)

    # Subdirectory with file
    subdir = temp_dir / "subdir"
    subdir.mkdir()
    zip_data = b"PK\x03\x04" + b"\x00" * 100
    zip_file = subdir / "test.zip"
    zip_file.write_bytes(zip_data)
    files.append(zip_file)

    return temp_dir, files


def test_batch_processor_initialization():
    """Test batch processor initialization."""
    processor = BatchProcessor()

    assert processor.config.max_workers == 4
    assert processor.config.recursive is True


def test_batch_process_directory(test_files):
    """Test processing a directory."""
    temp_dir, files = test_files

    config = BatchConfig(max_workers=2, recursive=True)
    processor = BatchProcessor(config)

    result = processor.process_directory(temp_dir)

    assert result.total_files == 4
    assert result.analyzed_files == 4
    assert result.failed_files == 0
    assert len(result.results) == 4
    assert result.duration > 0
    assert result.files_per_second > 0


def test_batch_non_recursive(test_files):
    """Test non-recursive batch processing."""
    temp_dir, files = test_files

    config = BatchConfig(recursive=False)
    processor = BatchProcessor(config)

    result = processor.process_directory(temp_dir)

    # Should only get files in root directory (3 files, not the one in subdir)
    assert result.total_files == 3
    assert result.analyzed_files == 3


def test_batch_file_size_filter(test_files):
    """Test file size filtering."""
    temp_dir, files = test_files

    # Set very small max size
    config = BatchConfig(max_file_size=50)
    processor = BatchProcessor(config)

    result = processor.process_directory(temp_dir)

    # All files should be skipped (they're all >50 bytes)
    assert result.analyzed_files == 0


def test_batch_exclude_patterns(test_files):
    """Test exclude patterns."""
    temp_dir, files = test_files

    config = BatchConfig(exclude_patterns=["*.png", "*.jpg"])
    processor = BatchProcessor(config)

    result = processor.process_directory(temp_dir)

    # Should only analyze pdf and zip
    assert result.analyzed_files == 2


def test_batch_include_patterns(test_files):
    """Test include patterns."""
    temp_dir, files = test_files

    config = BatchConfig(include_patterns=["*.png"])
    processor = BatchProcessor(config)

    result = processor.process_directory(temp_dir)

    # Should only analyze png
    assert result.analyzed_files == 1


def test_analyze_directory_convenience(test_files):
    """Test convenience function."""
    temp_dir, files = test_files

    result = analyze_directory(temp_dir, max_workers=2)

    assert result.total_files == 4
    assert result.analyzed_files == 4


def test_progress_callback(test_files):
    """Test progress callback."""
    temp_dir, files = test_files

    progress_updates = []

    def callback(completed, total):
        progress_updates.append((completed, total))

    config = BatchConfig(progress_callback=callback)
    processor = BatchProcessor(config)

    processor.process_directory(temp_dir)

    # Should have progress updates
    assert len(progress_updates) == 4
    assert progress_updates[-1] == (4, 4)
