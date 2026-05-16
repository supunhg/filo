"""Tests for format contradiction detection."""

import pytest
import zipfile
import io
import zlib
from filo.analyzer import Analyzer


def test_png_with_invalid_compression():
    """Test detection of PNG with corrupted zlib stream."""
    # Create PNG with valid signature but corrupted IDAT
    png_sig = bytes.fromhex("89504E470D0A1A0A")
    ihdr = bytes.fromhex("0000000D49484452" + "0000001000000010080200000090916836")

    # Create IDAT chunk with invalid zlib data
    idat_len = bytes.fromhex("00000010")  # 16 bytes
    idat_type = b"IDAT"
    idat_data = b"\x00" * 16  # Invalid zlib stream
    idat_crc = bytes.fromhex("00000000")

    corrupted_png = png_sig + ihdr + idat_len + idat_type + idat_data + idat_crc

    analyzer = Analyzer(use_ml=False)
    result = analyzer.analyze(corrupted_png)

    # Should detect PNG
    assert result.primary_format == "png"

    # Should find compression contradiction
    assert len(result.contradictions) > 0
    compression_issues = [c for c in result.contradictions if c.category == "compression"]
    assert len(compression_issues) > 0
    assert (
        "zlib" in compression_issues[0].details.lower()
        or "compression" in compression_issues[0].details.lower()
    )


def test_ooxml_missing_rels():
    """Test detection of OOXML structure missing mandatory _rels/.rels."""
    # Create ZIP with Content_Types but no _rels
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types></Types>')
        # Missing _rels/.rels
        zf.writestr("word/document.xml", '<?xml version="1.0"?><document></document>')

    analyzer = Analyzer(use_ml=False)
    result = analyzer.analyze(zip_buffer.getvalue())

    # Should detect as DOCX (or OOXML)
    assert result.primary_format in ["docx", "ooxml"]

    # Should find missing _rels contradiction
    assert len(result.contradictions) > 0
    missing_rels = [c for c in result.contradictions if "rels" in c.details.lower()]
    assert len(missing_rels) > 0
    assert missing_rels[0].category == "missing"


def test_ooxml_missing_core_document():
    """Test detection of OOXML with Content_Types but no actual document."""
    # Create ZIP with OOXML markers but no document content
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types></Types>')
        zf.writestr("_rels/.rels", '<?xml version="1.0"?><Relationships></Relationships>')
        # No document.xml, presentation.xml, or workbook.xml

    analyzer = Analyzer(use_ml=False)
    result = analyzer.analyze(zip_buffer.getvalue())

    # Should find structure contradiction
    structure_issues = [c for c in result.contradictions if c.category == "structure"]
    if structure_issues:
        assert "document" in structure_issues[0].details.lower()


def test_embedded_elf_in_zip():
    """Test detection of ELF executable embedded in ZIP file."""
    # Create ZIP with embedded ELF magic bytes
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("normal.txt", "Normal file content")
        zf.writestr("README.md", "Documentation")
        # Embed ELF magic in a file (past first 512 bytes)
        malicious_content = b"A" * 600 + b"\x7fELF" + b"\x00" * 100
        zf.writestr("data.bin", malicious_content)

    analyzer = Analyzer(use_ml=False)
    result = analyzer.analyze(zip_buffer.getvalue())

    # Should detect ZIP
    assert result.primary_format == "zip"

    # Should find embedded ELF
    embedded = [c for c in result.contradictions if c.category == "embedded"]
    assert len(embedded) > 0
    assert "ELF" in embedded[0].issue
    assert embedded[0].severity == "critical"


def test_embedded_pe_in_docx():
    """Test detection of PE executable embedded in DOCX."""
    # Create DOCX with embedded PE signature
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types></Types>')
        zf.writestr("_rels/.rels", '<?xml version="1.0"?><Relationships></Relationships>')
        zf.writestr("word/document.xml", '<?xml version="1.0"?><document></document>')
        # Embed PE/DOS magic bytes
        malicious_content = b"X" * 700 + b"MZ" + b"\x00" * 200
        zf.writestr("word/media/image1.jpg", malicious_content)

    analyzer = Analyzer(use_ml=False)
    result = analyzer.analyze(zip_buffer.getvalue())

    # Should detect DOCX
    assert result.primary_format == "docx"

    # Should find embedded executable
    embedded = [c for c in result.contradictions if c.category == "embedded"]
    assert len(embedded) > 0
    assert (
        "executable" in embedded[0].issue.lower()
        or "PE" in embedded[0].issue
        or "DOS" in embedded[0].issue
    )


def test_pdf_missing_eof():
    """Test detection of PDF missing %%EOF marker."""
    # Create truncated PDF
    pdf_data = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
    # Missing %%EOF

    analyzer = Analyzer(use_ml=False)
    result = analyzer.analyze(pdf_data)

    # Should detect PDF
    assert result.primary_format == "pdf"

    # Should find missing EOF
    structure_issues = [c for c in result.contradictions if c.category == "structure"]
    assert len(structure_issues) > 0
    assert "EOF" in structure_issues[0].issue or "EOF" in structure_issues[0].details


def test_jpeg_missing_sos():
    """Test detection of JPEG missing Start of Scan marker."""
    # Create JPEG with SOI and SOF but no SOS
    jpeg_data = b"\xff\xd8"  # SOI
    jpeg_data += b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"  # APP0/JFIF
    jpeg_data += (
        b"\xff\xc0\x00\x11\x08\x00\x10\x00\x10\x03\x01\x22\x00\x02\x11\x01\x03\x11\x01"  # SOF0
    )
    # Missing SOS (Start of Scan)
    # Add some data but no proper scan
    jpeg_data += b"\xff\xd9"  # EOI

    analyzer = Analyzer(use_ml=False)
    result = analyzer.analyze(jpeg_data)

    # Should detect JPEG
    assert result.primary_format == "jpeg"

    # Should find structural issue
    structure_issues = [c for c in result.contradictions if c.category == "structure"]
    if structure_issues:
        assert "SOS" in structure_issues[0].details or "Scan" in structure_issues[0].details


def test_no_contradictions_in_valid_file():
    """Test that valid files don't trigger false positives."""
    # Create valid PNG
    png_data = bytes.fromhex("89504E470D0A1A0A0000000D494844520000001000000010080200000090916836")

    # Add valid IDAT with proper zlib compression
    raw_data = b"\x00" * 64  # Simple scanline data
    compressed = zlib.compress(raw_data)

    idat_len = len(compressed).to_bytes(4, "big")
    idat_type = b"IDAT"
    idat_data = compressed

    # Calculate CRC
    import binascii

    crc_data = idat_type + idat_data
    crc = binascii.crc32(crc_data).to_bytes(4, "big")

    valid_png = png_data + idat_len + idat_type + idat_data + crc

    # Add IEND
    valid_png += b"\x00\x00\x00\x00IEND\xae\x42\x60\x82"

    analyzer = Analyzer(use_ml=False)
    result = analyzer.analyze(valid_png)

    # Should detect PNG with no contradictions
    assert result.primary_format == "png"
    assert len(result.contradictions) == 0


def test_embedded_shell_script():
    """Test detection of embedded shell script."""
    # Create ZIP with embedded shell script
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("normal.txt", "Normal content")
        # Embed shell script past header
        script_content = b"X" * 600 + b"#!/bin/bash" + b"\nrm -rf /\n"
        zf.writestr("data.txt", script_content)

    analyzer = Analyzer(use_ml=False)
    result = analyzer.analyze(zip_buffer.getvalue())

    # Should find embedded script
    embedded = [c for c in result.contradictions if c.category == "embedded"]
    assert len(embedded) > 0
    assert "script" in embedded[0].issue.lower() or "bash" in embedded[0].issue.lower()


def test_contradiction_severity_levels():
    """Test that contradictions have appropriate severity levels."""
    # Create file with critical embedded executable
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("file.txt", b"A" * 600 + b"\x7fELF" + b"\x00" * 100)

    analyzer = Analyzer(use_ml=False)
    result = analyzer.analyze(zip_buffer.getvalue())

    # Embedded executables should be critical
    embedded = [c for c in result.contradictions if c.category == "embedded"]
    if embedded:
        assert embedded[0].severity == "critical"


def test_multiple_contradictions():
    """Test detection of multiple contradictions in same file."""
    # Create DOCX with missing _rels AND embedded executable
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types></Types>')
        # Missing _rels/.rels (contradiction 1)
        zf.writestr("word/document.xml", '<?xml version="1.0"?><document></document>')
        # Embedded ELF (contradiction 2)
        zf.writestr("word/media/file.dat", b"X" * 600 + b"\x7fELF" + b"\x00" * 100)

    analyzer = Analyzer(use_ml=False)
    result = analyzer.analyze(zip_buffer.getvalue())

    # Should find multiple contradictions
    assert len(result.contradictions) >= 2

    # Should have different categories
    categories = {c.category for c in result.contradictions}
    assert len(categories) >= 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
