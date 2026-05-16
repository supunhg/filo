"""Tests for advanced repair strategies."""

import struct
import zlib

import pytest

from filo.repair import RepairEngine


@pytest.fixture
def repair_engine():
    """Create repair engine fixture."""
    return RepairEngine()


class TestPNGRepair:
    """Tests for PNG repair strategies."""
    
    def test_repair_png_chunks_valid(self, repair_engine):
        """Test PNG chunk repair with valid file."""
        # Create valid PNG with IHDR and IEND
        png = b"\x89PNG\r\n\x1a\n"
        
        # IHDR chunk
        ihdr_data = struct.pack(">II", 100, 100)  # 100x100
        ihdr_data += b"\x08\x02\x00\x00\x00"
        ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data) & 0xffffffff
        png += struct.pack(">I", 13)  # Length
        png += b"IHDR" + ihdr_data
        png += struct.pack(">I", ihdr_crc)
        
        # IEND chunk
        iend_crc = zlib.crc32(b"IEND") & 0xffffffff
        png += struct.pack(">I", 0)  # Length
        png += b"IEND"
        png += struct.pack(">I", iend_crc)
        
        repaired, report = repair_engine._repair_png_chunks(png)
        
        assert report.success is False  # No repairs needed
        assert "No repairs needed" in report.warnings
    
    def test_repair_png_chunks_bad_crc(self, repair_engine):
        """Test PNG chunk repair with corrupted CRC."""
        # Create PNG with bad CRC
        png = b"\x89PNG\r\n\x1a\n"
        
        # IHDR chunk with wrong CRC
        ihdr_data = struct.pack(">II", 100, 100)
        ihdr_data += b"\x08\x02\x00\x00\x00"
        png += struct.pack(">I", 13)
        png += b"IHDR" + ihdr_data
        png += struct.pack(">I", 0xDEADBEEF)  # Wrong CRC
        
        # IEND chunk
        iend_crc = zlib.crc32(b"IEND") & 0xffffffff
        png += struct.pack(">I", 0)
        png += b"IEND"
        png += struct.pack(">I", iend_crc)
        
        repaired, report = repair_engine._repair_png_chunks(png)
        
        assert report.success is True
        assert report.chunks_repaired == 1
        assert "Fixed CRC for IHDR chunk" in report.changes_made
        assert repaired != png
    
    def test_reconstruct_png_ihdr(self, repair_engine):
        """Test PNG IHDR reconstruction."""
        # PNG without IHDR
        png = b"\x89PNG\r\n\x1a\n"
        png += b"\x00\x00\x00\x00IDAT"  # Some IDAT data
        
        repaired, report = repair_engine._reconstruct_png_ihdr(png)
        
        assert report.success is True
        assert "Reconstructed IHDR chunk" in report.changes_made[0]
        assert repaired.startswith(b"\x89PNG\r\n\x1a\n")
        assert b"IHDR" in repaired
    
    def test_reconstruct_png_ihdr_no_signature(self, repair_engine):
        """Test PNG IHDR reconstruction when signature is missing."""
        png = b"\x00\x00\x00\x00IDAT"  # No PNG signature
        
        repaired, report = repair_engine._reconstruct_png_ihdr(png)
        
        assert report.success is True
        assert repaired.startswith(b"\x89PNG\r\n\x1a\n")
        assert b"IHDR" in repaired


class TestJPEGRepair:
    """Tests for JPEG repair strategies."""
    
    def test_repair_jpeg_markers_valid(self, repair_engine):
        """Test JPEG marker repair with valid file."""
        jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        jpeg += b"\xff\xd9"  # EOI marker
        
        repaired, report = repair_engine._repair_jpeg_markers(jpeg)
        
        assert report.success is False
        assert "No repairs needed" in report.warnings
    
    def test_repair_jpeg_markers_no_soi(self, repair_engine):
        """Test JPEG marker repair without SOI."""
        jpeg = b"\x00\x00\x00\x00\xff\xd9"  # No SOI
        
        repaired, report = repair_engine._repair_jpeg_markers(jpeg)
        
        assert report.success is True
        assert "Added JPEG SOI and JFIF markers" in report.changes_made
        assert repaired.startswith(b"\xff\xd8")
    
    def test_repair_jpeg_markers_no_eoi(self, repair_engine):
        """Test JPEG marker repair without EOI."""
        jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        
        repaired, report = repair_engine._repair_jpeg_markers(jpeg)
        
        assert report.success is True
        assert "Added JPEG EOI marker" in report.changes_made
        assert repaired.endswith(b"\xff\xd9")
    
    def test_add_jpeg_eoi(self, repair_engine):
        """Test adding JPEG EOI marker."""
        jpeg = b"\xff\xd8\x00\x00\x00\x00"
        
        repaired, report = repair_engine._add_jpeg_eoi(jpeg)
        
        assert report.success is True
        assert repaired == jpeg + b"\xff\xd9"
        assert report.confidence == 0.95
    
    def test_add_jpeg_eoi_already_present(self, repair_engine):
        """Test adding EOI when already present."""
        jpeg = b"\xff\xd8\x00\x00\xff\xd9"
        
        repaired, report = repair_engine._add_jpeg_eoi(jpeg)
        
        assert report.success is False
        assert "EOI marker already present" in report.warnings


class TestZIPRepair:
    """Tests for ZIP repair strategies."""
    
    def test_repair_zip_directory_valid(self, repair_engine):
        """Test ZIP directory repair with valid file."""
        zip_data = b"PK\x03\x04" + b"\x00" * 26  # Local file header
        zip_data += b"PK\x05\x06" + b"\x00" * 18  # EOCD
        
        repaired, report = repair_engine._repair_zip_directory(zip_data)
        
        assert report.success is False
        assert "Central directory appears intact" in report.warnings
    
    def test_repair_zip_directory_missing_eocd(self, repair_engine):
        """Test ZIP directory repair without EOCD."""
        zip_data = b"PK\x03\x04" + b"\x00" * 26
        
        repaired, report = repair_engine._repair_zip_directory(zip_data)
        
        assert report.success is True
        assert "Reconstructed End of Central Directory" in report.changes_made
        assert b"PK\x05\x06" in repaired
    
    def test_reconstruct_zip_headers(self, repair_engine):
        """Test ZIP header reconstruction."""
        zip_data = b"\x00\x00\x00\x00"  # No ZIP signature
        
        repaired, report = repair_engine._reconstruct_zip_headers(zip_data)
        
        assert report.success is True
        assert repaired.startswith(b"PK\x03\x04")
        assert "Added ZIP local file header" in report.changes_made
    
    def test_reconstruct_zip_headers_already_present(self, repair_engine):
        """Test ZIP header reconstruction when already present."""
        zip_data = b"PK\x03\x04\x00\x00"
        
        repaired, report = repair_engine._reconstruct_zip_headers(zip_data)
        
        assert report.success is False
        assert "ZIP header already present" in report.warnings


class TestPDFRepair:
    """Tests for PDF repair strategies."""
    
    def test_repair_pdf_xref_valid(self, repair_engine):
        """Test PDF xref repair with valid file."""
        pdf = b"%PDF-1.4\nxref\n0 1\ntrailer\n%%EOF"
        
        repaired, report = repair_engine._repair_pdf_xref(pdf)
        
        assert report.success is False
        assert "xref table appears present" in report.warnings
    
    def test_repair_pdf_xref_missing(self, repair_engine):
        """Test PDF xref repair without xref table."""
        pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        
        repaired, report = repair_engine._repair_pdf_xref(pdf)
        
        assert report.success is True
        assert "Added minimal cross-reference table" in report.changes_made
        assert b"xref" in repaired
        assert b"%%EOF" in repaired
    
    def test_add_pdf_eof(self, repair_engine):
        """Test adding PDF EOF marker."""
        pdf = b"%PDF-1.4\nxref\ntrailer"
        
        repaired, report = repair_engine._add_pdf_eof(pdf)
        
        assert report.success is True
        assert repaired.endswith(b"%%EOF")
        assert report.confidence == 0.9
    
    def test_add_pdf_eof_already_present(self, repair_engine):
        """Test adding EOF when already present."""
        pdf = b"%PDF-1.4\n%%EOF"
        
        repaired, report = repair_engine._add_pdf_eof(pdf)
        
        assert report.success is False
        assert "EOF marker already present" in report.warnings


class TestAdvancedRepairIntegration:
    """Integration tests for advanced repair strategies."""
    
    def test_repair_corrupted_png(self, repair_engine):
        """Test repairing a corrupted PNG through main repair method."""
        # Create PNG with bad CRC
        png = b"\x89PNG\r\n\x1a\n"
        ihdr_data = struct.pack(">II", 100, 100) + b"\x08\x02\x00\x00\x00"
        png += struct.pack(">I", 13) + b"IHDR" + ihdr_data
        png += struct.pack(">I", 0xBADBAD)  # Bad CRC
        
        repaired, report = repair_engine.repair(png, "png")
        
        assert report.success is True
        assert repaired != png
    
    def test_repair_truncated_jpeg(self, repair_engine):
        """Test repairing a truncated JPEG."""
        jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        # Missing EOI
        
        repaired, report = repair_engine.repair(jpeg, "jpeg")
        
        assert report.success is True
        assert repaired.endswith(b"\xff\xd9")
    
    def test_repair_broken_zip(self, repair_engine):
        """Test repairing a broken ZIP file."""
        zip_data = b"PK\x03\x04" + b"\x00" * 26
        # Missing central directory
        
        repaired, report = repair_engine.repair(zip_data, "zip")
        
        assert report.success is True
        assert b"PK\x05\x06" in repaired
    
    def test_repair_incomplete_pdf(self, repair_engine):
        """Test repairing an incomplete PDF."""
        pdf = b"%PDF-1.4\n1 0 obj\n<</Type/Catalog>>\nendobj\n"
        
        repaired, report = repair_engine.repair(pdf, "pdf")
        
        assert report.success is True
        assert b"%%EOF" in repaired
