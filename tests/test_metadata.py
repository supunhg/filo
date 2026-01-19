"""Tests for metadata extraction module"""

import pytest
from filo.metadata import (
    extract_metadata,
    JPEGMetadataExtractor,
    PNGMetadataExtractor,
    MetadataResult,
    MetadataField
)


class TestJPEGMetadataExtractor:
    """Test JPEG metadata extraction"""
    
    def test_jpeg_basic_structure(self):
        """Test basic JPEG structure extraction"""
        # Minimal JPEG: SOI + JFIF APP0 + SOF0 + SOS + EOI
        jpeg_data = bytes.fromhex(
            'FFD8'  # SOI
            'FFE0'  # APP0 marker
            '0010'  # Length = 16
            '4A46494600'  # 'JFIF\0'
            '0101'  # Version 1.01
            '00'  # Density units: none
            '0001'  # X density = 1
            '0001'  # Y density = 1
            '0000'  # Thumbnail size = 0x0
            'FFC0'  # SOF0 marker
            '0011'  # Length = 17
            '08'  # Bits per sample = 8
            '0280'  # Height = 640
            '0280'  # Width = 640
            '03'  # Components = 3
            '011100'  # Component 1
            '021101'  # Component 2
            '031101'  # Component 3
            'FFD9'  # EOI
        )
        
        extractor = JPEGMetadataExtractor()
        result = extractor.extract(jpeg_data)
        
        assert result.format == "JPEG"
        assert len(result.fields) > 0
        
        # Check for basic fields
        field_keys = [f.key for f in result.fields]
        assert "FileType" in field_keys
        assert "ImageWidth" in field_keys
        assert "ImageHeight" in field_keys
        
        # Check values
        width_field = next(f for f in result.fields if f.key == "ImageWidth")
        assert width_field.value == 640
        
        height_field = next(f for f in result.fields if f.key == "ImageHeight")
        assert height_field.value == 640
    
    def test_jpeg_comment_extraction(self):
        """Test JPEG comment marker extraction"""
        # JPEG with comment marker
        jpeg_data = bytes.fromhex(
            'FFD8'  # SOI
            'FFFE'  # COM marker
            '000D'  # Length = 13 (includes length field itself, which is 2 bytes, plus 11 bytes of data)
            '48656C6C6F20574F524C44'  # 'Hello WORLD' (11 bytes)
            'FFD9'  # EOI
        )
        
        extractor = JPEGMetadataExtractor()
        result = extractor.extract(jpeg_data)
        
        # Find comment field
        comment_fields = [f for f in result.fields if f.key == "Comment"]
        assert len(comment_fields) == 1
        assert comment_fields[0].value == "Hello WORLD"
        assert comment_fields[0].group == "JPEG"
    
    def test_jpeg_suspicious_base64_comment(self):
        """Test detection of suspicious base64 in comment"""
        # JPEG with base64-encoded steghide password in comment
        # This mimics the picoCTF challenge
        comment_text = b"c3RlZ2hpZGU6Y0VGNmVuZHZjbVE="  # "steghide:cEF6endvcmQ=" in base64
        
        jpeg_data = (
            b'\xFF\xD8'  # SOI
            b'\xFF\xFE'  # COM marker
            + (len(comment_text) + 2).to_bytes(2, 'big')  # Length
            + comment_text
            + b'\xFF\xD9'  # EOI
        )
        
        extractor = JPEGMetadataExtractor()
        result = extractor.extract(jpeg_data)
        
        # Should detect suspicious content
        assert result.has_suspicious is True
        assert "Comment" in result.suspicious_fields
        
        # Find comment field
        comment_field = next(f for f in result.fields if f.key == "Comment")
        assert comment_field.value == comment_text.decode('utf-8')
    
    def test_jpeg_jfif_metadata(self):
        """Test JFIF metadata extraction"""
        jpeg_data = bytes.fromhex(
            'FFD8'  # SOI
            'FFE0'  # APP0 marker
            '0010'  # Length = 16
            '4A46494600'  # 'JFIF\0'
            '0102'  # Version 1.02
            '01'  # Density units: pixels/inch
            '0048'  # X density = 72
            '0048'  # Y density = 72
            '0000'  # Thumbnail size = 0x0
            'FFD9'  # EOI
        )
        
        extractor = JPEGMetadataExtractor()
        result = extractor.extract(jpeg_data)
        
        # Find JFIF fields
        jfif_fields = [f for f in result.fields if f.group == "JFIF"]
        assert len(jfif_fields) > 0
        
        # Check version
        version_field = next(f for f in jfif_fields if f.key == "JFIFVersion")
        assert version_field.value == "1.02"
        
        # Check resolution
        xres_field = next(f for f in jfif_fields if f.key == "XResolution")
        assert xres_field.value == 72


class TestPNGMetadataExtractor:
    """Test PNG metadata extraction"""
    
    def test_png_basic_structure(self):
        """Test PNG IHDR extraction"""
        png_data = bytes.fromhex(
            '89504E470D0A1A0A'  # PNG signature
            '0000000D'  # IHDR length = 13
            '49484452'  # 'IHDR'
            '00000280'  # Width = 640
            '00000280'  # Height = 640
            '08'  # Bit depth = 8
            '06'  # Color type = 6 (RGBA)
            '000000'  # Compression, filter, interlace
            '00000000'  # CRC (dummy)
            '00000000'  # IEND length = 0
            '49454E44'  # 'IEND'
            'AE426082'  # IEND CRC
        )
        
        extractor = PNGMetadataExtractor()
        result = extractor.extract(png_data)
        
        assert result.format == "PNG"
        
        # Check for basic fields
        field_keys = [f.key for f in result.fields]
        assert "ImageWidth" in field_keys
        assert "ImageHeight" in field_keys
        assert "BitDepth" in field_keys
        assert "ColorType" in field_keys
        
        # Check values
        width_field = next(f for f in result.fields if f.key == "ImageWidth")
        assert width_field.value == 640
    
    def test_png_text_chunk(self):
        """Test PNG tEXt chunk extraction"""
        # Create PNG with tEXt chunk
        text_data = b'Comment\x00Hidden message here'
        
        png_data = (
            b'\x89PNG\r\n\x1a\n'  # PNG signature
            + len(text_data).to_bytes(4, 'big')  # Chunk length
            + b'tEXt'  # Chunk type
            + text_data
            + b'\x00\x00\x00\x00'  # CRC (dummy)
            + b'\x00\x00\x00\x00'  # IEND length
            + b'IEND'
            + b'\xAE\x42\x60\x82'  # IEND CRC
        )
        
        extractor = PNGMetadataExtractor()
        result = extractor.extract(png_data)
        
        # Find text fields
        text_fields = [f for f in result.fields if f.group == "PNG_Text"]
        assert len(text_fields) == 1
        assert text_fields[0].key == "Comment"
        assert text_fields[0].value == "Hidden message here"
    
    def test_png_suspicious_text(self):
        """Test detection of suspicious base64 in PNG text chunks"""
        # PNG with suspicious base64 in tEXt
        text_data = b'Password\x00c3RlZ2hpZGU6Y0VGNmVuZHZjbVE='
        
        png_data = (
            b'\x89PNG\r\n\x1a\n'  # PNG signature
            + len(text_data).to_bytes(4, 'big')
            + b'tEXt'
            + text_data
            + b'\x00\x00\x00\x00'  # CRC
            + b'\x00\x00\x00\x00'  # IEND length
            + b'IEND'
            + b'\xAE\x42\x60\x82'
        )
        
        extractor = PNGMetadataExtractor()
        result = extractor.extract(png_data)
        
        # Should detect suspicious content
        assert result.has_suspicious is True
        assert "Password" in result.suspicious_fields
    
    def test_png_time_chunk(self):
        """Test PNG tIME chunk extraction"""
        import struct
        
        time_data = (
            struct.pack('>H', 2024)  # Year = 2024
            + bytes([1, 15, 14, 30, 45])  # Jan 15, 14:30:45
        )
        
        png_data = (
            b'\x89PNG\r\n\x1a\n'
            + len(time_data).to_bytes(4, 'big')
            + b'tIME'
            + time_data
            + b'\x00\x00\x00\x00'  # CRC
            + b'\x00\x00\x00\x00'  # IEND length
            + b'IEND'
            + b'\xAE\x42\x60\x82'
        )
        
        extractor = PNGMetadataExtractor()
        result = extractor.extract(png_data)
        
        # Find time field
        time_fields = [f for f in result.fields if f.key == "ModificationTime"]
        assert len(time_fields) == 1
        assert "2024-01-15" in time_fields[0].value


class TestExtractMetadata:
    """Test the main extract_metadata function"""
    
    def test_auto_detect_jpeg(self):
        """Test auto-detection of JPEG format"""
        jpeg_data = bytes.fromhex('FFD8FFE000104A46494600FFD9')
        
        result = extract_metadata(jpeg_data)
        assert result.format == "JPEG"
    
    def test_auto_detect_png(self):
        """Test auto-detection of PNG format"""
        png_data = bytes.fromhex('89504E470D0A1A0A0000000049454E44AE426082')
        
        result = extract_metadata(png_data)
        assert result.format == "PNG"
    
    def test_unsupported_format(self):
        """Test handling of unsupported formats"""
        # Random data
        data = b'\x00\x01\x02\x03'
        
        result = extract_metadata(data)
        assert result.format == "unknown"
        assert len(result.warnings) > 0
    
    def test_format_hint_jpeg(self):
        """Test explicit format hint"""
        jpeg_data = bytes.fromhex('FFD8FFD9')
        
        result = extract_metadata(jpeg_data, format_hint='jpeg')
        assert result.format == "JPEG"
    
    def test_format_hint_png(self):
        """Test explicit format hint for PNG"""
        png_data = bytes.fromhex('89504E470D0A1A0A0000000049454E44AE426082')
        
        result = extract_metadata(png_data, format_hint='png')
        assert result.format == "PNG"


class TestSuspiciousDetection:
    """Test suspicious content detection patterns"""
    
    def test_base64_detection(self):
        """Test base64 pattern detection"""
        extractor = JPEGMetadataExtractor()
        
        # Should detect
        assert extractor._is_suspicious("c3RlZ2hpZGU6Y0VGNmVuZHZjbVE=")
        assert extractor._is_suspicious("VGhpcyBpcyBhIGxvbmcgYmFzZTY0IHN0cmluZw==")
        
        # Should not detect (too short)
        assert not extractor._is_suspicious("short")
        assert not extractor._is_suspicious("")
    
    def test_steghide_detection(self):
        """Test steghide keyword detection"""
        extractor = JPEGMetadataExtractor()
        
        assert extractor._is_suspicious("steghide:password")
        assert extractor._is_suspicious("STEGHIDE embedded data")
        assert not extractor._is_suspicious("regular comment")
    
    def test_encoding_prefix_detection(self):
        """Test detection of encoding prefixes"""
        extractor = JPEGMetadataExtractor()
        
        assert extractor._is_suspicious("data:image/png;base64,iVBORw0KGgo=")
        assert extractor._is_suspicious("base64:SGVsbG8=")
        assert extractor._is_suspicious("encrypted:aGlkZGVu")
        assert not extractor._is_suspicious("normal text")
