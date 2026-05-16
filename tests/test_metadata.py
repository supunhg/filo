"""Tests for metadata extraction module"""

import struct
from filo.metadata import (
    extract_metadata,
    JPEGMetadataExtractor,
    PNGMetadataExtractor
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


class TestComputedFields:
    """Test computed metadata fields"""
    
    def test_jpeg_computed_fields(self):
        """Test ImageSize and Megapixels computation"""
        # Create JPEG with known dimensions
        jpeg_data = bytes.fromhex(
            'FFD8'  # SOI
            'FFE000104A46494600010100000100010000'  # JFIF
            'FFC0'  # SOF0
            '0011'  # Length
            '08'  # Bits
            '0BB8'  # Height = 3000
            '0FA0'  # Width = 4000
            '03012200021101031101'  # Components
            'FFD9'  # EOI
        )
        
        extractor = JPEGMetadataExtractor()
        result = extractor.extract(jpeg_data)
        
        # Find computed fields
        image_size = next((f for f in result.fields if f.key == "ImageSize"), None)
        megapixels = next((f for f in result.fields if f.key == "Megapixels"), None)
        
        assert image_size is not None
        assert image_size.value == "4000x3000"
        assert image_size.group == "Computed"
        
        assert megapixels is not None
        assert megapixels.value == "12.0"


class TestICCProfile:
    """Test ICC profile extraction"""
    
    def test_jpeg_icc_profile_extraction(self):
        """Test ICC profile metadata extraction"""
        import struct
        
        # Create JPEG with minimal ICC profile
        jpeg_data = bytearray(b'\xFF\xD8')  # SOI
        
        # APP0 - JFIF
        jfif = b'\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
        jpeg_data.extend(jfif)
        
        # APP2 - ICC Profile
        icc_header = b'ICC_PROFILE\x00\x01\x01'
        icc_profile = bytearray(128)
        struct.pack_into('>I', icc_profile, 0, 128)  # Profile size
        icc_profile[4:8] = b'appl'  # CMM Type
        icc_profile[8:11] = b'\x02\x20\x00'  # Version 2.2.0
        icc_profile[12:16] = b'mntr'  # Display device
        icc_profile[16:20] = b'RGB '  # RGB color space
        icc_profile[20:24] = b'XYZ '  # XYZ PCS
        
        app2_data = icc_header + icc_profile
        jpeg_data.extend(b'\xFF\xE2')  # APP2 marker
        jpeg_data.extend(struct.pack('>H', len(app2_data) + 2))
        jpeg_data.extend(app2_data)
        
        # SOF0 and EOI
        jpeg_data.extend(b'\xFF\xC0\x00\x11\x08\x00\x64\x00\x64\x03\x01\x11\x00\x02\x11\x01\x03\x11\x01')
        jpeg_data.extend(b'\xFF\xD9')
        
        extractor = JPEGMetadataExtractor()
        result = extractor.extract(bytes(jpeg_data))
        
        # Check ICC fields
        icc_fields = [f for f in result.fields if f.group == "ICC_Profile"]
        assert len(icc_fields) > 0
        
        # Check specific fields
        cmm_field = next((f for f in icc_fields if f.key == "ProfileCMMType"), None)
        assert cmm_field is not None
        assert cmm_field.value == "appl"
        
        version_field = next((f for f in icc_fields if f.key == "ProfileVersion"), None)
        assert version_field is not None
        assert version_field.value == "2.2.0"


class TestEncodingProcess:
    """Test encoding process detection"""
    
    def test_baseline_dct(self):
        """Test Baseline DCT detection"""
        jpeg_data = bytes.fromhex(
            'FFD8FFE000104A46494600010100000100010000'
            'FFC00011080064006403011100021101031101'  # SOF0 = Baseline DCT
            'FFD9'
        )
        
        extractor = JPEGMetadataExtractor()
        result = extractor.extract(jpeg_data)
        
        encoding = next((f for f in result.fields if f.key == "EncodingProcess"), None)
        assert encoding is not None
        assert "Baseline DCT" in encoding.value
        assert "Huffman" in encoding.value
    
    def test_progressive_dct(self):
        """Test Progressive DCT detection"""
        jpeg_data = bytes.fromhex(
            'FFD8FFE000104A46494600010100000100010000'
            'FFC20011080064006403011100021101031101'  # SOF2 = Progressive DCT
            'FFD9'
        )
        
        extractor = JPEGMetadataExtractor()
        result = extractor.extract(jpeg_data)
        
        encoding = next((f for f in result.fields if f.key == "EncodingProcess"), None)
        assert encoding is not None
        assert "Progressive DCT" in encoding.value


class TestMIMEType:
    """Test MIME type extraction"""
    
    def test_jpeg_mime_type(self):
        """Test JPEG MIME type"""
        jpeg_data = bytes.fromhex('FFD8FFD9')  # Minimal JPEG
        
        extractor = JPEGMetadataExtractor()
        result = extractor.extract(jpeg_data)
        
        mime_field = next((f for f in result.fields if f.key == "MIMEType"), None)
        assert mime_field is not None
        assert mime_field.value == "image/jpeg"
        assert mime_field.group == "File"


class TestFixtures:
    """Test with generated fixture files"""
    
    def test_fixture_files_exist(self):
        """Ensure fixture files were generated"""
        from pathlib import Path
        
        fixtures_dir = Path(__file__).parent / "fixtures" / "metadata"
        
        assert (fixtures_dir / "minimal.jpg").exists()
        assert (fixtures_dir / "with_comment.jpg").exists()
        assert (fixtures_dir / "with_icc.jpg").exists()
        assert (fixtures_dir / "with_text.png").exists()
        assert (fixtures_dir / "with_suspicious.png").exists()
        assert (fixtures_dir / "with_time.png").exists()


class TestIPTCParsing:
    """Test IPTC metadata extraction"""
    
    def test_iptc_copyright_notice(self):
        """Test IPTC copyright notice extraction"""
        # Create minimal JPEG with IPTC copyright
        data = bytearray()
        data.extend(b'\xFF\xD8')  # SOI
        
        # APP13 marker (Photoshop)
        app13_data = bytearray()
        app13_data.extend(b'Photoshop 3.0\x00')
        app13_data.extend(b'8BIM')  # 8BIM signature
        app13_data.extend(struct.pack('>H', 0x0404))  # IPTC resource ID
        app13_data.extend(b'\x00')  # Name length (0)
        app13_data.extend(b'\x00')  # Padding
        
        # IPTC data
        iptc_data = bytearray()
        copyright_text = b'PicoCTF'
        iptc_data.append(0x1C)  # Tag marker
        iptc_data.append(2)  # Record 2 (Application)
        iptc_data.append(116)  # Dataset 116 (CopyrightNotice)
        iptc_data.extend(struct.pack('>H', len(copyright_text)))
        iptc_data.extend(copyright_text)
        
        app13_data.extend(struct.pack('>I', len(iptc_data)))
        app13_data.extend(iptc_data)
        
        data.extend(b'\xFF\xED')  # APP13
        data.extend(struct.pack('>H', len(app13_data) + 2))
        data.extend(app13_data)
        
        data.extend(b'\xFF\xD9')  # EOI
        
        extractor = JPEGMetadataExtractor()
        result = extractor.extract(bytes(data))
        
        # Check copyright notice
        copyright_fields = [f for f in result.fields if f.key == "CopyrightNotice"]
        assert len(copyright_fields) == 1
        assert copyright_fields[0].value == "PicoCTF"
        assert copyright_fields[0].group == "IPTC"


class TestXMPParsing:
    """Test XMP metadata extraction"""
    
    def test_xmp_license_base64(self):
        """Test XMP license extraction with base64 (CTF scenario)"""
        # Create minimal JPEG with XMP containing base64 license
        data = bytearray()
        data.extend(b'\xFF\xD8')  # SOI
        
        xmp_data = b'''<?xpacket begin='' id='W5M0MpCehiHzreSzNTczkc9d'?>
<x:xmpmeta xmlns:x='adobe:ns:meta/' x:xmptk='Image::ExifTool 10.80'>
<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>
 <rdf:Description rdf:about=''
  xmlns:cc='http://creativecommons.org/ns#'>
  <cc:license rdf:resource='cGljb0NURnt0aGVfbTN0YWRhdGFfMXNfbW9kaWZpZWR9'/>
 </rdf:Description>
</rdf:RDF>
</x:xmpmeta>
<?xpacket end='w'?>'''
        
        data.extend(b'\xFF\xE1')  # APP1
        data.extend(struct.pack('>H', len(xmp_data) + 2 + 29))
        data.extend(b'http://ns.adobe.com/xap/1.0/\x00')
        data.extend(xmp_data)
        
        data.extend(b'\xFF\xD9')  # EOI
        
        extractor = JPEGMetadataExtractor()
        result = extractor.extract(bytes(data))
        
        # Check XMP license
        license_fields = [f for f in result.fields if f.key == "License"]
        assert len(license_fields) == 1
        assert license_fields[0].value == "cGljb0NURnt0aGVfbTN0YWRhdGFfMXNfbW9kaWZpZWR9"
        assert license_fields[0].group == "XMP"
        
        # Should be flagged as suspicious
        assert result.has_suspicious
        assert "License" in result.suspicious_fields
    
    def test_xmp_rights(self):
        """Test XMP rights/creator extraction"""
        xmp_data = b'''<?xpacket begin='' id='W5M0MpCehiHzreSzNTczkc9d'?>
<x:xmpmeta xmlns:x='adobe:ns:meta/'>
<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>
 <rdf:Description rdf:about=''
  xmlns:dc='http://purl.org/dc/elements/1.1/'>
  <dc:rights>
   <rdf:Alt>
    <rdf:li xml:lang='x-default'>PicoCTF</rdf:li>
   </rdf:Alt>
  </dc:rights>
 </rdf:Description>
</rdf:RDF>
</x:xmpmeta>'''
        
        data = bytearray()
        data.extend(b'\xFF\xD8')  # SOI
        data.extend(b'\xFF\xE1')  # APP1
        data.extend(struct.pack('>H', len(xmp_data) + 2 + 29))
        data.extend(b'http://ns.adobe.com/xap/1.0/\x00')
        data.extend(xmp_data)
        data.extend(b'\xFF\xD9')  # EOI
        
        extractor = JPEGMetadataExtractor()
        result = extractor.extract(bytes(data))
        
        # Check rights field
        rights_fields = [f for f in result.fields if f.key == "Rights"]
        assert len(rights_fields) == 1
        assert rights_fields[0].value == "PicoCTF"
        assert rights_fields[0].group == "XMP"
