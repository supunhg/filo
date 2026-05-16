"""
Tests for polyglot detection - files valid as multiple formats simultaneously.
"""

import struct
import zlib
from filo.polyglot import PolyglotDetector


class TestFormatValidators:
    """Test individual format validators."""

    def test_validate_png_valid(self):
        detector = PolyglotDetector()

        png_data = bytearray(
            [
                0x89,
                0x50,
                0x4E,
                0x47,
                0x0D,
                0x0A,
                0x1A,
                0x0A,
            ]
        )

        ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
        ihdr_crc = zlib.crc32(b"IHDR" + ihdr)
        png_data.extend(struct.pack(">I", len(ihdr)))
        png_data.extend(b"IHDR")
        png_data.extend(ihdr)
        png_data.extend(struct.pack(">I", ihdr_crc))

        assert detector._validate_png(bytes(png_data))

    def test_validate_png_invalid(self):
        detector = PolyglotDetector()

        invalid_data = b"Not a PNG file"
        assert not detector._validate_png(invalid_data)

    def test_validate_gif_valid(self):
        detector = PolyglotDetector()

        gif_data = b"GIF89a" + struct.pack("<HH", 100, 100) + b"\x00" * 5
        assert detector._validate_gif(gif_data)

    def test_validate_gif_invalid(self):
        detector = PolyglotDetector()

        invalid_data = b"GIF" + b"\x00" * 10
        assert not detector._validate_gif(invalid_data)

    def test_validate_jpeg_valid(self):
        detector = PolyglotDetector()

        jpeg_data = bytes(
            [
                0xFF,
                0xD8,
                0xFF,
                0xE0,
                0x00,
                0x10,
                0x4A,
                0x46,
                0x49,
                0x46,
                0x00,
                0x01,
                0x01,
                0x00,
                0x00,
                0x01,
                0x00,
                0x01,
                0x00,
                0x00,
                0xFF,
                0xDA,
                0x00,
                0x08,
                0x01,
                0x01,
                0x00,
                0x00,
                0x3F,
                0x00,
                0x00,
                0xFF,
                0xD9,
            ]
        )

        assert detector._validate_jpeg(jpeg_data)

    def test_validate_jpeg_invalid(self):
        detector = PolyglotDetector()

        invalid_data = b"\xff\xd8" + b"\x00" * 10
        assert not detector._validate_jpeg(invalid_data)

    def test_validate_zip_valid(self):
        detector = PolyglotDetector()

        zip_data = bytearray(b"PK\x03\x04")
        zip_data.extend(b"\x00" * 26)
        zip_data.extend(b"PK\x05\x06")
        zip_data.extend(b"\x00" * 18)

        assert detector._validate_zip(bytes(zip_data))

    def test_validate_zip_invalid(self):
        detector = PolyglotDetector()

        invalid_data = b"Not a ZIP file"
        assert not detector._validate_zip(invalid_data)

    def test_validate_pdf_valid(self):
        detector = PolyglotDetector()

        pdf_data = b"%PDF-1.4\n" + b"%" + b"\x00" * 100 + b"/Type" + b"\x00" * 100 + b"%%EOF\n"
        assert detector._validate_pdf(pdf_data)

    def test_validate_pdf_invalid(self):
        detector = PolyglotDetector()

        invalid_data = b"Not a PDF"
        assert not detector._validate_pdf(invalid_data)

    def test_validate_pe_valid(self):
        detector = PolyglotDetector()

        pe_data = bytearray(b"MZ")
        pe_data.extend(b"\x00" * 58)
        pe_data.extend(struct.pack("<I", 64))
        pe_data.extend(b"PE\x00\x00")

        assert detector._validate_pe(bytes(pe_data))

    def test_validate_pe_invalid(self):
        detector = PolyglotDetector()

        invalid_data = b"Not a PE file"
        assert not detector._validate_pe(invalid_data)


class TestPolyglotDetection:
    """Test polyglot file detection."""

    def test_png_zip_polyglot(self):
        detector = PolyglotDetector()

        png_data = bytearray(
            [
                0x89,
                0x50,
                0x4E,
                0x47,
                0x0D,
                0x0A,
                0x1A,
                0x0A,
            ]
        )

        ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
        ihdr_crc = zlib.crc32(b"IHDR" + ihdr)
        png_data.extend(struct.pack(">I", len(ihdr)))
        png_data.extend(b"IHDR")
        png_data.extend(ihdr)
        png_data.extend(struct.pack(">I", ihdr_crc))

        iend_crc = zlib.crc32(b"IEND")
        png_data.extend(struct.pack(">I", 0))
        png_data.extend(b"IEND")
        png_data.extend(struct.pack(">I", iend_crc))

        _zip_offset = len(png_data)
        png_data.extend(b"PK\x03\x04")
        png_data.extend(b"\x00" * 26)
        png_data.extend(b"PK\x05\x06")
        png_data.extend(b"\x00" * 18)

        polyglots = detector.detect_polyglots(bytes(png_data))

        assert len(polyglots) > 0
        assert any(p.pattern == "png_zip" for p in polyglots)

    def test_gif_jar_polyglot(self):
        detector = PolyglotDetector()

        gif_data = bytearray(b"GIF89a")
        gif_data.extend(struct.pack("<HH", 100, 100))
        gif_data.extend(b"\x00" * 50)

        gif_data.extend(b"PK\x03\x04")
        gif_data.extend(b"\x00" * 26)
        gif_data.extend(b"META-INF/MANIFEST.MF")
        gif_data.extend(b"\x00" * 50)
        gif_data.extend(b"PK\x05\x06")
        gif_data.extend(b"\x00" * 18)

        polyglots = detector.detect_polyglots(bytes(gif_data))

        assert len(polyglots) > 0
        assert any(p.pattern == "gifar" for p in polyglots)

    def test_pdf_with_javascript(self):
        detector = PolyglotDetector()

        pdf_data = b"%PDF-1.4\n"
        pdf_data += b'/JavaScript /JS eval(unescape("payload")) /OpenAction\n'
        pdf_data += b"/Type /Catalog\n"
        pdf_data += b"\x00" * 100
        pdf_data += b"%%EOF\n"

        polyglots = detector.detect_polyglots(pdf_data)

        assert len(polyglots) > 0
        pdf_js_found = any(p.pattern == "pdf_js" for p in polyglots)
        assert pdf_js_found

    def test_no_polyglot_simple_file(self):
        detector = PolyglotDetector()

        png_data = bytearray(
            [
                0x89,
                0x50,
                0x4E,
                0x47,
                0x0D,
                0x0A,
                0x1A,
                0x0A,
            ]
        )

        ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
        ihdr_crc = zlib.crc32(b"IHDR" + ihdr)
        png_data.extend(struct.pack(">I", len(ihdr)))
        png_data.extend(b"IHDR")
        png_data.extend(ihdr)
        png_data.extend(struct.pack(">I", ihdr_crc))

        polyglots = detector.detect_polyglots(bytes(png_data))

        assert len(polyglots) == 0

    def test_risk_assessment(self):
        detector = PolyglotDetector()

        assert detector._assess_risk("gifar", ["gif", "jar"]) == "high"
        assert detector._assess_risk("pdf_js", ["pdf"]) == "high"
        assert detector._assess_risk("png_zip", ["png", "zip"]) == "medium"
        assert detector._assess_risk("unknown", ["png", "jpeg"]) == "low"

    def test_confidence_calculation(self):
        detector = PolyglotDetector()

        confidence = detector._calculate_polyglot_confidence(b"test", ["png", "zip"])
        assert 0.70 <= confidence <= 1.0

    def test_pattern_descriptions(self):
        detector = PolyglotDetector()

        assert "GIFAR" in detector._get_pattern_description("gifar")
        assert "PNG + ZIP" in detector._get_pattern_description("png_zip")
        assert "JavaScript" in detector._get_pattern_description("pdf_js")


class TestJavaScriptDetection:
    """Test JavaScript payload detection in PDFs."""

    def test_pdf_with_js_indicators(self):
        detector = PolyglotDetector()

        pdf_data = b"%PDF-1.4\n/JavaScript /AA eval( unescape( String.fromCharCode\n%%EOF\n"
        assert detector._has_js_payload(pdf_data)

    def test_pdf_without_js(self):
        detector = PolyglotDetector()

        pdf_data = b"%PDF-1.4\n/Type /Catalog\n%%EOF\n"
        assert not detector._has_js_payload(pdf_data)

    def test_non_pdf_no_js(self):
        detector = PolyglotDetector()

        not_pdf = b"Not a PDF with /JavaScript"
        assert not detector._has_js_payload(not_pdf)


class TestMultipleFormats:
    """Test detection of multiple valid formats."""

    def test_three_format_polyglot(self):
        detector = PolyglotDetector()

        data = bytearray(b"%PDF-1.4\n")
        data.extend(b"/Type /Catalog\n")
        data.extend(b"%%EOF\n")
        data.extend(b"\x00" * 100)
        data.extend(b"PK\x03\x04")
        data.extend(b"\x00" * 26)
        data.extend(b"PK\x05\x06")
        data.extend(b"\x00" * 18)

        valid_formats = detector._get_valid_formats(bytes(data))

        assert "pdf" in valid_formats
        assert "zip" in valid_formats

    def test_find_other_combinations(self):
        detector = PolyglotDetector()

        valid_formats = {"png", "jpeg", "zip"}
        existing = []

        other = detector._find_other_combinations(valid_formats, existing)

        assert len(other) > 0
        assert all(p.confidence > 0.70 for p in other)


class TestIntegration:
    """Integration tests with Analyzer."""

    def test_analyzer_detects_polyglot(self):
        from filo import Analyzer

        png_zip_data = bytearray(
            [
                0x89,
                0x50,
                0x4E,
                0x47,
                0x0D,
                0x0A,
                0x1A,
                0x0A,
            ]
        )

        ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
        ihdr_crc = zlib.crc32(b"IHDR" + ihdr)
        png_zip_data.extend(struct.pack(">I", len(ihdr)))
        png_zip_data.extend(b"IHDR")
        png_zip_data.extend(ihdr)
        png_zip_data.extend(struct.pack(">I", ihdr_crc))

        iend_crc = zlib.crc32(b"IEND")
        png_zip_data.extend(struct.pack(">I", 0))
        png_zip_data.extend(b"IEND")
        png_zip_data.extend(struct.pack(">I", iend_crc))

        png_zip_data.extend(b"PK\x03\x04")
        png_zip_data.extend(b"\x00" * 26)
        png_zip_data.extend(b"PK\x05\x06")
        png_zip_data.extend(b"\x00" * 18)

        analyzer = Analyzer(detect_polyglots=True)
        result = analyzer.analyze(bytes(png_zip_data))

        assert len(result.polyglots) > 0

    def test_analyzer_no_polyglot_normal_file(self):
        from filo import Analyzer

        normal_data = bytearray(
            [
                0x89,
                0x50,
                0x4E,
                0x47,
                0x0D,
                0x0A,
                0x1A,
                0x0A,
            ]
        )

        ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
        ihdr_crc = zlib.crc32(b"IHDR" + ihdr)
        normal_data.extend(struct.pack(">I", len(ihdr)))
        normal_data.extend(b"IHDR")
        normal_data.extend(ihdr)
        normal_data.extend(struct.pack(">I", ihdr_crc))

        analyzer = Analyzer(detect_polyglots=True)
        result = analyzer.analyze(bytes(normal_data))

        assert len(result.polyglots) == 0
