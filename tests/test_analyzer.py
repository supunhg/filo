"""
Tests for Analyzer
"""

from filo.analyzer import Analyzer, StatisticalAnalyzer


def test_analyzer_initialization():
    """Test analyzer initializes properly."""
    analyzer = Analyzer()
    assert analyzer.database.count() > 0


def test_analyze_png():
    """Test PNG file detection."""
    analyzer = Analyzer()

    # PNG signature
    png_data = bytes.fromhex("89504E470D0A1A0A0000000D49484452")
    png_data += b"\x00" * 100  # Add some data

    result = analyzer.analyze(png_data)

    assert result.primary_format == "png"
    assert result.confidence > 0.5
    assert result.file_size == len(png_data)
    assert result.checksum_sha256 is not None


def test_analyze_jpeg():
    """Test JPEG file detection."""
    analyzer = Analyzer()

    # JPEG JFIF signature with proper header structure
    # FFD8FFE0 (SOI + APP0) + size + JFIF marker + version + some data
    jpeg_data = bytes.fromhex("FFD8FFE000104A4649460001010000010001000000") + b"\x00" * 100

    result = analyzer.analyze(jpeg_data)

    assert result.primary_format == "jpeg"
    assert result.confidence > 0.4  # Lowered threshold for partial signature match


def test_analyze_pdf():
    """Test PDF file detection."""
    analyzer = Analyzer()

    # PDF header
    pdf_data = b"%PDF-1.7\r\n" + b"\x00" * 100

    result = analyzer.analyze(pdf_data)

    assert result.primary_format == "pdf"
    assert result.confidence > 0.5


def test_analyze_unknown():
    """Test unknown file detection."""
    # Test without ML to check signature-only behavior
    analyzer = Analyzer(use_ml=False)

    # Random data
    unknown_data = b"\x00\x11\x22\x33\x44\x55" * 20

    result = analyzer.analyze(unknown_data)

    # Should be unknown with low confidence when ML is disabled
    assert result.primary_format == "unknown"
    assert result.confidence == 0.0


def test_statistical_entropy():
    """Test entropy calculation."""
    # Random data should have high entropy
    import random

    random_data = bytes([random.randint(0, 255) for _ in range(1000)])
    entropy_random = StatisticalAnalyzer.calculate_entropy(random_data)
    assert entropy_random > 7.0  # Close to 8.0

    # Uniform data should have low entropy
    uniform_data = b"\x00" * 1000
    entropy_uniform = StatisticalAnalyzer.calculate_entropy(uniform_data)
    assert entropy_uniform == 0.0


def test_evidence_chain():
    """Test that evidence chain is populated."""
    analyzer = Analyzer()

    png_data = bytes.fromhex("89504E470D0A1A0A0000000D49484452") + b"\x00" * 100
    result = analyzer.analyze(png_data)

    assert len(result.evidence_chain) > 0
    assert result.evidence_chain[0]["module"] == "signature_analysis"


def test_analyze_corrupted_jpeg():
    """Test detection of JPEG with corrupted header but JFIF marker present."""
    analyzer = Analyzer()

    # Corrupted JPEG: missing SOI marker but has JFIF marker and quantization table
    # Simulates a file like \x78\xff\xe0\x00\x10JFIF...
    corrupted_jpeg = bytes.fromhex(
        "5c78ffe000104a46494600010101000100010000"
        "ffdb004300080606070605080707070909080a0c140d0c0b0b0c"
    )

    result = analyzer.analyze(corrupted_jpeg)

    # Should detect as JPEG with moderate confidence using fallback signatures
    assert result.primary_format == "jpeg"
    assert result.confidence > 0.25
    assert any("JFIF marker (fallback)" in str(ev) for ev in result.evidence_chain)


def test_analyze_office_formats():
    """Test detection of Office Open XML formats (DOCX, PPTX, XLSX)."""
    import zipfile
    import io

    analyzer = Analyzer()

    # Test DOCX
    docx_buffer = io.BytesIO()
    with zipfile.ZipFile(docx_buffer, "w") as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types></Types>')
        zf.writestr("word/document.xml", '<?xml version="1.0"?><document></document>')

    result = analyzer.analyze(docx_buffer.getvalue())
    assert result.primary_format == "docx"
    assert result.confidence > 0.9

    # Test PPTX
    pptx_buffer = io.BytesIO()
    with zipfile.ZipFile(pptx_buffer, "w") as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types></Types>')
        zf.writestr("ppt/presentation.xml", '<?xml version="1.0"?><presentation></presentation>')

    result = analyzer.analyze(pptx_buffer.getvalue())
    assert result.primary_format == "pptx"
    assert result.confidence > 0.9

    # Test XLSX
    xlsx_buffer = io.BytesIO()
    with zipfile.ZipFile(xlsx_buffer, "w") as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types></Types>')
        zf.writestr("xl/workbook.xml", '<?xml version="1.0"?><workbook></workbook>')

    result = analyzer.analyze(xlsx_buffer.getvalue())
    assert result.primary_format == "xlsx"
    assert result.confidence > 0.9


def test_analyze_opendocument_formats():
    """Test detection of OpenDocument formats (ODT, ODP, ODS)."""
    import zipfile
    import io

    analyzer = Analyzer()

    # Test ODT
    odt_buffer = io.BytesIO()
    with zipfile.ZipFile(odt_buffer, "w") as zf:
        zf.writestr("mimetype", "application/vnd.oasis.opendocument.text")
        zf.writestr("content.xml", '<?xml version="1.0"?><document></document>')

    result = analyzer.analyze(odt_buffer.getvalue())
    assert result.primary_format == "odt"
    assert result.confidence > 0.9

    # Test ODP
    odp_buffer = io.BytesIO()
    with zipfile.ZipFile(odp_buffer, "w") as zf:
        zf.writestr("mimetype", "application/vnd.oasis.opendocument.presentation")
        zf.writestr("content.xml", '<?xml version="1.0"?><presentation></presentation>')

    result = analyzer.analyze(odp_buffer.getvalue())
    assert result.primary_format == "odp"
    assert result.confidence > 0.9

    # Test ODS
    ods_buffer = io.BytesIO()
    with zipfile.ZipFile(ods_buffer, "w") as zf:
        zf.writestr("mimetype", "application/vnd.oasis.opendocument.spreadsheet")
        zf.writestr("content.xml", '<?xml version="1.0"?><spreadsheet></spreadsheet>')

    result = analyzer.analyze(ods_buffer.getvalue())
    assert result.primary_format == "ods"
    assert result.confidence > 0.9


class TestEntropyViz:
    def test_chunk_entropy_empty(self):
        from filo.analyzer import StatisticalAnalyzer

        assert StatisticalAnalyzer.chunk_entropy(b"") == []

    def test_chunk_entropy_uniform(self):
        from filo.analyzer import StatisticalAnalyzer

        data = b"\x00" * 1024
        entropies = StatisticalAnalyzer.chunk_entropy(data)
        assert len(entropies) == 4
        for e in entropies:
            assert e == 0.0

    def test_chunk_entropy_random(self):
        from filo.analyzer import StatisticalAnalyzer

        data = bytes(range(256)) * 4
        entropies = StatisticalAnalyzer.chunk_entropy(data)
        assert len(entropies) == 4
        for e in entropies:
            assert e > 7.0

    def test_chunk_entropy_mixed(self):
        from filo.analyzer import StatisticalAnalyzer

        nulls = b"\x00" * 512
        random_data = bytes(range(256)) * 2
        data = nulls + random_data
        entropies = StatisticalAnalyzer.chunk_entropy(data)
        assert len(entropies) == 4
        assert entropies[0] == 0.0
        assert entropies[1] == 0.0
        assert entropies[2] > 7.0
        assert entropies[3] > 7.0

    def test_format_entropy_bar(self):
        from filo.analyzer import StatisticalAnalyzer

        entropies = [0.0, 2.0, 5.0, 8.0]
        bar = StatisticalAnalyzer.format_entropy_bar(entropies)
        assert bar is not None
        assert len(bar) > 0

    def test_format_entropy_bar_empty(self):
        from filo.analyzer import StatisticalAnalyzer

        assert StatisticalAnalyzer.format_entropy_bar([]) == ""
