"""
Integration tests
"""

from filo import Analyzer, RepairEngine


def test_analyze_and_repair_workflow(temp_dir, corrupted_pdf_data):
    """Test complete workflow: analyze -> detect issue -> repair."""
    # Create corrupted file
    corrupted_file = temp_dir / "corrupted.pdf"
    corrupted_file.write_bytes(corrupted_pdf_data)

    # Analyze
    analyzer = Analyzer()
    result = analyzer.analyze_file(corrupted_file)

    # Should detect as PDF (or unknown due to missing header)
    print(f"Detected as: {result.primary_format} with {result.confidence:.2%} confidence")

    # Repair
    engine = RepairEngine()
    repaired_data, report = engine.repair_file(
        corrupted_file,
        format_name="pdf",
        strategy="auto",
        output_path=temp_dir / "repaired.pdf",
        create_backup=False,
    )

    assert report.success
    assert repaired_data.startswith(b"%PDF")

    # Verify repaired file exists
    repaired_file = temp_dir / "repaired.pdf"
    assert repaired_file.exists()

    # Analyze repaired file
    result2 = analyzer.analyze_file(repaired_file)
    assert result2.primary_format == "pdf"
    assert result2.confidence > 0.5


def test_multiple_format_detection(sample_png_data, sample_jpeg_data, sample_pdf_data):
    """Test detecting multiple different formats."""
    analyzer = Analyzer()

    # PNG
    png_result = analyzer.analyze(sample_png_data)
    assert png_result.primary_format == "png"

    # JPEG
    jpeg_result = analyzer.analyze(sample_jpeg_data)
    assert jpeg_result.primary_format == "jpeg"

    # PDF
    pdf_result = analyzer.analyze(sample_pdf_data)
    assert pdf_result.primary_format == "pdf"
