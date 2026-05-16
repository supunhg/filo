"""
Tests for RepairEngine
"""

import pytest

from filo.repair import RepairEngine


def test_repair_engine_initialization():
    """Test repair engine initializes properly."""
    engine = RepairEngine()
    assert engine.database.count() > 0


def test_repair_pdf():
    """Test PDF header repair."""
    engine = RepairEngine()

    # PDF without header
    data = b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"

    repaired, report = engine.repair(data, "pdf", strategy="add_pdf_header")

    assert report.success
    assert repaired.startswith(b"%PDF-1.7")
    assert len(repaired) > len(data)
    assert "Added PDF-1.7 header" in report.changes_made


def test_repair_pdf_already_has_header():
    """Test PDF repair when header already exists."""
    engine = RepairEngine()

    # PDF with header
    data = b"%PDF-1.7\r\n1 0 obj\n"

    repaired, report = engine.repair(data, "pdf", strategy="add_pdf_header")

    assert not report.success
    assert "already present" in report.warnings[0].lower()
    assert repaired == data


def test_repair_auto_strategy():
    """Test auto strategy selection."""
    engine = RepairEngine()

    # Corrupted PDF
    data = b"corrupted pdf data here"

    repaired, report = engine.repair(data, "pdf", strategy="auto")

    # Should try strategies (advanced strategies tried first)
    assert report.strategy_used in [
        "add_pdf_header",
        "generate_minimal_header",
        "add_pdf_eof",
        "repair_pdf_xref",
    ]


def test_repair_unknown_format():
    """Test repair with unknown format."""
    engine = RepairEngine()

    with pytest.raises(ValueError, match="Unknown format"):
        engine.repair(b"data", "nonexistent_format")


def test_repair_report_structure():
    """Test repair report contains expected fields."""
    engine = RepairEngine()

    data = b"test data"
    repaired, report = engine.repair(data, "pdf", strategy="add_pdf_header")

    assert hasattr(report, "success")
    assert hasattr(report, "strategy_used")
    assert hasattr(report, "original_size")
    assert hasattr(report, "repaired_size")
    assert hasattr(report, "changes_made")
    assert hasattr(report, "warnings")

    assert report.original_size == len(data)
