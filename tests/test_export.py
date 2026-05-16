"""Tests for export functionality."""

import json
from pathlib import Path

import pytest

from filo.export import JSONExporter, SARIFExporter, export_to_file
from filo.analyzer import Analyzer
from filo.repair import RepairReport


@pytest.fixture
def sample_result():
    """Create sample analysis result."""
    analyzer = Analyzer(use_ml=False)
    data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
    return analyzer.analyze(data)


def test_json_export_result(sample_result):
    """Test JSON export of single result."""
    exported = JSONExporter.export_result(sample_result, pretty=True)
    
    data = json.loads(exported)
    
    assert data["format"] == "png"
    assert "confidence" in data
    assert "file_size" in data
    assert "entropy" in data
    assert "checksum" in data


def test_json_export_batch(sample_result):
    """Test JSON export of batch results."""
    results = [
        (Path("test1.png"), sample_result),
        (Path("test2.png"), sample_result),
    ]
    
    exported = JSONExporter.export_batch(results, pretty=True)
    
    data = json.loads(exported)
    
    assert data["total_files"] == 2
    assert len(data["files"]) == 2
    assert "timestamp" in data


def test_json_export_repair():
    """Test JSON export of repair report."""
    report = RepairReport(
        success=True,
        strategy_used="test_strategy",
        original_size=100,
        repaired_size=110,
        changes_made=["Added header"],
        warnings=[],
        confidence=0.9
    )
    
    exported = JSONExporter.export_repair(report, pretty=True)
    
    data = json.loads(exported)
    
    assert data["success"] is True
    assert data["strategy_used"] == "test_strategy"
    assert data["confidence"] == 0.9


def test_sarif_export_result(sample_result):
    """Test SARIF export of single result."""
    exported = SARIFExporter.export_result(sample_result, Path("test.png"), pretty=True)
    
    data = json.loads(exported)
    
    assert data["version"] == "2.1.0"
    assert "runs" in data
    assert len(data["runs"]) == 1
    assert data["runs"][0]["tool"]["driver"]["name"] == "Filo"


def test_sarif_export_batch(sample_result):
    """Test SARIF export of batch results."""
    results = [
        (Path("test1.png"), sample_result),
        (Path("test2.png"), sample_result),
    ]
    
    exported = SARIFExporter.export_batch(results, pretty=True)
    
    data = json.loads(exported)
    
    assert data["version"] == "2.1.0"
    assert "runs" in data


def test_export_to_file(sample_result, temp_dir):
    """Test exporting to file."""
    output_path = temp_dir / "result.json"
    
    exported = JSONExporter.export_result(sample_result)
    export_to_file(exported, output_path, overwrite=True)
    
    assert output_path.exists()
    
    # Verify content
    with open(output_path) as f:
        data = json.load(f)
    
    assert data["format"] == "png"


def test_export_to_file_no_overwrite(temp_dir):
    """Test export with no overwrite."""
    output_path = temp_dir / "result.json"
    output_path.write_text("existing")
    
    with pytest.raises(FileExistsError):
        export_to_file("new data", output_path, overwrite=False)


def test_sarif_with_warnings(sample_result):
    """Test SARIF export with warnings - currently AnalysisResult doesn't have warnings field."""
    exported = SARIFExporter.export_result(sample_result, Path("test.png"))
    data = json.loads(exported)
    
    results = data["runs"][0]["results"]
    
    # Should have main result
    assert len(results) >= 1
    assert results[0]["ruleId"] == "FILE-001"
