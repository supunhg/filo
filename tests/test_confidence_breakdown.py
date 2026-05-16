"""Tests for confidence breakdown and explanation features."""

import pytest
from filo.analyzer import Analyzer


def test_confidence_contributions_in_signature_analysis():
    """Test that signature matches include contribution breakdown."""
    analyzer = Analyzer(use_ml=False)
    
    # Create a PNG file (signature at offset 0 and 8)
    png_data = bytes.fromhex("89504E470D0A1A0A0000000D494844520000001000000010080200000090916836")
    
    result = analyzer.analyze(png_data)
    
    # Check that evidence chain includes contributions
    assert len(result.evidence_chain) > 0
    
    # Find signature analysis evidence for PNG
    sig_evidence = [e for e in result.evidence_chain 
                    if e["format"] == "png" and e["module"] == "signature_analysis"]
    
    assert len(sig_evidence) > 0
    assert "contributions" in sig_evidence[0]
    assert len(sig_evidence[0]["contributions"]) > 0
    
    # Verify contribution structure
    for contrib in sig_evidence[0]["contributions"]:
        assert "source" in contrib
        assert "value" in contrib
        assert "description" in contrib
        assert "is_penalty" in contrib
        assert contrib["source"] == "signature"


def test_confidence_contributions_in_container_analysis():
    """Test that ZIP container analysis includes contribution breakdown."""
    import zipfile
    import io
    
    analyzer = Analyzer(use_ml=False)
    
    # Create a minimal DOCX structure
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('[Content_Types].xml', '<?xml version="1.0"?><Types></Types>')
        zf.writestr('word/document.xml', '<?xml version="1.0"?><document></document>')
    
    result = analyzer.analyze(zip_buffer.getvalue())
    
    # Find container analysis evidence for DOCX
    container_evidence = [e for e in result.evidence_chain 
                          if e["format"] == "docx" and e["module"] == "zip_container_analysis"]
    
    assert len(container_evidence) > 0
    assert "contributions" in container_evidence[0]
    assert len(container_evidence[0]["contributions"]) > 0
    
    # Verify contributions mention the key DOCX files
    contrib_descriptions = [c["description"] for c in container_evidence[0]["contributions"]]
    assert any("word/document.xml" in desc for desc in contrib_descriptions)
    assert any("[Content_Types].xml" in desc for desc in contrib_descriptions)


def test_confidence_penalties_in_structural_analysis():
    """Test that structural analysis includes penalties for missing fields."""
    analyzer = Analyzer(use_ml=False)
    
    # Create a very short PNG file (missing expected structure)
    png_data = bytes.fromhex("89504E47")  # Only magic bytes, missing IHDR
    
    result = analyzer.analyze(png_data)
    
    # Find structural analysis evidence
    struct_evidence = [e for e in result.evidence_chain 
                       if e["module"] == "structural_analysis"]
    
    # If structural analysis ran, check for penalties
    if struct_evidence:
        assert "contributions" in struct_evidence[0]
        contributions = struct_evidence[0]["contributions"]
        
        # Check if any contribution is marked as penalty
        penalties = [c for c in contributions if c.get("is_penalty", False)]
        
        # Verify penalty structure if present
        for penalty in penalties:
            assert penalty["value"] < 0
            assert "description" in penalty


def test_contribution_value_ranges():
    """Test that contribution values are within expected ranges."""
    analyzer = Analyzer(use_ml=False)
    
    # Create a complete PNG file
    png_data = bytes.fromhex("89504E470D0A1A0A0000000D494844520000001000000010080200000090916836")
    
    result = analyzer.analyze(png_data)
    
    # Collect all contributions
    all_contributions = []
    for evidence in result.evidence_chain:
        if "contributions" in evidence:
            all_contributions.extend(evidence["contributions"])
    
    # Verify each contribution
    for contrib in all_contributions:
        # Contributions should be reasonable (not absurdly high or low)
        if contrib["is_penalty"]:
            assert contrib["value"] < 0
            assert contrib["value"] >= -1.0  # No more than -100% penalty
        else:
            assert contrib["value"] >= 0
            assert contrib["value"] <= 1.0  # No more than 100% contribution


def test_explain_flag_output_format(capsys):
    """Test that --explain flag produces correct output format."""
    import subprocess
    import tempfile
    
    # Create a test PNG file
    with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
        f.write(bytes.fromhex("89504E470D0A1A0A0000000D494844520000001000000010080200000090916836"))
        temp_path = f.name
    
    try:
        # Run filo with --explain flag
        result = subprocess.run(
            ['filo', 'analyze', temp_path, '--explain'],
            capture_output=True,
            text=True
        )
        
        output = result.stdout
        
        # Verify key elements are present
        assert "Confidence Breakdown:" in output
        assert "Primary:" in output
        assert "PNG" in output or "png" in output
        assert "%" in output  # Percentage values
        
        # Verify contribution format (+ or - prefix)
        assert "+" in output or "-" in output
        
    finally:
        import os
        os.unlink(temp_path)


def test_aggregated_confidence_calculation():
    """Test that displayed contributions reflect the detection strength."""
    analyzer = Analyzer(use_ml=False)
    
    # Create a DOCX file
    import zipfile
    import io
    
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('[Content_Types].xml', '<?xml version="1.0"?><Types></Types>')
        zf.writestr('word/document.xml', '<?xml version="1.0"?><document></document>')
    
    result = analyzer.analyze(zip_buffer.getvalue())
    
    # Collect all contributions for the primary format
    total_contribution = 0.0
    for evidence in result.evidence_chain:
        if evidence["format"] == result.primary_format and "contributions" in evidence:
            module_weight = evidence.get("weight", 1.0)
            module = evidence["module"]
            
            # Apply the same weighting as analyzer
            for contrib in evidence["contributions"]:
                if module == "signature_analysis":
                    weighted = contrib["value"] * module_weight * 0.6
                elif module == "structural_analysis":
                    weighted = contrib["value"] * module_weight * 0.4
                elif module == "zip_container_analysis":
                    weighted = contrib["value"] * module_weight * 0.8
                else:
                    weighted = contrib["value"]
                
                total_contribution += weighted
    
    # The total can exceed 1.0 (final confidence is clamped)
    # But it should be positive and represent detection strength
    assert total_contribution > 0
    
    # For strong detections, contributions should sum to a meaningful value
    if result.confidence >= 0.8:
        assert total_contribution >= 0.5  # At least some positive evidence


def test_contribution_source_types():
    """Test that contributions use expected source types."""
    analyzer = Analyzer(use_ml=False)
    
    # Create a PNG file
    png_data = bytes.fromhex("89504E470D0A1A0A0000000D494844520000001000000010080200000090916836")
    
    result = analyzer.analyze(png_data)
    
    # Collect all source types
    sources = set()
    for evidence in result.evidence_chain:
        if "contributions" in evidence:
            for contrib in evidence["contributions"]:
                sources.add(contrib["source"])
    
    # Valid source types
    valid_sources = {"signature", "structure", "container", "ml"}
    
    # All sources should be from the valid set
    assert sources.issubset(valid_sources)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
