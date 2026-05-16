import pytest
from pathlib import Path
from filo.yarascanner import YARAScanner, YARAError


@pytest.fixture
def scanner():
    return YARAScanner()


SAMPLE_YARA_RULE = """
rule test_text_string : test detection {
    meta:
        description = "Test rule for text detection"
    strings:
        $text = "Hello World"
    condition:
        $text
}

rule test_hex_string {
    meta:
        description = "Test rule for hex detection"
    strings:
        $hex = { 00 01 02 03 FF FE }
    condition:
        $hex
}
"""


class TestYARAScanner:
    def test_available(self, scanner):
        """YARA should be available when yara-python is installed."""
        assert scanner.available is True

    def test_compile_and_scan_text(self, scanner):
        """Test compiling rules and scanning data for text patterns."""
        scanner.compile_rules(SAMPLE_YARA_RULE)
        result = scanner.scan_data(b"Hello World")
        assert result.rule_count == 1
        assert len(result.matches) == 1
        assert result.matches[0].rule == "test_text_string"
        assert "test" in result.matches[0].tags
        assert "detection" in result.matches[0].tags

    def test_compile_and_scan_hex(self, scanner):
        """Test scanning for hex byte patterns."""
        scanner.compile_rules(SAMPLE_YARA_RULE)
        result = scanner.scan_data(b"\x00\x01\x02\x03\xff\xfe")
        assert result.rule_count == 1
        assert result.matches[0].rule == "test_hex_string"

    def test_no_match(self, scanner):
        """Test that non-matching data returns empty results."""
        scanner.compile_rules(SAMPLE_YARA_RULE)
        result = scanner.scan_data(b"No patterns here at all")
        assert result.rule_count == 0
        assert len(result.matches) == 0

    def test_multiple_rules_match(self, scanner):
        """Test that multiple rules match the same data."""
        scanner.compile_rules(SAMPLE_YARA_RULE)
        result = scanner.scan_data(b"Hello World\x00\x01\x02\x03\xff\xfe")
        assert result.rule_count == 2
        rule_names = {m.rule for m in result.matches}
        assert "test_text_string" in rule_names
        assert "test_hex_string" in rule_names

    def test_meta_extracted(self, scanner):
        """Test that rule metadata is extracted correctly."""
        scanner.compile_rules(SAMPLE_YARA_RULE)
        result = scanner.scan_data(b"Hello World")
        assert len(result.matches) == 1
        match = result.matches[0]
        assert match.meta.get("description") == "Test rule for text detection"

    def test_tags_extracted(self, scanner):
        """Test that rule tags are extracted."""
        scanner.compile_rules(SAMPLE_YARA_RULE)
        result = scanner.scan_data(b"Hello World")
        assert len(result.matches) == 1
        assert "test" in result.matches[0].tags

    def test_scan_file(self, scanner, tmp_path):
        """Test scanning a file on disk."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text(SAMPLE_YARA_RULE)
        scanner.load_rule_file(rule_file)

        data_file = tmp_path / "sample.bin"
        data_file.write_bytes(b"Hello World\x00\x01\x02\x03\xff\xfe")
        result = scanner.scan_file(data_file)

        assert result.rule_count == 2

    def test_load_rule_file_not_found(self, scanner):
        """Test that loading a non-existent rule file raises YARAError."""
        with pytest.raises(YARAError, match="Rule file not found"):
            scanner.load_rule_file(Path("/nonexistent/rule.yar"))

    def test_scan_without_rules(self, scanner):
        """Test that scanning without loaded rules returns an error."""
        result = scanner.scan_data(b"test")
        assert result.error is not None

    def test_string_matches_populated(self, scanner):
        """Test that matched string details are populated."""
        scanner.compile_rules(SAMPLE_YARA_RULE)
        result = scanner.scan_data(b"prefix Hello World suffix")
        assert len(result.matches) == 1
        assert len(result.matches[0].strings) >= 1
        string_info = result.matches[0].strings[0]
        assert string_info["identifier"] == "$text"
        assert isinstance(string_info["offset"], int)
