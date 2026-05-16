from filo.cli import _extract_strings, _string_entropy, _detect_encoding


class TestExtractStrings:
    def test_empty_data(self):
        assert _extract_strings(b"") == []

    def test_ascii_strings(self):
        data = b"HelloWorld" + b"\x00" * 10 + b"AnotherString"
        results = _extract_strings(data, min_len=4)
        assert len(results) >= 2
        assert any(r["data"] == b"HelloWorld" for r in results)
        assert any(r["data"] == b"AnotherString" for r in results)

    def test_min_length_filter(self):
        data = b"ab" + b"\x00" + b"abcd" + b"\x00" + b"abcdef"
        results = _extract_strings(data, min_len=4)
        assert len(results) == 2
        assert all(r["length"] >= 4 for r in results)

    def test_no_short_strings(self):
        data = b"\x00".join([b"a", b"ab", b"abc"])
        results = _extract_strings(data, min_len=4)
        assert len(results) == 0

    def test_mixed_with_binary(self):
        data = b"\xff\xfe\xfd" + b"VISIBLE" + b"\x01\x02\x03"
        results = _extract_strings(data, min_len=4)
        assert len(results) == 1
        assert results[0]["data"] == b"VISIBLE"

    def test_offsets_correct(self):
        data = b"\x00" * 10 + b"STRING1" + b"\x00" * 5 + b"STRING2"
        results = _extract_strings(data, min_len=4)
        str1 = next(r for r in results if r["data"] == b"STRING1")
        str2 = next(r for r in results if r["data"] == b"STRING2")
        assert str1["offset"] == 10
        assert str2["offset"] == 22

    def test_unicode_strings(self):
        data = b"H\x00e\x00l\x00l\x00o\x00\x00\x00" + b"W\x00o\x00r\x00l\x00d\x00"
        results = _extract_strings(data, min_len=4)
        unicode_results = [r for r in results if r["type"] == "unicode"]
        assert len(unicode_results) >= 1


class TestStringEntropy:
    def test_zero_entropy(self):
        assert _string_entropy(b"\x00" * 10) == 0.0

    def test_high_entropy(self):
        e = _string_entropy(bytes(range(256)))
        assert e > 7.5

    def test_low_entropy(self):
        e = _string_entropy(b"AAAAAAAABBBBBBBB")
        assert e < 1.5

    def test_empty(self):
        assert _string_entropy(b"") == 0.0


class TestDetectEncoding:
    def test_base64(self):
        result = _detect_encoding(b"SGVsbG8gV29ybGQ=")
        assert result is not None
        assert "base64" in result

    def test_utf8(self):
        result = _detect_encoding(b"hello")
        assert result == "utf-8"

    def test_random_binary(self):
        result = _detect_encoding(bytes(range(64)))
        assert result is None
