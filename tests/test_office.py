import struct
from filo.office import analyze_office_file, OLE2_MAGIC, SUSPICIOUS_KEYWORDS, AUTO_EXEC_PATTERNS


def make_ole2_header(sector_shift: int = 9) -> bytes:
    """Create a minimal OLE2 header."""
    header = bytearray(512)
    header[0:8] = OLE2_MAGIC
    # Minor version
    struct.pack_into("<H", header, 24, 0x003E)
    # Major version
    struct.pack_into("<H", header, 26, 0x0003)
    # Byte order
    struct.pack_into("<H", header, 28, 0xFFFE)
    # Sector size shift
    struct.pack_into("<H", header, 30, sector_shift)
    # Mini sector size shift
    struct.pack_into("<H", header, 32, 0x0006)
    # Reserved
    struct.pack_into("<I", header, 36, 0)
    # Total directory sectors
    struct.pack_into("<I", header, 40, 0)
    # Total FAT sectors
    struct.pack_into("<I", header, 44, 0)
    # First directory sector
    struct.pack_into("<I", header, 48, 0xFFFFFFFF)
    # Mini stream cutoff
    struct.pack_into("<I", header, 52, 0x00001000)
    # Mini FAT first sector
    struct.pack_into("<I", header, 56, 0xFFFFFFFE)
    # Mini FAT sector count
    struct.pack_into("<I", header, 60, 0)
    # DIFAT first sector
    struct.pack_into("<I", header, 64, 0xFFFFFFFE)
    # DIFAT sector count
    struct.pack_into("<I", header, 68, 0)
    # DIFAT entries (first 109, all free by default)
    for i in range(109):
        struct.pack_into("<I", header, 76 + i * 4, 0xFFFFFFFF)
    return bytes(header)


def make_dir_entry(
    name: str, obj_type: int = 2, start_sector: int = 0xFFFFFFFF, stream_size: int = 0
) -> bytes:
    entry = bytearray(128)
    name_encoded = name.encode("utf-16-le") + b"\x00\x00"
    name_len = min(len(name_encoded), 64)
    entry[0:name_len] = name_encoded[:name_len]
    struct.pack_into("<H", entry, 64, len(name_encoded) + 2 if name else 0)
    entry[66] = obj_type
    entry[67] = 0  # color: black
    struct.pack_into("<I", entry, 68, 0xFFFFFFFF)  # left sibling
    struct.pack_into("<I", entry, 72, 0xFFFFFFFF)  # right sibling
    struct.pack_into("<I", entry, 76, 0xFFFFFFFF)  # child
    struct.pack_into("<I", entry, 116, start_sector)
    struct.pack_into("<Q", entry, 120, stream_size)
    return bytes(entry)


class TestOfficeAnalyzer:
    def test_empty_data(self):
        """Empty data should return empty result."""
        result = analyze_office_file(b"")
        assert result.is_ole2 is False
        assert result.has_macros is False

    def test_non_ole2_data(self):
        """Non-OLE2 data should return empty result."""
        result = analyze_office_file(b"This is not an OLE2 file at all\x00" * 50)
        assert result.is_ole2 is False

    def test_ole2_no_macros(self):
        """Minimal OLE2 file without macros should detect OLE2 but no macros."""
        data = make_ole2_header() + b"\x00" * 512 * 10
        result = analyze_office_file(data)
        assert result.is_ole2 is True
        assert result.has_macros is False

    def test_not_enough_data(self):
        """Short data should not be analyzed."""
        result = analyze_office_file(b"\x00" * 100)
        assert result.is_ole2 is False

    def test_suspicious_keywords_list(self):
        """Suspicious keywords list should include common malware indicators."""
        assert "Shell" in SUSPICIOUS_KEYWORDS
        assert "CreateObject" in SUSPICIOUS_KEYWORDS
        assert "WScript.Shell" in SUSPICIOUS_KEYWORDS
        assert "powershell" in SUSPICIOUS_KEYWORDS
        assert "URLDownloadToFile" in SUSPICIOUS_KEYWORDS

    def test_auto_exec_patterns(self):
        """Auto-exec patterns should include common auto-open macros."""
        assert "AutoOpen" in AUTO_EXEC_PATTERNS
        assert "Workbook_Open" in AUTO_EXEC_PATTERNS
        assert "Document_Open" in AUTO_EXEC_PATTERNS

    def test_no_false_positive_on_random_data(self):
        """Random binary data should not trigger macro detection."""
        data = bytes([i % 256 for i in range(1024)])
        result = analyze_office_file(data)
        assert result.is_ole2 is False

    def test_large_ole2(self):
        """Large OLE2-like data should not cause errors."""
        data = make_ole2_header() + b"\x00" * (512 * 20)
        result = analyze_office_file(data)
        assert result.is_ole2 is True
