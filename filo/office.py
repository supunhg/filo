import struct
import re
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

AUTO_EXEC_PATTERNS = [
    "AutoOpen",
    "Auto_Open",
    "AutoClose",
    "Auto_Close",
    "AutoExec",
    "Auto_Exec",
    "Workbook_Open",
    "Workbook_BeforeClose",
    "Document_Open",
    "Document_Close",
    "AutoOpenDocument",
]

SUSPICIOUS_KEYWORDS = [
    "Shell",
    "CreateObject",
    "WScript",
    "WScript.Shell",
    "Shell.Application",
    "ADODB.Stream",
    "WinHttp",
    "MSXML2",
    "URLDownloadToFile",
    "XMLHTTP",
    "Process.Start",
    "cmd.exe",
    "powershell",
    "PowerShell",
    "regsvr32",
    "rundll32",
    "mshta",
    "certutil",
    "bitsadmin",
    "wmic",
    "cscript",
    "wscript",
    "Base64Decode",
    "FromBase64String",
    "Environment.ExpandEnvironmentStrings",
    "Socket",
    "TCP",
    "WinSock",
    ".exe",
    ".dll",
    ".vbs",
    ".ps1",
    ".bat",
    ".scr",
    "GetObject",
    "Eval",
    "Execute",
    "ExecuteGlobal",
    "CallByName",
    "Chr(",
    "ChrW(",
]


@dataclass
class MacroStream:
    name: str
    source: str = ""
    offset: int = 0
    size: int = 0


@dataclass
class OfficeAnalysisResult:
    is_ole2: bool = False
    has_macros: bool = False
    macro_count: int = 0
    streams: list[MacroStream] = field(default_factory=list)
    auto_exec_macros: list[str] = field(default_factory=list)
    suspicious_keywords: list[str] = field(default_factory=list)
    keyword_count: int = 0
    is_encrypted: bool = False
    is_protected: bool = False
    app_name: Optional[str] = None
    app_version: Optional[str] = None


def _parse_ole2_directory(data: bytes) -> list[tuple[str, int, int]]:
    if len(data) < 512 or not data.startswith(OLE2_MAGIC):
        return []

    # Parse OLE2 header
    minor_version = struct.unpack_from("<H", data, 24)[0]
    major_version = struct.unpack_from("<H", data, 26)[0]
    sector_shift = struct.unpack_from("<H", data, 30)[0]
    mini_sector_shift = struct.unpack_from("<H", data, 32)[0]
    num_dir_sectors = struct.unpack_from("<I", data, 40)[0]
    num_fat_sectors = struct.unpack_from("<I", data, 44)[0]
    first_dir_sector = struct.unpack_from("<I", data, 48)[0]

    sector_size = 1 << sector_shift
    mini_sector_size = 1 << mini_sector_shift

    # Read DIFAT (Double Indirect FAT)
    # For simplicity, read first 109 FAT sectors from header
    difat = list(struct.unpack_from("<109I", data, 76))

    # Build FAT chain
    fat_sectors = []
    for sec_id in difat:
        if sec_id == 0xFFFFFFFF or sec_id == 0:
            continue
        if sec_id * sector_size + sector_size > len(data):
            continue
        fat_sectors.append(sec_id)

    # Read all FAT entries
    fat = []
    for sec_id in fat_sectors:
        offset = sec_id * sector_size
        if offset + sector_size > len(data):
            continue
        entries = struct.unpack_from(f"<{sector_size // 4}I", data, offset)
        fat.extend(entries)

    # Read directory entries (128 bytes each)
    entries = []
    current_sec = first_dir_sector
    while current_sec != 0xFFFFFFFF and current_sec != 0xFFFFFFFE:
        sec_offset = current_sec * sector_size
        if sec_offset + sector_size > len(data):
            break
        for i in range(sector_size // 128):
            dir_offset = sec_offset + i * 128
            if dir_offset + 128 > len(data):
                break
            name_buf = data[dir_offset : dir_offset + 64]
            name_len = struct.unpack_from("<H", data, dir_offset + 64)[0]
            obj_type = data[dir_offset + 66]
            color = data[dir_offset + 67]
            left_sibling = struct.unpack_from("<I", data, dir_offset + 68)[0]
            right_sibling = struct.unpack_from("<I", data, dir_offset + 72)[0]
            child = struct.unpack_from("<I", data, dir_offset + 76)[0]
            clsid = data[dir_offset + 80 : dir_offset + 96]
            state_bits = struct.unpack_from("<I", data, dir_offset + 96)[0]
            creation = struct.unpack_from("<Q", data, dir_offset + 100)[0]
            modified = struct.unpack_from("<Q", data, dir_offset + 108)[0]
            start_sector = struct.unpack_from("<I", data, dir_offset + 116)[0]
            stream_size = struct.unpack_from("<Q", data, dir_offset + 120)[0]

            if name_len > 0:
                try:
                    name = name_buf[: name_len - 2].decode("utf-16-le", errors="replace")
                except:
                    name = ""
            else:
                name = ""

            if name and obj_type in (1, 2, 5):
                entries.append((name, start_sector, stream_size))

        # Move to next directory sector via FAT
        fat_idx = current_sec
        if fat_idx < len(fat):
            current_sec = fat[fat_idx]
        else:
            break

    return entries


def _extract_ole_stream(data: bytes, start_sector: int, stream_size: int, fat: list[int], sector_size: int) -> bytes:
    if stream_size == 0:
        return b""
    result = bytearray()
    current_sec = start_sector
    remaining = stream_size
    visited = set()
    while current_sec != 0xFFFFFFFF and current_sec != 0xFFFFFFFE and remaining > 0:
        if current_sec in visited:
            break
        visited.add(current_sec)
        sec_offset = current_sec * sector_size
        if sec_offset + sector_size > len(data):
            break
        chunk = data[sec_offset : sec_offset + min(sector_size, remaining)]
        result.extend(chunk)
        remaining -= len(chunk)
        if current_sec < len(fat):
            current_sec = fat[current_sec]
        else:
            break
    return bytes(result)


def _detect_vba_in_entries(entries: list[tuple[str, int, int]], data: bytes, fat: list[int], sector_size: int) -> list[MacroStream]:
    vba_streams = []
    for name, start, size in entries:
        if "VBA" in name or name.endswith("Module"):
            vba_streams.append(MacroStream(name=name, offset=start, size=size))
        elif name == "ThisDocument" and start != 0:
            vba_streams.append(MacroStream(name=name, offset=start, size=size))
    return vba_streams


def _scan_for_keywords(source: str) -> list[str]:
    found = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw.lower() in source.lower():
            if kw not in found:
                found.append(kw)
    return found


def _scan_for_auto_exec(source: str) -> list[str]:
    found = []
    for pattern in AUTO_EXEC_PATTERNS:
        if re.search(rf"(Sub|Function)\s+{pattern}\b", source, re.IGNORECASE):
            if pattern not in found:
                found.append(pattern)
    return found


def analyze_office_file(data: bytes) -> OfficeAnalysisResult:
    result = OfficeAnalysisResult()

    if not data or len(data) < 512 or not data.startswith(OLE2_MAGIC):
        return result

    result.is_ole2 = True

    # Parse basic OLE2 structure
    minor_version = struct.unpack_from("<H", data, 24)[0]
    major_version = struct.unpack_from("<H", data, 26)[0]
    sector_shift = struct.unpack_from("<H", data, 30)[0]
    sector_size = 1 << sector_shift

    # Check for encryption/protection flags
    if len(data) > 56:
        flags = struct.unpack_from("<I", data, 56)[0]
        result.is_encrypted = bool(flags & 0x1)
        result.is_protected = bool(flags & 0x2)

    # Try to detect application from directory entries
    entries = _parse_ole2_directory(data)
    vba_names = {e[0] for e in entries}

    # Detect app type from stream names
    if "WordDocument" in vba_names or "1Table" in vba_names:
        result.app_name = "Word"
    elif "Workbook" in vba_names or "Book" in vba_names:
        result.app_name = "Excel"
    elif "PowerPoint Document" in vba_names:
        result.app_name = "PowerPoint"
    elif "MsoDct" in vba_names:
        result.app_name = "Outlook"
    elif any(n.startswith("\x05") for n in vba_names):
        result.app_name = "OLE2 Storage"

    # Check for VBA project streams
    has_vba = any(
        "VBA" in n or n.endswith(("Module", "Class1"))
        for n in vba_names
    )
    project_stream = any(
        n in vba_names
        for n in ["_VBA_PROJECT", "VBA/", "VBA/ThisDocument", "VBA/Module1"]
    )

    result.has_macros = has_vba or project_stream

    if result.has_macros:
        # Count macro modules
        macro_modules = [
            n for n in vba_names
            if n.startswith("VBA/Module") or n.startswith("Module") or n == "ThisDocument"
        ]
        result.macro_count = len(macro_modules)

        # Look for specific auto-exec macros and keywords
        # We check ThisDocument stream if we can find it
        for name, start, size in entries:
            if name in ("ThisDocument", "VBA/ThisDocument"):
                if size > 0 and size < 10 * 1024 * 1024:
                    stream_data = _extract_ole_stream(
                        data, start, size, _build_fat(data, sector_size), sector_size
                    )
                    try:
                        source = stream_data.decode("utf-16-le", errors="replace")
                        result.auto_exec_macros = _scan_for_auto_exec(source)
                        result.suspicious_keywords = _scan_for_keywords(source)
                        result.keyword_count = len(result.suspicious_keywords)
                    except:
                        pass

        # Scan additional module streams for patterns
        for name, start, size in entries:
            if name not in ("ThisDocument", "VBA/ThisDocument") and (
                "Module" in name or "Class" in name or "Form" in name or "Sheet" in name
            ):
                if size > 0 and size < 10 * 1024 * 1024:
                    stream_data = _extract_ole_stream(
                        data, start, size, _build_fat(data, sector_size), sector_size
                    )
                    try:
                        source = stream_data.decode("utf-16-le", errors="replace")
                        more_auto = _scan_for_auto_exec(source)
                        for a in more_auto:
                            if a not in result.auto_exec_macros:
                                result.auto_exec_macros.append(a)
                        more_kw = _scan_for_keywords(source)
                        for k in more_kw:
                            if k not in result.suspicious_keywords:
                                result.suspicious_keywords.append(k)
                                result.keyword_count += 1
                    except:
                        pass

    return result


def _build_fat(data: bytes, sector_size: int) -> list[int]:
    """Build FAT chain from DIFAT."""
    if len(data) < 512:
        return []
    difat = list(struct.unpack_from("<109I", data, 76))
    fat = []
    for sec_id in difat:
        if sec_id == 0xFFFFFFFF or sec_id == 0:
            continue
        offset = sec_id * sector_size
        if offset + sector_size > len(data):
            continue
        entries = struct.unpack_from(f"<{sector_size // 4}I", data, offset)
        fat.extend(entries)
    return fat
