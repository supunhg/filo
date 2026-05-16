"""
Contradiction detection for identifying format anomalies and suspicious structures.

This module detects when files exhibit contradictory traits that may indicate:
- Corrupted files
- Malware/polyglots
- Format confusion attacks
- Embedded malicious content
"""

import logging
from typing import Optional
from filo.models import Contradiction

logger = logging.getLogger(__name__)


class ContradictionDetector:
    """Detects structural contradictions and format anomalies."""

    @staticmethod
    def check_png_compression(data: bytes) -> Optional[Contradiction]:
        """Check if PNG has valid zlib compression in IDAT chunks."""
        if len(data) < 33:  # Minimum PNG size
            return None

        # Collect all IDAT chunks (they should be consecutive)
        pos = 8  # After PNG signature
        idat_data_chunks = []

        try:
            while pos < len(data) - 12:
                if pos + 8 > len(data):
                    break

                # Read chunk length and type
                chunk_length = int.from_bytes(data[pos : pos + 4], "big")
                chunk_type = data[pos + 4 : pos + 8]

                if chunk_type == b"IDAT":
                    # Collect IDAT data (multiple IDAT chunks form one zlib stream)
                    idat_data_chunks.append(data[pos + 8 : pos + 8 + chunk_length])
                elif chunk_type == b"IEND" or (idat_data_chunks and chunk_type != b"IDAT"):
                    # Reached end of IDAT sequence
                    break

                # Move to next chunk
                pos += 12 + chunk_length

            # If we found IDAT chunks, try to decompress the concatenated stream
            if idat_data_chunks:
                import zlib

                combined_idat = b"".join(idat_data_chunks)

                try:
                    # Try to decompress - will raise error if invalid
                    zlib.decompress(combined_idat)
                except zlib.error as e:
                    # Only report as error if it's a serious corruption
                    # Some valid PNGs may have truncation warnings that viewers ignore
                    error_msg = str(e).lower()
                    if "unknown compression method" in error_msg or "invalid" in error_msg:
                        return Contradiction(
                            severity="error",
                            claimed_format="png",
                            issue="Invalid compression stream",
                            details=f"IDAT chunk contains invalid zlib data: {str(e)}",
                            category="compression",
                        )
                    # Ignore truncation warnings if image otherwise works

        except Exception as e:
            logger.debug(f"PNG compression check failed: {e}")

        return None

    @staticmethod
    def check_zip_ooxml_structure(data: bytes, namelist: list[str]) -> Optional[Contradiction]:
        """Check if ZIP claiming to be OOXML has required structure."""
        has_content_types = any("[content_types].xml" in name.lower() for name in namelist)

        if has_content_types:
            # This claims to be OOXML format
            has_rels = any("_rels/.rels" in name.lower() for name in namelist)

            if not has_rels:
                return Contradiction(
                    severity="warning",
                    claimed_format="ooxml",
                    issue="Missing mandatory _rels/.rels",
                    details="OOXML format requires _rels/.rels but it's absent",
                    category="missing",
                )

            # Check for specific format markers
            has_word = any("word/document.xml" in name.lower() for name in namelist)
            has_ppt = any("ppt/presentation.xml" in name.lower() for name in namelist)
            has_xl = any("xl/workbook.xml" in name.lower() for name in namelist)

            # If it has Content_Types but no actual document
            if not (has_word or has_ppt or has_xl):
                return Contradiction(
                    severity="warning",
                    claimed_format="ooxml",
                    issue="Missing core document file",
                    details="Has [Content_Types].xml but no document.xml, presentation.xml, or workbook.xml",
                    category="structure",
                )

        return None

    @staticmethod
    def check_embedded_formats(data: bytes, primary_format: str, **context) -> list[Contradiction]:
        """Detect suspicious embedded format signatures."""
        contradictions = []

        # For ZIP-based formats, also check inside compressed members
        if primary_format in [
            "zip",
            "docx",
            "xlsx",
            "pptx",
            "jar",
            "apk",
            "odt",
            "odp",
            "ods",
            "epub",
        ]:
            try:
                import zipfile
                import io

                with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                    for name in zf.namelist()[:20]:  # Check first 20 files
                        try:
                            member_data = zf.read(name)
                            # Check first 10KB of each member
                            check_data = member_data[: min(len(member_data), 10240)]

                            # Suspicious patterns
                            suspicious_patterns = {
                                b"\x7fELF": ("ELF executable", "embedded"),
                                b"MZ": ("PE/DOS executable", "embedded"),
                                b"\xca\xfe\xba\xbe": ("Mach-O executable", "embedded"),
                                b"#!/bin/sh": ("Shell script", "embedded"),
                                b"#!/bin/bash": ("Bash script", "embedded"),
                                b"<?php": ("PHP script", "embedded"),
                            }

                            for pattern, (format_name, category) in suspicious_patterns.items():
                                offset = check_data.find(pattern)
                                if offset != -1 and offset < 8192:  # Within first 8KB
                                    contradictions.append(
                                        Contradiction(
                                            severity="critical",
                                            claimed_format=primary_format,
                                            issue=f"Embedded {format_name} signature",
                                            details=f"Found {format_name} in ZIP member '{name}' at offset {offset}",
                                            category=category,
                                        )
                                    )
                                    break  # One per member
                        except Exception:
                            pass
            except Exception as e:
                logger.debug(f"ZIP member check failed: {e}")

        # Also check main file data (for non-ZIP or polyglots)
        # Skip first 512 bytes (legitimate headers)
        search_data = data[512 : min(len(data), 10240)]  # Search next 10KB

        # Suspicious magic bytes to look for
        suspicious_patterns = {
            b"\x7fELF": ("ELF executable", "embedded"),
            b"MZ": ("PE/DOS executable", "embedded"),
            b"\x4d\x5a\x90": ("PE executable", "embedded"),
            b"\xca\xfe\xba\xbe": ("Mach-O executable", "embedded"),
            b"#!/bin/sh": ("Shell script", "embedded"),
            b"#!/bin/bash": ("Bash script", "embedded"),
            b"<?php": ("PHP script", "embedded"),
        }

        for pattern, (format_name, category) in suspicious_patterns.items():
            offset = search_data.find(pattern)
            if offset != -1:
                contradictions.append(
                    Contradiction(
                        severity="critical",
                        claimed_format=primary_format,
                        issue=f"Embedded {format_name} signature",
                        details=f"Found {format_name} magic bytes at offset {512 + offset}",
                        category=category,
                    )
                )

        return contradictions

    @staticmethod
    def check_zip_structure_integrity(data: bytes) -> Optional[Contradiction]:
        """Check ZIP structural integrity."""
        try:
            import zipfile
            import io

            zip_buffer = io.BytesIO(data)
            with zipfile.ZipFile(zip_buffer, "r") as zf:
                # Test ZIP integrity
                corrupt_files = []
                for name in zf.namelist()[:10]:  # Check first 10 files
                    try:
                        zf.testzip()
                        break
                    except Exception:
                        corrupt_files.append(name)

                if corrupt_files:
                    return Contradiction(
                        severity="error",
                        claimed_format="zip",
                        issue="Corrupted ZIP entries",
                        details=f"ZIP structure corruption detected in: {', '.join(corrupt_files[:3])}",
                        category="structure",
                    )
        except Exception as e:
            logger.debug(f"ZIP integrity check failed: {e}")

        return None

    @staticmethod
    def check_png_header(data: bytes) -> Optional[Contradiction]:
        """Check PNG signature and chunk structure."""
        if len(data) < 33:  # Minimum: 8-byte signature + 25-byte IHDR chunk
            return None

        # PNG signature: 89 50 4E 47 0D 0A 1A 0A
        correct_sig = b"\x89PNG\r\n\x1a\n"
        actual_sig = data[0:8]

        issues = []

        # Check signature corruption
        if actual_sig != correct_sig:
            # Check if it's close to PNG signature (partial corruption)
            corrupted_bytes = []
            for i, (actual, expected) in enumerate(zip(actual_sig, correct_sig)):
                if actual != expected:
                    corrupted_bytes.append(f"byte {i}: 0x{actual:02X} should be 0x{expected:02X}")

            if corrupted_bytes:
                issues.append(f"Corrupted PNG signature: {'; '.join(corrupted_bytes)}")

        # Check IHDR chunk (should be first chunk after signature)
        if len(data) >= 16:
            ihdr_length = int.from_bytes(data[8:12], "big")
            ihdr_type = data[12:16]

            # IHDR chunk type should be "IHDR"
            if ihdr_type != b"IHDR":
                # Check if it's corrupted
                corrupted = []
                for i, (actual, expected) in enumerate(zip(ihdr_type, b"IHDR")):
                    if actual != expected:
                        corrupted.append(
                            f"byte {i}: '{chr(actual) if 32 <= actual < 127 else '?'}' (0x{actual:02X}) should be '{chr(expected)}' (0x{expected:02X})"
                        )

                if corrupted:
                    issues.append(f"Corrupted IHDR chunk name: {'; '.join(corrupted)}")

            # IHDR length should be 13
            if ihdr_length != 13:
                issues.append(f"Invalid IHDR chunk length: {ihdr_length} (should be 13)")

        # Look for corrupted IDAT chunks (common in CTF challenges)
        # Start after IHDR chunk (8 bytes sig + 4 length + 4 type + 13 data + 4 CRC = 33)
        pos = 33
        idat_corruptions = []
        while pos < min(len(data), 2048):  # Check first 2KB for chunk names
            try:
                if pos + 8 > len(data):
                    break

                chunk_length = int.from_bytes(data[pos : pos + 4], "big")
                chunk_type = data[pos + 4 : pos + 8]

                # Check if chunk type looks corrupted
                # Valid chunk types are all letters (A-Z, a-z)
                if all(65 <= b <= 90 or 97 <= b <= 122 for b in chunk_type):
                    # Skip known valid chunks (sRGB, gAMA, pHYs, tEXt, etc.)
                    known_chunks = {
                        b"IDAT",
                        b"IHDR",
                        b"IEND",
                        b"PLTE",
                        b"sRGB",
                        b"gAMA",
                        b"pHYs",
                        b"tEXt",
                        b"iTXt",
                        b"zTXt",
                        b"bKGD",
                        b"tRNS",
                        b"cHRM",
                        b"sBIT",
                        b"sPLT",
                        b"hIST",
                        b"tIME",
                    }

                    # Check for near-IDAT patterns (but not other valid chunks)
                    # Pattern: 0xABDET or similar (ab 44 45 54)
                    if chunk_type not in known_chunks and (
                        (
                            chunk_type[0] == 0xAB and chunk_type[1:4] == b"DET"
                        )  # Specific CTF pattern
                        or (
                            chunk_type != b"IDAT"
                            and abs(chunk_type[0] - ord("I")) <= 3
                            and abs(chunk_type[1] - ord("D")) <= 3
                            and abs(chunk_type[2] - ord("A")) <= 3
                            and abs(chunk_type[3] - ord("T")) <= 3
                            and chunk_type not in known_chunks
                        )
                    ):
                        corrupted = []
                        for i, (actual, expected) in enumerate(zip(chunk_type, b"IDAT")):
                            if actual != expected:
                                corrupted.append(
                                    f"'{chr(actual) if 32 <= actual < 127 else '?'}' (0x{actual:02X}) should be '{chr(expected)}' (0x{expected:02X})"
                                )

                        idat_corruptions.append(f"Chunk at 0x{pos:X}: {'; '.join(corrupted)}")
                        break  # Report first corruption only

                # Move to next chunk
                pos += 8 + chunk_length + 4  # length + type + data + CRC

            except Exception:
                break

        if idat_corruptions:
            issues.append(f"Corrupted IDAT chunk: {idat_corruptions[0]}")

        if issues:
            return Contradiction(
                severity="critical",
                claimed_format="png",
                issue="Corrupted PNG header or chunks",
                details="; ".join(issues),
                category="header_corruption",
            )

        return None

    @staticmethod
    def check_jpeg_structure(data: bytes) -> Optional[Contradiction]:
        """Check JPEG marker sequence validity."""
        if len(data) < 10:
            return None

        # JPEG should start with SOI (0xFFD8)
        if data[0:2] != b"\xff\xd8":
            return None

        # Check for common structural issues
        pos = 2
        has_sof = False
        has_sos = False

        try:
            while pos < len(data) - 2:
                if data[pos] != 0xFF:
                    # Not a marker
                    break

                marker = data[pos + 1]

                # Start of Frame markers
                if marker in [0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7]:
                    has_sof = True

                # Start of Scan
                if marker == 0xDA:
                    has_sos = True
                    break

                # End of Image
                if marker == 0xD9:
                    break

                # Skip marker
                if marker in [0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8]:
                    # Standalone markers (no length)
                    pos += 2
                else:
                    # Read length
                    if pos + 3 >= len(data):
                        break
                    length = (data[pos + 2] << 8) | data[pos + 3]
                    pos += 2 + length

            # JPEG should have SOF and SOS markers
            if has_sof and not has_sos:
                return Contradiction(
                    severity="warning",
                    claimed_format="jpeg",
                    issue="Missing Start of Scan (SOS) marker",
                    details="JPEG has SOF but no SOS marker - likely truncated",
                    category="structure",
                )

        except Exception as e:
            logger.debug(f"JPEG structure check failed: {e}")

        return None

    @staticmethod
    def check_pdf_structure(data: bytes) -> Optional[Contradiction]:
        """Check PDF structural validity."""
        if len(data) < 8:
            return None

        # PDF should start with %PDF-
        if not data.startswith(b"%PDF-"):
            return None

        # Check for EOF marker
        if b"%%EOF" not in data[-1024:]:
            return Contradiction(
                severity="warning",
                claimed_format="pdf",
                issue="Missing EOF marker",
                details="PDF lacks %%EOF marker in last 1KB - may be truncated or corrupted",
                category="structure",
            )

        return None

    @staticmethod
    def check_bmp_header(data: bytes) -> Optional[Contradiction]:
        """Check BMP header for corruption or tampering."""
        if len(data) < 54 or not data.startswith(b"BM"):
            return None

        try:
            import struct

            # Read BMP header fields
            struct.unpack("<I", data[2:6])[0]
            pixel_offset = struct.unpack("<I", data[10:14])[0]
            dib_header_size = struct.unpack("<I", data[14:18])[0]
            width = struct.unpack("<I", data[18:22])[0]
            height = struct.unpack("<I", data[22:26])[0]
            bits_per_pixel = struct.unpack("<H", data[28:30])[0]

            issues = []

            # Check for known "bad" patterns
            if dib_header_size == 0xBAD0 or dib_header_size == 0xD0BA:
                issues.append(
                    f"DIB header size is 0x{dib_header_size:X} (suspicious 'BAD0' pattern)"
                )

            if pixel_offset == 0xBAD0 or pixel_offset == 0xD0BA:
                issues.append(f"Pixel offset is 0x{pixel_offset:X} (suspicious 'BAD0' pattern)")

            # Check DIB header size validity
            valid_dib_sizes = [12, 40, 52, 56, 108, 124]  # Common DIB header sizes
            if dib_header_size not in valid_dib_sizes:
                if dib_header_size not in [0xBAD0, 0xD0BA]:  # Don't double-report
                    issues.append(
                        f"Invalid DIB header size: {dib_header_size} (expected 40 for standard BMP)"
                    )

            # Check pixel offset sanity
            expected_offset = 14 + dib_header_size  # BMP file header + DIB header
            if dib_header_size == 40:  # Standard BITMAPINFOHEADER
                expected_offset = 54

            if pixel_offset != expected_offset and pixel_offset not in [0xBAD0, 0xD0BA]:
                issues.append(f"Unusual pixel offset: {pixel_offset} (expected {expected_offset})")

            # Calculate expected height from file size
            if bits_per_pixel > 0 and width > 0:
                bits_per_pixel // 8
                row_size = ((width * bits_per_pixel + 31) // 32) * 4  # Row size aligned to 4 bytes

                # Use the actual pixel offset if it seems valid
                actual_offset = 54 if pixel_offset > len(data) else pixel_offset
                pixel_data_size = len(data) - actual_offset
                calculated_height = pixel_data_size // row_size if row_size > 0 else 0

                # Allow some tolerance for rounding
                if calculated_height > 0 and abs(calculated_height - height) > 2:
                    issues.append(
                        f"Height mismatch: header says {height}px but file size suggests {calculated_height}px ({calculated_height - height} rows hidden)"
                    )

            if issues:
                severity = "critical" if any("BAD0" in issue for issue in issues) else "error"
                return Contradiction(
                    severity=severity,
                    claimed_format="bmp",
                    issue="Corrupted or tampered BMP header",
                    details="; ".join(issues),
                    category="header_corruption",
                )

        except Exception as e:
            logger.debug(f"BMP header check failed: {e}")

        return None

    @staticmethod
    def detect_all(data: bytes, primary_format: str, **context) -> list[Contradiction]:
        """Run all contradiction checks and return findings."""
        contradictions = []

        # Format-specific checks
        if primary_format == "png":
            contradiction = ContradictionDetector.check_png_header(data)
            if contradiction:
                contradictions.append(contradiction)

            contradiction = ContradictionDetector.check_png_compression(data)
            if contradiction:
                contradictions.append(contradiction)

        elif primary_format == "bmp":
            contradiction = ContradictionDetector.check_bmp_header(data)
            if contradiction:
                contradictions.append(contradiction)

        elif primary_format == "jpeg":
            contradiction = ContradictionDetector.check_jpeg_structure(data)
            if contradiction:
                contradictions.append(contradiction)

        elif primary_format == "pdf":
            contradiction = ContradictionDetector.check_pdf_structure(data)
            if contradiction:
                contradictions.append(contradiction)

        elif primary_format in ["docx", "xlsx", "pptx"]:
            # Check OOXML structure if we have namelist
            namelist = context.get("namelist", [])
            if namelist:
                contradiction = ContradictionDetector.check_zip_ooxml_structure(data, namelist)
                if contradiction:
                    contradictions.append(contradiction)

        elif primary_format == "zip":
            contradiction = ContradictionDetector.check_zip_structure_integrity(data)
            if contradiction:
                contradictions.append(contradiction)

        # Universal checks
        # Check for embedded executables (malware triage)
        if primary_format in ["zip", "docx", "xlsx", "pptx", "pdf", "png", "jpeg"]:
            embedded = ContradictionDetector.check_embedded_formats(data, primary_format)
            contradictions.extend(embedded)

        return contradictions
