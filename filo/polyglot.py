"""Polyglot file detection - identifies files valid as multiple formats."""

import struct
import zlib
from typing import List, Optional, Set

from filo.models import PolyglotMatch


class PolyglotDetector:

    def __init__(self):
        self.validators = {
            "png": self._validate_png,
            "gif": self._validate_gif,
            "jpeg": self._validate_jpeg,
            "zip": self._validate_zip,
            "jar": self._validate_jar,
            "rar": self._validate_rar,
            "pdf": self._validate_pdf,
            "pe": self._validate_pe,
            "elf": self._validate_elf,
        }

        self.polyglot_patterns = {
            "gifar": ["gif", "jar"],
            "gifar_rar": ["gif", "rar"],
            "png_zip": ["png", "zip"],
            "jpeg_zip": ["jpeg", "zip"],
            "pdf_js": ["pdf"],
            "pe_zip": ["pe", "zip"],
        }

    def detect_polyglots(
        self, data: bytes, primary_format: Optional[str] = None
    ) -> List[PolyglotMatch]:
        """
        Detect all polyglot format combinations.

        Args:
            data: File data to analyze
            primary_format: Optional hint for primary format

        Returns:
            List of detected polyglot combinations
        """
        polyglots = []

        valid_formats = self._get_valid_formats(data)

        if "pdf" in valid_formats and self._has_js_payload(data):
            polyglots.append(
                PolyglotMatch(
                    formats=sorted(["pdf", "javascript"]),
                    pattern="pdf_js",
                    confidence=0.92,
                    description="PDF with embedded JavaScript payload",
                    risk_level="high",
                    evidence="Valid PDF + JS payload detected",
                )
            )

        if len(valid_formats) < 2:
            return polyglots

        for pattern_name, required_formats in self.polyglot_patterns.items():
            if pattern_name == "pdf_js":
                continue

            if all(fmt in valid_formats for fmt in required_formats):
                confidence = self._calculate_polyglot_confidence(data, required_formats)
                risk = self._assess_risk(pattern_name, required_formats)

                polyglots.append(
                    PolyglotMatch(
                        formats=sorted(required_formats),
                        pattern=pattern_name,
                        confidence=confidence,
                        description=self._get_pattern_description(pattern_name),
                        risk_level=risk,
                        evidence=f"Valid as: {', '.join(required_formats)}",
                    )
                )

        other_combinations = self._find_other_combinations(valid_formats, polyglots)
        polyglots.extend(other_combinations)

        return polyglots

    def _get_valid_formats(self, data: bytes) -> Set[str]:
        """Run all validators and return set of valid formats."""
        valid = set()

        for format_name, validator in self.validators.items():
            try:
                if validator(data):
                    valid.add(format_name)
            except Exception:
                pass

        return valid

    def _validate_png(self, data: bytes) -> bool:
        """Validate PNG format."""
        if len(data) < 33:
            return False

        if data[:8] != b"\x89PNG\r\n\x1a\n":
            return False

        if data[12:16] != b"IHDR":
            return False

        ihdr_crc_expected = struct.unpack(">I", data[29:33])[0]
        ihdr_data = data[12:29]
        ihdr_crc_actual = zlib.crc32(ihdr_data) & 0xFFFFFFFF

        return ihdr_crc_expected == ihdr_crc_actual

    def _validate_gif(self, data: bytes) -> bool:
        """Validate GIF format."""
        if len(data) < 13:
            return False

        if data[:3] not in (b"GIF",):
            return False

        if data[3:6] not in (b"87a", b"89a"):
            return False

        width = struct.unpack("<H", data[6:8])[0]
        height = struct.unpack("<H", data[8:10])[0]

        if width == 0 or height == 0 or width > 65535 or height > 65535:
            return False

        return True

    def _validate_jpeg(self, data: bytes) -> bool:
        """Validate JPEG format."""
        if len(data) < 4:
            return False

        if data[:2] != b"\xff\xd8":
            return False

        pos = 2
        found_sos = False

        while pos < len(data) - 1:
            if data[pos] != 0xFF:
                break

            marker = data[pos + 1]

            if marker == 0xD9:
                return True

            if marker == 0xDA:
                found_sos = True

            if marker in (0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8):
                pos += 2
                continue

            if pos + 3 >= len(data):
                break

            length = struct.unpack(">H", data[pos + 2 : pos + 4])[0]
            pos += 2 + length

        return found_sos

    def _validate_zip(self, data: bytes) -> bool:
        """Validate ZIP format."""
        if len(data) < 22:
            return False

        has_local_header = data[:4] == b"PK\x03\x04"

        eocd_pos = data.rfind(b"PK\x05\x06")
        if eocd_pos == -1:
            return has_local_header

        if len(data) - eocd_pos < 22:
            return has_local_header

        return True

    def _validate_jar(self, data: bytes) -> bool:
        """Validate JAR format (ZIP with manifest)."""
        if not self._validate_zip(data):
            return False

        if b"META-INF/MANIFEST.MF" in data:
            return True

        return False

    def _validate_rar(self, data: bytes) -> bool:
        """Validate RAR format."""
        if len(data) < 7:
            return False

        if data[:7] == b"Rar!\x1a\x07\x00":
            return True

        if data[:8] == b"Rar!\x1a\x07\x01\x00":
            return True

        return False

    def _validate_pdf(self, data: bytes) -> bool:
        """Validate PDF format."""
        if len(data) < 8:
            return False

        if not data[:4] == b"%PDF":
            return False

        if b"%%EOF" in data[-1024:]:
            return True

        return b"/Type" in data[:2048]

    def _validate_pe(self, data: bytes) -> bool:
        """Validate PE format."""
        if len(data) < 64:
            return False

        if data[:2] != b"MZ":
            return False

        pe_offset_pos = 60
        if len(data) < pe_offset_pos + 4:
            return False

        pe_offset = struct.unpack("<I", data[pe_offset_pos : pe_offset_pos + 4])[0]

        if pe_offset == 0 or pe_offset > len(data) - 4:
            return data[:2] == b"MZ"

        if len(data) < pe_offset + 4:
            return data[:2] == b"MZ"

        return data[pe_offset : pe_offset + 2] == b"PE"

    def _validate_elf(self, data: bytes) -> bool:
        """Validate ELF format."""
        if len(data) < 52:
            return False

        if data[:4] != b"\x7fELF":
            return False

        ei_class = data[4]
        if ei_class not in (1, 2):
            return False

        ei_data = data[5]
        if ei_data not in (1, 2):
            return False

        return True

    def _has_js_payload(self, data: bytes) -> bool:
        """Check if PDF contains JavaScript payload."""
        if not self._validate_pdf(data):
            return False

        js_indicators = [
            b"/JavaScript",
            b"/JS",
            b"/AA",
            b"/OpenAction",
            b"eval(",
            b"unescape(",
            b"String.fromCharCode",
        ]

        search_data = data[: min(len(data), 100000)]

        matches = sum(1 for indicator in js_indicators if indicator in search_data)

        return matches >= 2

    def _calculate_polyglot_confidence(self, data: bytes, formats: List[str]) -> float:
        """Calculate confidence score for polyglot detection."""
        base_confidence = 0.85

        validations_passed = sum(
            1 for fmt in formats if fmt in self.validators and self.validators[fmt](data)
        )

        confidence = base_confidence + (validations_passed * 0.03)

        return min(confidence, 0.98)

    def _assess_risk(self, pattern: str, formats: List[str]) -> str:
        """Assess security risk level of polyglot."""
        high_risk_patterns = ["gifar", "gifar_rar", "pdf_js", "pe_zip"]
        medium_risk_patterns = ["png_zip", "jpeg_zip"]

        if pattern in high_risk_patterns:
            return "high"
        elif pattern in medium_risk_patterns:
            return "medium"
        else:
            return "low"

    def _get_pattern_description(self, pattern: str) -> str:
        """Get human-readable description of polyglot pattern."""
        descriptions = {
            "gifar": "GIF + JAR hybrid (GIFAR attack)",
            "gifar_rar": "GIF + RAR hybrid",
            "png_zip": "PNG + ZIP hybrid",
            "jpeg_zip": "JPEG + ZIP hybrid",
            "pdf_js": "PDF with JavaScript payload",
            "pe_zip": "PE executable + ZIP hybrid",
        }
        return descriptions.get(pattern, f"{pattern.upper()} polyglot")

    def _find_other_combinations(
        self, valid_formats: Set[str], existing: List[PolyglotMatch]
    ) -> List[PolyglotMatch]:
        """Find polyglot combinations not covered by known patterns."""
        polyglots = []
        existing_combos = {tuple(sorted(p.formats)) for p in existing}

        format_list = sorted(valid_formats)

        for i, fmt1 in enumerate(format_list):
            for fmt2 in format_list[i + 1 :]:
                combo = tuple(sorted([fmt1, fmt2]))

                if combo not in existing_combos:
                    risk = "medium" if any(f in ["pe", "elf", "pdf"] for f in combo) else "low"

                    polyglots.append(
                        PolyglotMatch(
                            formats=list(combo),
                            pattern=f"{combo[0]}_{combo[1]}",
                            confidence=0.82,
                            description=f"Valid as {combo[0].upper()} and {combo[1].upper()}",
                            risk_level=risk,
                            evidence=f"Dual-format file: {combo[0]}, {combo[1]}",
                        )
                    )

        return polyglots
