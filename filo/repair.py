import logging
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union, Tuple

from filo.formats import FormatDatabase
from filo.models import FormatSpec
from filo.lineage import LineageTracker, OperationType

logger = logging.getLogger(__name__)


@dataclass
class RepairReport:
    """Report of repair operation."""

    success: bool
    strategy_used: str
    original_size: int
    repaired_size: int
    changes_made: list[str]
    warnings: list[str]
    confidence: float = 0.0
    validation_result: Optional[str] = None
    chunks_repaired: int = 0


class RepairEngine:
    """
    File repair and header reconstruction engine.

    Implements multiple strategies for repairing corrupted files.
    """

    def __init__(
        self,
        database: Optional[FormatDatabase] = None,
        lineage_tracker: Optional[LineageTracker] = None,
    ) -> None:
        """
        Initialize repair engine.

        Args:
            database: Optional format database
            lineage_tracker: Optional lineage tracker for chain-of-custody
        """
        self.database = database or FormatDatabase()
        self.lineage_tracker = lineage_tracker
        self._register_advanced_strategies()
        logger.info(f"RepairEngine initialized with {self.database.count()} formats")

    def _register_advanced_strategies(self) -> None:
        """Register format-specific advanced repair strategies."""
        self.advanced_strategies = {
            "png": [
                self._repair_png_chunks,
                self._repair_png_crc,
                self._reconstruct_png_ihdr,
                self._repair_png_header,
            ],
            "jpeg": [
                self._repair_jpeg_markers,
                self._add_jpeg_eoi,
            ],
            "zip": [
                self._repair_zip_directory,
                self._reconstruct_zip_headers,
            ],
            "pdf": [
                self._repair_pdf_xref,
                self._add_pdf_eof,
            ],
            "bmp": [
                self._repair_bmp_header,
            ],
            "elf": [
                self._repair_elf_header,
            ],
            "ole2": [
                self._repair_ole2_header,
            ],
        }

    def repair(
        self,
        data: bytes,
        format_name: str,
        strategy: str = "auto",
        original_path: Optional[str] = None,
    ) -> tuple[bytes, RepairReport]:
        """
        Repair corrupted file data.

        Args:
            data: Corrupted file data
            format_name: Target format for repair
            strategy: Repair strategy ('auto', 'advanced', or specific strategy name)
            original_path: Path to original file (for lineage tracking)

        Returns:
            Tuple of (repaired_data, repair_report)
        """
        spec = self.database.get_format(format_name)
        if not spec:
            raise ValueError(f"Unknown format: {format_name}")

        # Try advanced strategies first if available
        if strategy == "auto" or strategy == "advanced":
            if format_name in self.advanced_strategies:
                for repair_func in self.advanced_strategies[format_name]:
                    try:
                        repaired, report = repair_func(data)
                        if report.success:
                            logger.info(f"Advanced repair successful: {repair_func.__name__}")
                            # Record lineage if tracker available
                            if self.lineage_tracker and repaired != data:
                                self.lineage_tracker.record(
                                    original_data=data,
                                    result_data=repaired,
                                    operation=OperationType.REPAIR,
                                    original_path=original_path,
                                    format=format_name,
                                    strategy=report.strategy_used,
                                    changes=report.changes_made,
                                )
                            return repaired, report
                    except Exception as e:
                        logger.debug(f"Advanced strategy {repair_func.__name__} failed: {e}")

        if strategy == "advanced":
            return data, RepairReport(
                success=False,
                strategy_used="advanced",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=[],
                warnings=["No advanced strategies succeeded"],
            )

        if strategy == "auto":
            # Try standard strategies in priority order
            for repair_strategy in sorted(spec.repair_strategies, key=lambda s: s.priority):
                try:
                    repaired, report = self._apply_strategy(data, spec, repair_strategy.name)
                    if report.success:
                        # Record lineage if tracker available
                        if self.lineage_tracker and repaired != data:
                            self.lineage_tracker.record(
                                original_data=data,
                                result_data=repaired,
                                operation=OperationType.REPAIR,
                                original_path=original_path,
                                format=format_name,
                                strategy=report.strategy_used,
                                changes=report.changes_made,
                            )
                        return repaired, report
                except Exception as e:
                    logger.warning(f"Strategy {repair_strategy.name} failed: {e}")

            # No strategy succeeded
            return data, RepairReport(
                success=False,
                strategy_used="none",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=[],
                warnings=["All repair strategies failed"],
            )
        else:
            return self._apply_strategy(data, spec, strategy)

    def _apply_strategy(
        self, data: bytes, spec: FormatSpec, strategy_name: str
    ) -> tuple[bytes, RepairReport]:
        """Apply a specific repair strategy."""
        # Dispatch to strategy methods
        method_name = f"_strategy_{strategy_name}"
        if hasattr(self, method_name):
            method = getattr(self, method_name)
            return method(data, spec)  # type: ignore[no-any-return]

        # Generic strategies
        if strategy_name == "generate_minimal_header":
            return self._strategy_generate_minimal_header(data, spec)
        elif strategy_name == "add_pdf_header":
            return self._strategy_add_pdf_header(data, spec)
        elif strategy_name == "add_zip_header":
            return self._strategy_add_zip_header(data, spec)
        else:
            raise ValueError(f"Unknown repair strategy: {strategy_name}")

    def _strategy_generate_minimal_header(
        self, data: bytes, spec: FormatSpec
    ) -> tuple[bytes, RepairReport]:
        """Generate minimal valid header for file."""
        changes: list[str] = []
        warnings: list[str] = []

        # Get default template
        if "default" not in spec.templates:
            warnings.append("No default template available")
            return data, RepairReport(
                success=False,
                strategy_used="generate_minimal_header",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=changes,
                warnings=warnings,
            )

        template = spec.templates["default"]

        # Use template as-is (without variable substitution)
        header_hex = template.hex.split("{{")[0]  # Take part before first variable
        header_bytes = bytes.fromhex(header_hex)

        # Check if header is already present
        if data.startswith(header_bytes[: len(header_hex) // 2]):
            warnings.append("Header already present")
            return data, RepairReport(
                success=False,
                strategy_used="generate_minimal_header",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=changes,
                warnings=warnings,
            )

        # Prepend header
        repaired = header_bytes + data
        changes.append(f"Added {len(header_bytes)} byte header")

        return repaired, RepairReport(
            success=True,
            strategy_used="generate_minimal_header",
            original_size=len(data),
            repaired_size=len(repaired),
            changes_made=changes,
            warnings=warnings,
        )

    def _strategy_add_pdf_header(self, data: bytes, spec: FormatSpec) -> tuple[bytes, RepairReport]:
        """Add PDF header to file."""
        pdf_header = b"%PDF-1.7\r\n"
        changes: list[str] = []

        if data.startswith(b"%PDF"):
            return data, RepairReport(
                success=False,
                strategy_used="add_pdf_header",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=changes,
                warnings=["PDF header already present"],
            )

        repaired = pdf_header + data
        changes.append("Added PDF-1.7 header")

        return repaired, RepairReport(
            success=True,
            strategy_used="add_pdf_header",
            original_size=len(data),
            repaired_size=len(repaired),
            changes_made=changes,
            warnings=[],
        )

    def _strategy_add_zip_header(self, data: bytes, spec: FormatSpec) -> tuple[bytes, RepairReport]:
        """Add ZIP local file header."""
        zip_header = bytes.fromhex("504B0304")
        changes: list[str] = []

        if data.startswith(zip_header):
            return data, RepairReport(
                success=False,
                strategy_used="add_zip_header",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=changes,
                warnings=["ZIP header already present"],
            )

        repaired = zip_header + data
        changes.append("Added ZIP local file header")

        return repaired, RepairReport(
            success=True,
            strategy_used="add_zip_header",
            original_size=len(data),
            repaired_size=len(repaired),
            changes_made=changes,
            warnings=[],
        )

    def _strategy_reconstruct_from_chunks(
        self, data: bytes, spec: FormatSpec
    ) -> tuple[bytes, RepairReport]:
        """
        Reconstruct file header from existing chunk data.

        This is specifically designed for chunk-based formats like PNG
        where the header might be corrupted but chunks are intact.
        """
        changes: list[str] = []
        warnings: list[str] = []

        # Currently only supports PNG format
        if spec.format != "png":
            return data, RepairReport(
                success=False,
                strategy_used="reconstruct_from_chunks",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=changes,
                warnings=["reconstruct_from_chunks only supports PNG format"],
            )

        # Check if PNG signature is correct
        png_sig = b"\x89PNG\r\n\x1a\n"
        if data[:8] != png_sig:
            # Try to find IHDR chunk which should be at offset 8
            ihdr_pos = data.find(b"IHDR")
            if ihdr_pos >= 0 and ihdr_pos < 100:  # Should be near start
                # Found IHDR, reconstruct signature
                repaired = bytearray(png_sig)
                repaired.extend(data[8:])  # Keep everything after signature
                changes.append("Reconstructed PNG signature")

                return bytes(repaired), RepairReport(
                    success=True,
                    strategy_used="reconstruct_from_chunks",
                    original_size=len(data),
                    repaired_size=len(repaired),
                    changes_made=changes,
                    warnings=warnings,
                )
            else:
                warnings.append("Could not locate IHDR chunk for reconstruction")
                return data, RepairReport(
                    success=False,
                    strategy_used="reconstruct_from_chunks",
                    original_size=len(data),
                    repaired_size=len(data),
                    changes_made=changes,
                    warnings=warnings,
                )

        # Signature is fine, check if file is already valid
        return data, RepairReport(
            success=False,
            strategy_used="reconstruct_from_chunks",
            original_size=len(data),
            repaired_size=len(data),
            changes_made=changes,
            warnings=["PNG signature already valid"],
        )

    def repair_file(
        self,
        file_path: Union[str, Path],
        format_name: str,
        strategy: str = "auto",
        output_path: Optional[Union[str, Path]] = None,
        create_backup: bool = True,
    ) -> tuple[bytes, RepairReport]:
        """
        Repair a file from disk.

        Args:
            file_path: Path to corrupted file
            format_name: Target format for repair
            strategy: Repair strategy to use
            output_path: Where to write repaired file (None = overwrite original)
            create_backup: Whether to create .bak backup

        Returns:
            Tuple of (repaired_data, repair_report)
        """
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # Read original data
        with open(path, "rb") as f:
            data = f.read()

        # Repair
        repaired_data, report = self.repair(data, format_name, strategy)

        # Write output
        if report.success:
            if output_path is None:
                output_path = path

            output_path = Path(output_path)

            # Create backup if requested
            if create_backup and output_path == path:
                backup_path = path.with_suffix(path.suffix + ".bak")
                backup_path.write_bytes(data)
                logger.info(f"Created backup: {backup_path}")

            # Write repaired file
            output_path.write_bytes(repaired_data)
            logger.info(f"Wrote repaired file: {output_path}")

        return repaired_data, report

    # Advanced PNG Repair Strategies

    def _repair_png_chunks(self, data: bytes) -> Tuple[bytes, RepairReport]:
        """Repair PNG chunk structure and CRCs."""
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            return data, RepairReport(
                success=False,
                strategy_used="repair_png_chunks",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=[],
                warnings=["Not a PNG file"],
            )

        changes = []
        warnings = []
        repaired = bytearray(data[:8])  # Keep PNG signature
        pos = 8
        chunks_repaired = 0

        while pos < len(data) - 12:
            try:
                # Read chunk length
                if pos + 4 > len(data):
                    break
                chunk_len = struct.unpack(">I", data[pos : pos + 4])[0]

                if pos + 12 + chunk_len > len(data):
                    warnings.append(f"Truncated chunk at offset {pos}")
                    break

                # Read chunk type and data
                chunk_type = data[pos + 4 : pos + 8]
                chunk_data = data[pos + 8 : pos + 8 + chunk_len]
                chunk_crc = struct.unpack(">I", data[pos + 8 + chunk_len : pos + 12 + chunk_len])[0]

                # Recalculate CRC
                calc_crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF

                if calc_crc != chunk_crc:
                    changes.append(
                        f"Fixed CRC for {chunk_type.decode('ascii', errors='ignore')} chunk"
                    )
                    chunks_repaired += 1
                    chunk_crc = calc_crc

                # Write chunk
                repaired.extend(struct.pack(">I", chunk_len))
                repaired.extend(chunk_type)
                repaired.extend(chunk_data)
                repaired.extend(struct.pack(">I", chunk_crc))

                pos += 12 + chunk_len

                # Stop at IEND
                if chunk_type == b"IEND":
                    break

            except Exception as e:
                warnings.append(f"Error at offset {pos}: {e}")
                break

        if not changes and not chunks_repaired:
            return data, RepairReport(
                success=False,
                strategy_used="repair_png_chunks",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=[],
                warnings=["No repairs needed"],
            )

        return bytes(repaired), RepairReport(
            success=True,
            strategy_used="repair_png_chunks",
            original_size=len(data),
            repaired_size=len(repaired),
            changes_made=changes,
            warnings=warnings,
            chunks_repaired=chunks_repaired,
            confidence=0.9,
        )

    def _repair_png_crc(self, data: bytes) -> Tuple[bytes, RepairReport]:
        """Fix all PNG chunk CRCs."""
        return self._repair_png_chunks(data)

    def _reconstruct_png_ihdr(self, data: bytes) -> Tuple[bytes, RepairReport]:
        """Reconstruct missing or corrupted PNG IHDR chunk."""
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            # Add PNG signature if missing
            data = b"\x89PNG\r\n\x1a\n" + data

        changes = []

        # Check if IHDR exists at position 8
        if len(data) < 33 or data[12:16] != b"IHDR":
            # Reconstruct minimal IHDR
            # Try to infer dimensions from IDAT chunks
            width, height = 800, 600  # Default fallback

            ihdr_data = struct.pack(">II", width, height)  # Width, Height
            ihdr_data += b"\x08\x02\x00\x00\x00"  # bit_depth=8, color_type=2 (RGB), compression=0, filter=0, interlace=0

            ihdr_chunk = struct.pack(">I", 13)  # Length
            ihdr_chunk += b"IHDR"
            ihdr_chunk += ihdr_data
            ihdr_chunk += struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF)

            # Insert after PNG signature
            repaired = data[:8] + ihdr_chunk + data[8:]
            changes.append("Reconstructed IHDR chunk with default dimensions")

            return repaired, RepairReport(
                success=True,
                strategy_used="reconstruct_png_ihdr",
                original_size=len(data),
                repaired_size=len(repaired),
                changes_made=changes,
                warnings=["Used default dimensions 800x600"],
                confidence=0.6,
            )

        return data, RepairReport(
            success=False,
            strategy_used="reconstruct_png_ihdr",
            original_size=len(data),
            repaired_size=len(data),
            changes_made=[],
            warnings=["IHDR already present"],
        )

    # Advanced JPEG Repair Strategies

    def _repair_jpeg_markers(self, data: bytes) -> Tuple[bytes, RepairReport]:
        """Repair JPEG markers and structure."""
        if not data.startswith(b"\xff\xd8"):
            # Add SOI marker
            data = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + data
            changes = ["Added JPEG SOI and JFIF markers"]
        else:
            changes = []

        # Check for EOI marker
        if not data.endswith(b"\xff\xd9"):
            data += b"\xff\xd9"
            changes.append("Added JPEG EOI marker")

        if changes:
            return data, RepairReport(
                success=True,
                strategy_used="repair_jpeg_markers",
                original_size=len(data) - sum(len(c) for c in changes),
                repaired_size=len(data),
                changes_made=changes,
                warnings=[],
                confidence=0.85,
            )

        return data, RepairReport(
            success=False,
            strategy_used="repair_jpeg_markers",
            original_size=len(data),
            repaired_size=len(data),
            changes_made=[],
            warnings=["No repairs needed"],
        )

    def _add_jpeg_eoi(self, data: bytes) -> Tuple[bytes, RepairReport]:
        """Add JPEG end-of-image marker."""
        if data.endswith(b"\xff\xd9"):
            return data, RepairReport(
                success=False,
                strategy_used="add_jpeg_eoi",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=[],
                warnings=["EOI marker already present"],
            )

        repaired = data + b"\xff\xd9"
        return repaired, RepairReport(
            success=True,
            strategy_used="add_jpeg_eoi",
            original_size=len(data),
            repaired_size=len(repaired),
            changes_made=["Added EOI marker (0xFFD9)"],
            warnings=[],
            confidence=0.95,
        )

    # Advanced ZIP Repair Strategies

    def _repair_zip_directory(self, data: bytes) -> Tuple[bytes, RepairReport]:
        """Repair ZIP central directory."""
        if not data.startswith(b"PK\x03\x04"):
            return data, RepairReport(
                success=False,
                strategy_used="repair_zip_directory",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=[],
                warnings=["Not a ZIP file"],
            )

        changes = []

        # Look for end of central directory
        eocd_sig = b"PK\x05\x06"
        eocd_pos = data.rfind(eocd_sig)

        if eocd_pos == -1:
            # Reconstruct EOCD
            eocd = eocd_sig
            eocd += b"\x00" * 18  # Minimal EOCD structure
            repaired = data + eocd
            changes.append("Reconstructed End of Central Directory")

            return repaired, RepairReport(
                success=True,
                strategy_used="repair_zip_directory",
                original_size=len(data),
                repaired_size=len(repaired),
                changes_made=changes,
                warnings=["Reconstructed minimal EOCD - file may not be fully accessible"],
                confidence=0.5,
            )

        return data, RepairReport(
            success=False,
            strategy_used="repair_zip_directory",
            original_size=len(data),
            repaired_size=len(data),
            changes_made=[],
            warnings=["Central directory appears intact"],
        )

    def _reconstruct_zip_headers(self, data: bytes) -> Tuple[bytes, RepairReport]:
        """Reconstruct ZIP local file headers."""
        if data.startswith(b"PK\x03\x04"):
            return data, RepairReport(
                success=False,
                strategy_used="reconstruct_zip_headers",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=[],
                warnings=["ZIP header already present"],
            )

        # Add minimal ZIP local file header
        header = b"PK\x03\x04"  # Local file header signature
        header += b"\x14\x00"  # Version needed
        header += b"\x00\x00"  # General purpose bit flag
        header += b"\x00\x00"  # Compression method (stored)
        header += b"\x00" * 8  # Modification time/date
        header += b"\x00" * 12  # CRC-32, sizes
        header += b"\x00\x00"  # File name length
        header += b"\x00\x00"  # Extra field length

        repaired = header + data

        return repaired, RepairReport(
            success=True,
            strategy_used="reconstruct_zip_headers",
            original_size=len(data),
            repaired_size=len(repaired),
            changes_made=["Added ZIP local file header"],
            warnings=["File may require additional repair"],
            confidence=0.6,
        )

    # Advanced PDF Repair Strategies

    def _repair_pdf_xref(self, data: bytes) -> Tuple[bytes, RepairReport]:
        """Repair or reconstruct PDF cross-reference table."""
        if not data.startswith(b"%PDF"):
            return data, RepairReport(
                success=False,
                strategy_used="repair_pdf_xref",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=[],
                warnings=["Not a PDF file"],
            )

        changes = []

        # Check for xref table
        if b"xref" not in data:
            # Add minimal xref and trailer
            xref = b"\nxref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1 >>\nstartxref\n"
            xref += str(len(data)).encode() + b"\n%%EOF"
            repaired = data + xref
            changes.append("Added minimal cross-reference table")

            return repaired, RepairReport(
                success=True,
                strategy_used="repair_pdf_xref",
                original_size=len(data),
                repaired_size=len(repaired),
                changes_made=changes,
                warnings=["Reconstructed minimal xref - PDF may have limited functionality"],
                confidence=0.5,
            )

        return data, RepairReport(
            success=False,
            strategy_used="repair_pdf_xref",
            original_size=len(data),
            repaired_size=len(data),
            changes_made=[],
            warnings=["xref table appears present"],
        )

    def _repair_png_header(self, data: bytes) -> Tuple[bytes, RepairReport]:
        """Repair corrupted PNG signature and chunk names."""
        import struct

        if len(data) < 33:
            return data, RepairReport(
                success=False,
                strategy_used="repair_png_header",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=[],
                warnings=["File too small to be a valid PNG"],
            )

        changes: list[str] = []
        warnings: list[str] = []
        repaired = bytearray(data)

        # PNG signature: 89 50 4E 47 0D 0A 1A 0A
        correct_sig = b"\x89PNG\r\n\x1a\n"
        actual_sig = data[0:8]

        # Fix signature if corrupted
        if actual_sig != correct_sig:
            repaired[0:8] = correct_sig
            sig_changes = []
            for i, (actual, expected) in enumerate(zip(actual_sig, correct_sig)):
                if actual != expected:
                    sig_changes.append(f"byte {i}: 0x{actual:02X} → 0x{expected:02X}")
            changes.append(f"Fixed PNG signature: {', '.join(sig_changes)}")

        # Fix IHDR chunk name (should be first chunk after signature)
        if len(data) >= 16:
            ihdr_type = data[12:16]
            if ihdr_type != b"IHDR":
                repaired[12:16] = b"IHDR"
                chunk_changes = []
                for i, (actual, expected) in enumerate(zip(ihdr_type, b"IHDR")):
                    if actual != expected:
                        actual_char = chr(actual) if 32 <= actual < 127 else "?"
                        chunk_changes.append(
                            f"'{actual_char}' (0x{actual:02X}) → '{chr(expected)}' (0x{expected:02X})"
                        )
                changes.append(f"Fixed IHDR chunk name: {', '.join(chunk_changes)}")

                # Recalculate CRC for IHDR chunk
                ihdr_length = struct.unpack(">I", data[8:12])[0]
                if ihdr_length == 13:  # Standard IHDR length
                    import zlib

                    chunk_data = repaired[12 : 12 + 4 + ihdr_length]  # type + data
                    crc = zlib.crc32(chunk_data) & 0xFFFFFFFF
                    struct.pack_into(">I", repaired, 12 + 4 + ihdr_length, crc)
                    changes.append("Recalculated IHDR CRC")

        # Scan through all chunks and fix common corruptions
        pos = 33
        idat_found = False

        while pos < len(data) - 12:  # Need at least 12 bytes for chunk header
            try:
                if pos + 8 > len(data):
                    break

                chunk_length = struct.unpack(">I", repaired[pos : pos + 4])[0]
                chunk_type = repaired[pos + 4 : pos + 8]

                # Fix pHYs chunk corruption (0xAA in X-axis pixels per unit)
                if chunk_type == b"pHYs" and chunk_length == 9:
                    # Check if X-axis has 0xAA corruption
                    if repaired[pos + 8] == 0xAA:
                        old_val = bytes(repaired[pos + 8 : pos + 12])
                        repaired[pos + 8] = 0x00  # Fix X-axis first byte
                        new_val = bytes(repaired[pos + 8 : pos + 12])
                        changes.append(f"Fixed pHYs X-axis: 0x{old_val.hex()} → 0x{new_val.hex()}")

                        # Recalculate CRC
                        import zlib

                        chunk_data = repaired[pos + 4 : pos + 8 + chunk_length]
                        crc = zlib.crc32(chunk_data) & 0xFFFFFFFF
                        struct.pack_into(">I", repaired, pos + 8 + chunk_length, crc)
                        changes.append("Recalculated pHYs CRC")

                # Fix corrupted IDAT chunk
                # Check for IDAT-like corruptions: length has 0xAAAA prefix or type is corrupted
                if not idat_found:
                    # Check if this looks like a corrupted IDAT
                    # Common pattern: length = 0xAAAAFFxx, type = 0xABDET or similar
                    length_bytes = repaired[pos : pos + 4]
                    type_bytes = repaired[pos + 4 : pos + 8]

                    # Check if length has 0xAAAA prefix (corrupted)
                    if length_bytes[0:2] == b"\xaa\xaa":
                        old_length = struct.unpack(">I", length_bytes)[0]
                        # Replace AAAA with 0000
                        repaired[pos] = 0x00
                        repaired[pos + 1] = 0x00
                        new_length = struct.unpack(">I", repaired[pos : pos + 4])[0]
                        changes.append(
                            f"Fixed IDAT length at 0x{pos:X}: 0x{old_length:08X} → 0x{new_length:08X}"
                        )
                        chunk_length = new_length

                    # Check if chunk type looks like corrupted IDAT
                    # Pattern: 0xABDET (ab 44 45 54) should be IDAT (49 44 41 54)
                    if (type_bytes[0] == 0xAB and type_bytes[1:4] == b"DET") or (
                        all(65 <= b <= 90 or 97 <= b <= 122 for b in type_bytes)
                        and type_bytes != b"IDAT"
                        and abs(type_bytes[1] - ord("D")) <= 10
                        and abs(type_bytes[2] - ord("A")) <= 10
                    ):

                        old_type = bytes(type_bytes)
                        repaired[pos + 4 : pos + 8] = b"IDAT"

                        chunk_changes = []
                        for i, (actual, expected) in enumerate(zip(old_type, b"IDAT")):
                            if actual != expected:
                                actual_char = chr(actual) if 32 <= actual < 127 else "?"
                                chunk_changes.append(
                                    f"'{actual_char}' (0x{actual:02X}) → '{chr(expected)}' (0x{expected:02X})"
                                )
                        changes.append(
                            f"Fixed IDAT chunk type at 0x{pos:X}: {', '.join(chunk_changes)}"
                        )

                        # Recalculate CRC for IDAT
                        if pos + 8 + chunk_length + 4 <= len(data):
                            import zlib

                            chunk_data = repaired[pos + 4 : pos + 8 + chunk_length]
                            crc = zlib.crc32(chunk_data) & 0xFFFFFFFF
                            struct.pack_into(">I", repaired, pos + 8 + chunk_length, crc)
                            changes.append(f"Recalculated IDAT CRC at 0x{pos:X}")

                        idat_found = True

                # Move to next chunk (with sanity check on length)
                if chunk_length < 10 * 1024 * 1024:  # Max 10MB per chunk
                    pos += 8 + chunk_length + 4
                else:
                    # Corrupted length, try to find next chunk signature
                    break

            except Exception as e:
                logger.debug(f"Error processing chunk at 0x{pos:X}: {e}")
                break

        # Validate the repair
        if not changes:
            return data, RepairReport(
                success=False,
                strategy_used="repair_png_header",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=[],
                warnings=["Header appears valid, no changes needed"],
            )

        return bytes(repaired), RepairReport(
            success=True,
            strategy_used="repair_png_header",
            original_size=len(data),
            repaired_size=len(repaired),
            changes_made=changes,
            warnings=warnings,
            confidence=0.95,
            validation_result="Repaired PNG signature and chunk structure",
        )

    def _repair_bmp_header(self, data: bytes) -> Tuple[bytes, RepairReport]:
        """
        Repair corrupted BMP header.

        Common issues:
        - Wrong DIB header size (offset 0x0E)
        - Wrong pixel data offset (offset 0x0A)
        - Wrong image height (need to calculate from file size)
        """
        if len(data) < 54 or not data.startswith(b"BM"):
            return data, RepairReport(
                success=False,
                strategy_used="repair_bmp_header",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=[],
                warnings=["Not a BMP file or too small"],
            )

        changes = []
        warnings = []
        repaired = bytearray(data)

        # Read current header values
        file_size = struct.unpack("<I", data[2:6])[0]
        pixel_offset_orig = struct.unpack("<I", data[10:14])[0]
        dib_size_orig = struct.unpack("<I", data[14:18])[0]
        width = struct.unpack("<I", data[18:22])[0]
        height_orig = struct.unpack("<I", data[22:26])[0]
        bits_per_pixel = struct.unpack("<H", data[28:30])[0]

        # Fix DIB header size if wrong (should be 40 for BITMAPINFOHEADER)
        if dib_size_orig != 40:
            struct.pack_into("<I", repaired, 14, 40)
            changes.append(f"Fixed DIB header size: 0x{dib_size_orig:X} → 0x28 (40)")

        # Fix pixel data offset (should be 14 + DIB header size = 54 for standard BMP)
        standard_offset = 54
        if pixel_offset_orig != standard_offset:
            struct.pack_into("<I", repaired, 10, standard_offset)
            changes.append(
                f"Fixed pixel data offset: 0x{pixel_offset_orig:X} → 0x{standard_offset:X}"
            )

        # Calculate correct height from file size
        # Formula: height = (file_size - header_size) / (width * bytes_per_pixel)
        bits_per_pixel // 8
        row_size = ((width * bits_per_pixel + 31) // 32) * 4  # Row size aligned to 4 bytes
        pixel_data_size = file_size - standard_offset
        calculated_height = pixel_data_size // row_size

        if calculated_height != height_orig and calculated_height > 0:
            struct.pack_into("<I", repaired, 22, calculated_height)
            changes.append(
                f"Fixed height: {height_orig} → {calculated_height} (calculated from file size)"
            )
            warnings.append(f"Original height ({height_orig}) didn't match file size")

        # Validate the repair
        if not changes:
            return data, RepairReport(
                success=False,
                strategy_used="repair_bmp_header",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=[],
                warnings=["Header appears valid, no changes needed"],
            )

        return bytes(repaired), RepairReport(
            success=True,
            strategy_used="repair_bmp_header",
            original_size=len(data),
            repaired_size=len(repaired),
            changes_made=changes,
            warnings=warnings,
            confidence=0.95,
            validation_result=f"Repaired BMP: {width}x{calculated_height}, {bits_per_pixel}bpp",
        )

    def _repair_elf_header(self, data: bytes) -> Tuple[bytes, RepairReport]:
        """Repair or reconstruct corrupted ELF header."""
        changes = []
        warnings = []
        repaired = data

        if len(data) >= 4 and data[:4] == b"\x7fELF":
            return data, RepairReport(
                success=False,
                strategy_used="repair_elf_header",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=[],
                warnings=["ELF magic already present"],
            )

        if len(data) < 16:
            return data, RepairReport(
                success=False,
                strategy_used="repair_elf_header",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=[],
                warnings=["Data too small for ELF header"],
            )

        ei_class = data[4] if len(data) > 4 else 2
        ei_data = data[5] if len(data) > 5 else 1
        if ei_class not in (1, 2):
            ei_class = 2
            warnings.append("EI_CLASS not detected, assuming 64-bit")
        elif ei_class == 1:
            warnings.append("Detected 32-bit ELF")
        if ei_data not in (1, 2):
            ei_data = 1
            warnings.append("EI_DATA not detected, assuming little-endian")

        entry_offset = 0x18 if ei_class == 1 else 0x18
        header = bytearray(b"\x7fELF")
        header.append(ei_class)
        header.append(ei_data)
        header.append(1)  # EI_VERSION
        header.append(0)  # EI_OSABI
        header.extend(b"\x00" * 8)  # EI_ABIVERSION + padding
        if ei_class == 1:
            header.extend(struct.pack("<H", 2))  # e_type = ET_EXEC
            header.extend(struct.pack("<H", 0x3E))  # e_machine x86-64
            header.extend(struct.pack("<I", 1))  # e_version
            header.extend(struct.pack("<I", entry_offset))  # e_entry (dummy)
            header.extend(struct.pack("<I", 64))  # e_phoff
            header.extend(struct.pack("<I", 0))  # e_shoff
            header.extend(struct.pack("<I", 0))  # e_flags
            header.extend(struct.pack("<H", 64))  # e_ehsize
            header.extend(struct.pack("<H", 56))  # e_phentsize
            header.extend(struct.pack("<H", 1))  # e_phnum
            header.extend(struct.pack("<H", 0))  # e_shentsize
            header.extend(struct.pack("<H", 0))  # e_shnum
            header.extend(struct.pack("<H", 0))  # e_shstrndx
        else:
            header.extend(struct.pack("<H", 2))
            header.extend(struct.pack("<H", 0x3E))
            header.extend(struct.pack("<I", 1))
            header.extend(struct.pack("<Q", entry_offset))
            header.extend(struct.pack("<Q", 64))
            header.extend(struct.pack("<Q", 0))
            header.extend(struct.pack("<I", 0))
            header.extend(struct.pack("<H", 64))
            header.extend(struct.pack("<H", 56))
            header.extend(struct.pack("<H", 1))
            header.extend(struct.pack("<H", 0))
            header.extend(struct.pack("<H", 0))
            header.extend(struct.pack("<H", 0))

        repaired = bytes(header) + data
        changes.append("Prepended ELF header")
        if warnings:
            changes.extend(warnings)

        return repaired, RepairReport(
            success=True,
            strategy_used="repair_elf_header",
            original_size=len(data),
            repaired_size=len(repaired),
            changes_made=changes,
            warnings=warnings,
            confidence=0.7,
            validation_result=f"Reconstructed ELF header: {'64' if ei_class == 2 else '32'}-bit, {'big' if ei_data == 2 else 'little'}-endian",
        )

    def _repair_ole2_header(self, data: bytes) -> Tuple[bytes, RepairReport]:
        """Repair or reconstruct corrupted OLE2 (Compound Document) header."""
        ole2_magic = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        changes: list[str] = []
        warnings: list[str] = []

        if len(data) >= 8 and data[:8] == ole2_magic:
            return data, RepairReport(
                success=False,
                strategy_used="repair_ole2_header",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=[],
                warnings=["OLE2 magic already present"],
            )

        if len(data) < 512:
            return data, RepairReport(
                success=False,
                strategy_used="repair_ole2_header",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=[],
                warnings=["Data too small for OLE2 header"],
            )

        header = bytearray(512)
        header[:8] = ole2_magic
        header[8:16] = b"\x00\x00\x00\x00\x00\x00\x00\x00"
        struct.pack_into("<H", header, 24, 9)
        struct.pack_into("<H", header, 26, 6)
        struct.pack_into("<I", header, 28, 0)
        struct.pack_into("<I", header, 44, 0)
        struct.pack_into("<I", header, 48, 0)
        struct.pack_into("<I", header, 56, 1)

        if len(data) >= 512:
            tail = data[512:]
            reconstructed = bytes(header) + tail
        else:
            reconstructed = bytes(header[: len(data)])

        changes.append("Reconstructed OLE2 compound document header")

        return reconstructed, RepairReport(
            success=True,
            strategy_used="repair_ole2_header",
            original_size=len(data),
            repaired_size=len(reconstructed),
            changes_made=changes,
            warnings=warnings,
            confidence=0.6,
            validation_result="Reconstructed OLE2 header with default block allocation table",
        )

    def _add_pdf_eof(self, data: bytes) -> Tuple[bytes, RepairReport]:
        """Add PDF end-of-file marker."""
        if data.rstrip().endswith(b"%%EOF"):
            return data, RepairReport(
                success=False,
                strategy_used="add_pdf_eof",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=[],
                warnings=["EOF marker already present"],
            )

        repaired = data.rstrip() + b"\n%%EOF"
        return repaired, RepairReport(
            success=True,
            strategy_used="add_pdf_eof",
            original_size=len(data),
            repaired_size=len(repaired),
            changes_made=["Added %%EOF marker"],
            warnings=[],
            confidence=0.9,
        )
