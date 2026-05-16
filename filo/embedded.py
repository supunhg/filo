"""
Embedded Object Detection

Detects files hidden inside other files - critical for malware analysis.

Examples:
- ZIP inside EXE (malware droppers)
- PNG appended after EOF (steganography)
- PDF with embedded executables (exploits)
- Multiple formats in one file (polyglots)

Author: Filo Forensics Team
"""

import logging
from typing import Optional

from filo.formats import FormatDatabase
from filo.models import FormatSpec, EmbeddedObject

logger = logging.getLogger(__name__)


class EmbeddedDetector:
    """
    Detects files embedded within other files.
    
    Scans entire file for signatures at arbitrary offsets,
    detects overlays, and identifies polyglot files.
    """
    
    # Format exclusion rules: formats to skip when inside certain parent formats
    EXCLUSION_RULES = {
        'elf': {'wasm', 'ico', 'text', 'markdown'},  # ELF binaries have random byte patterns
        'pe': {'wasm', 'ico', 'text', 'markdown'},   # PE executables have random byte patterns
        'dll': {'wasm', 'ico', 'text', 'markdown'},
        'class': {'wasm', 'ico', 'text'},            # Java bytecode
        'dex': {'wasm', 'ico', 'text'},              # Android DEX files
        'text': {'text', 'markdown'},                # Don't report text inside text
        'markdown': {'text', 'markdown'},
    }
    
    def __init__(self, formats_db: Optional[FormatDatabase] = None):
        """
        Initialize embedded object detector.
        
        Args:
            formats_db: Format database (creates new if None)
        """
        self.formats_db = formats_db or FormatDatabase()
        
    def detect_embedded(
        self, 
        data: bytes, 
        min_confidence: float = 0.75,
        skip_primary: bool = True,
        parent_format: Optional[str] = None
    ) -> list[EmbeddedObject]:
        """
        Detect all embedded objects in binary data.
        
        Args:
            data: Binary data to scan
            min_confidence: Minimum confidence threshold (0.0-1.0)
            skip_primary: Skip signature at offset 0 (primary format)
            
        Returns:
            List of detected embedded objects, sorted by offset
        """
        if not data or len(data) < 4:
            return []
        
        embedded_objects: list[EmbeddedObject] = []
        
        # Scan for all known signatures at any offset
        for format_name in self.formats_db.list_formats():
            spec = self.formats_db.get_format(format_name)
            if not spec or not spec.signatures:
                continue
            
            # Skip formats excluded for this parent format
            if parent_format and parent_format in self.EXCLUSION_RULES:
                if format_name in self.EXCLUSION_RULES[parent_format]:
                    continue
            
            # Check each signature
            for sig_spec in spec.signatures:
                if not sig_spec.hex:
                    continue
                
                # Find all occurrences of this signature
                magic_bytes = bytes.fromhex(sig_spec.hex.replace(" ", ""))
                offset = 0
                
                while offset < len(data):
                    offset = data.find(magic_bytes, offset)
                    if offset == -1:
                        break
                    
                    # Skip offset 0 if requested (primary format handled elsewhere)
                    if skip_primary and offset == 0:
                        offset += 1
                        continue
                    
                    # Estimate size first (needed for validation)
                    size = self._estimate_size(data, offset, spec)
                    
                    # Skip if insufficient data remaining
                    min_size = self._get_minimum_size(spec)
                    if len(data) - offset < min_size:
                        offset += 1
                        continue
                    
                    # Calculate confidence based on signature quality
                    confidence = self._calculate_confidence(
                        data, offset, spec, sig_spec, size
                    )
                    
                    if confidence >= min_confidence:
                        # Extract data snippet for verification
                        snippet = data[offset:offset + 16]
                        
                        # Auto-generate description
                        size_str = f"{size} bytes" if size else "unknown size"
                        description = f"{format_name.upper()} at offset 0x{offset:X} ({size_str})"
                        
                        embedded_obj = EmbeddedObject(
                            offset=offset,
                            format=format_name,
                            confidence=confidence,
                            size=size,
                            description=description,
                            data_snippet=snippet
                        )
                        
                        embedded_objects.append(embedded_obj)
                        logger.debug(f"Found embedded {format_name} at 0x{offset:X} (conf: {confidence:.0%})")
                    
                    offset += 1
        
        # Deduplicate overlapping detections (keep highest confidence)
        embedded_objects = self._deduplicate(embedded_objects)
        
        # Sort by offset
        embedded_objects.sort(key=lambda x: x.offset)
        
        return embedded_objects
    
    def detect_overlay(self, data: bytes, primary_format: str) -> Optional[EmbeddedObject]:
        """
        Detect overlay (data appended after logical EOF).
        
        Common in malware where executables have ZIP/RAR appended.
        
        Args:
            data: Binary data to check
            primary_format: Primary file format (e.g., 'pe', 'elf')
            
        Returns:
            EmbeddedObject if overlay detected, None otherwise
        """
        spec = self.formats_db.get_format(primary_format)
        if not spec:
            return None
        
        # Get logical EOF based on format
        eof_offset = self._get_logical_eof(data, spec)
        if eof_offset is None or eof_offset >= len(data):
            return None
        
        # Check if there's significant data after EOF
        overlay_data = data[eof_offset:]
        if len(overlay_data) < 512:  # Ignore small trailing data
            return None
        
        # Try to detect what the overlay contains
        overlay_objects = self.detect_embedded(overlay_data, skip_primary=False)
        
        if overlay_objects:
            # Adjust offset to be relative to original file
            obj = overlay_objects[0]
            return EmbeddedObject(
                offset=eof_offset + obj.offset,
                format=obj.format,
                confidence=obj.confidence,
                size=obj.size,
                description=f"Overlay: {obj.format.upper()} appended after EOF",
                data_snippet=obj.data_snippet
            )
        else:
            # Unknown overlay data
            return EmbeddedObject(
                offset=eof_offset,
                format="unknown",
                confidence=0.50,
                size=len(overlay_data),
                description=f"Unknown overlay data ({len(overlay_data)} bytes)",
                data_snippet=overlay_data[:16]
            )
    
    def _calculate_confidence(
        self, 
        data: bytes, 
        offset: int, 
        spec: FormatSpec, 
        sig_spec,
        size: Optional[int] = None
    ) -> float:
        """
        Calculate confidence for embedded object detection.
        
        Factors:
        - Signature strength (length, uniqueness)
        - Structural validation (if available)
        - Context (alignment, surrounding data)
        - Size reasonableness
        """
        confidence = 0.70  # Base confidence for signature match
        
        # Boost for longer signatures
        magic_bytes = bytes.fromhex(sig_spec.hex.replace(" ", ""))
        if len(magic_bytes) >= 8:
            confidence += 0.15
        elif len(magic_bytes) >= 6:
            confidence += 0.10
        elif len(magic_bytes) >= 4:
            confidence += 0.05
        
        # Boost for aligned offsets (many formats prefer alignment)
        if offset % 512 == 0:
            confidence += 0.05
        elif offset % 16 == 0:
            confidence += 0.02
        
        # Penalize very short signatures (2-3 bytes) - too many false positives
        if len(magic_bytes) <= 3:
            confidence -= 0.15
        
        # Boost if size is known and reasonable
        if size and 512 <= size <= 10_000_000:  # Between 512 bytes and 10MB
            confidence += 0.05
        
        # Validate structure if possible
        if spec.format == "zip":
            # Check for valid ZIP structure
            if self._validate_zip_structure(data[offset:]):
                confidence += 0.10
        elif spec.format == "pe":
            # Check for valid PE header
            if self._validate_pe_structure(data[offset:]):
                confidence += 0.10
        elif spec.format == "elf":
            # Check for valid ELF header
            if self._validate_elf_structure(data[offset:]):
                confidence += 0.10
        
        return min(confidence, 0.99)  # Cap at 99%
    
    def _validate_zip_structure(self, data: bytes) -> bool:
        """Quick validation of ZIP structure."""
        if len(data) < 30:
            return False
        
        # Check local file header signature
        if data[:4] != b'PK\x03\x04':
            return False
        
        # Check version needed
        version = int.from_bytes(data[4:6], 'little')
        if version > 100:  # Unreasonably high version
            return False
        
        return True
    
    def _validate_pe_structure(self, data: bytes) -> bool:
        """Quick validation of PE structure."""
        if len(data) < 64:
            return False
        
        # Check MZ signature
        if data[:2] != b'MZ':
            return False
        
        # Check PE offset
        pe_offset = int.from_bytes(data[60:64], 'little')
        if pe_offset > len(data) or pe_offset < 64:
            return False
        
        # Check PE signature if within bounds
        if pe_offset + 4 <= len(data):
            if data[pe_offset:pe_offset + 4] != b'PE\x00\x00':
                return False
        
        return True
    
    def _validate_elf_structure(self, data: bytes) -> bool:
        """Quick validation of ELF structure."""
        if len(data) < 52:
            return False
        
        # Check ELF magic
        if data[:4] != b'\x7fELF':
            return False
        
        # Check class (32-bit or 64-bit)
        if data[4] not in (1, 2):
            return False
        
        # Check data encoding (little/big endian)
        if data[5] not in (1, 2):
            return False
        
        return True
    
    def _estimate_size(self, data: bytes, offset: int, spec: FormatSpec) -> Optional[int]:
        """
        Estimate size of embedded object.
        
        Some formats have size headers, others need heuristics.
        """
        remaining = data[offset:]
        
        # Format-specific size extraction
        if spec.format == "zip" and len(remaining) >= 30:
            # ZIP has compressed/uncompressed size in local header
            # This is a simplification - full ZIP parsing is complex
            compressed_size = int.from_bytes(remaining[18:22], 'little')
            if 0 < compressed_size < len(remaining):
                return compressed_size + 30  # Header + data
        
        elif spec.format == "png" and len(remaining) >= 8:
            # PNG chunks have length prefix
            # Scan for IEND chunk to find end
            pos = 8  # Skip PNG signature
            while pos + 12 < len(remaining):
                chunk_len = int.from_bytes(remaining[pos:pos + 4], 'big')
                chunk_type = remaining[pos + 4:pos + 8]
                
                if chunk_type == b'IEND':
                    return pos + 12
                
                pos += 12 + chunk_len
                if chunk_len > 10_000_000:  # Sanity check
                    break
        
        elif spec.format in ("pe", "elf") and len(remaining) >= 64:
            # Executables have size in headers
            if spec.format == "pe":
                # PE size is in optional header
                pe_offset = int.from_bytes(remaining[60:64], 'little')
                if pe_offset + 24 <= len(remaining):
                    size_of_image = int.from_bytes(
                        remaining[pe_offset + 80:pe_offset + 84], 'little'
                    )
                    if 0 < size_of_image < len(remaining):
                        return size_of_image
            elif spec.format == "elf":
                # ELF has program headers and section headers
                # This is a simplification
                pass
        
        # Default: unknown size
        return None
    
    def _get_minimum_size(self, spec: FormatSpec) -> int:
        """
        Get minimum valid size for a format.
        
        Helps filter out false positives where signature appears
        but there's insufficient data for a valid file.
        """
        min_sizes = {
            'zip': 30,      # Local file header minimum
            'png': 57,      # Signature + IHDR + IEND minimum
            'jpeg': 128,    # Reasonable JPEG minimum
            'pdf': 256,     # Minimal PDF structure
            'pe': 512,      # PE header + minimal code
            'elf': 52,      # ELF header minimum (32-bit)
            'gif': 800,     # GIF header + minimal image data
            'bmp': 54,      # BMP header minimum
            'wasm': 8,      # WASM header (often false positive)
            'ico': 22,      # ICO header (often false positive)
            'text': 20,     # Reasonable text minimum
            'markdown': 20,
        }
        
        return min_sizes.get(spec.format, 16)  # Default 16 bytes
    
    def _get_logical_eof(self, data: bytes, spec: FormatSpec) -> Optional[int]:
        """
        Get logical end-of-file offset for a format.
        
        Where the format structure ends, not physical file size.
        """
        if spec.format == "pe":
            # PE file size from SizeOfImage
            if len(data) < 64:
                return None
            
            pe_offset = int.from_bytes(data[60:64], 'little')
            if pe_offset + 84 > len(data):
                return None
            
            size_of_image = int.from_bytes(data[pe_offset + 80:pe_offset + 84], 'little')
            if 0 < size_of_image < len(data):
                return size_of_image
        
        elif spec.format == "elf":
            # ELF file size from section headers
            # Simplified - just return None for now
            pass
        
        elif spec.format == "zip":
            # ZIP end is EOCD (End of Central Directory)
            # Scan backwards for EOCD signature
            eocd_sig = b'PK\x05\x06'
            offset = data.rfind(eocd_sig)
            if offset != -1:
                return offset + 22  # EOCD is 22 bytes minimum
        
        return None
    
    def _deduplicate(self, objects: list[EmbeddedObject]) -> list[EmbeddedObject]:
        """
        Remove duplicate detections at same/nearby offsets.
        
        Keeps highest confidence detection when multiple formats
        match at the same location.
        """
        if not objects:
            return []
        
        # Sort by offset, then by confidence (descending)
        objects.sort(key=lambda x: (x.offset, -x.confidence))
        
        deduplicated = []
        last_offset = -1000
        
        for obj in objects:
            # Consider offsets within 16 bytes as duplicates
            if obj.offset - last_offset > 16:
                deduplicated.append(obj)
                last_offset = obj.offset
        
        return deduplicated
