"""
LSB Steganography Detection Module

Detects hidden data in images using Least Significant Bit (LSB) analysis.
Pure Python implementation with zsteg-compatible algorithm.
Also detects hidden text in SVG files and metadata in various formats.
"""

import logging
import struct
import zlib
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Optional
from enum import Enum

logger = logging.getLogger(__name__)


class BitOrder(Enum):
    """Bit extraction order."""

    LSB = "lsb"  # Least significant bit first
    MSB = "msb"  # Most significant bit first


class PixelOrder(Enum):
    """Pixel iteration order."""

    XY = "xy"  # Left to right, top to bottom
    YX = "yx"  # Top to bottom, left to right
    XY_REV = "XY"  # Right to left, top to bottom
    YX_REV = "YX"  # Bottom to top, left to right


@dataclass
class StegoResult:
    """Result from steganography detection."""

    method: str
    channel: str
    bit_plane: int
    order: str
    data: bytes
    data_type: str
    description: str
    confidence: float
    offset: int = 0
    size: int = 0


class LSBExtractor:
    """Extract data from LSB of image pixels."""

    def __init__(self):
        self.min_string_len = 8
        self.max_extract_bytes = 1024 * 1024  # 1MB limit

    def extract_bits(
        self,
        data: bytes,
        bits: int = 1,
        order: BitOrder = BitOrder.LSB,
        channels: str = "rgba",
        pixel_order: PixelOrder = PixelOrder.XY,
    ) -> bytes:
        """
        Extract bits from image data using zsteg-compatible algorithm.

        This matches zsteg's exact behavior:
        - LSB order: extract bit 0 from each byte
        - MSB order: extract bit 7 from each byte
        - Bits are packed MSB-first into output bytes

        Args:
            data: Raw pixel data (RGBA format)
            bits: Number of bits to extract per byte (1-8)
            order: LSB or MSB first
            channels: Which channels to use (r, g, b, a, rgb, rgba, etc.)
            pixel_order: Order to traverse pixels

        Returns:
            Extracted bytes
        """
        if not data or bits < 1 or bits > 8:
            return b""

        result_bits = []
        max_bits = min(len(data) * bits, self.max_extract_bytes * 8)

        for i, byte_val in enumerate(data):
            if len(result_bits) >= max_bits:
                break

            # Extract specified number of bits
            if order == BitOrder.LSB:
                # Extract from LSB (bit 0, 1, 2, ...)
                for bit_idx in range(bits):
                    bit = (byte_val >> bit_idx) & 1
                    result_bits.append(bit)
            else:
                # Extract from MSB (bit 7, 6, 5, ...)
                for bit_idx in range(bits):
                    bit = (byte_val >> (7 - bit_idx)) & 1
                    result_bits.append(bit)

        # Convert bits to bytes using MSB-first packing (zsteg's method)
        # In zsteg: when bit_order is :lsb, it does: byte |= (a.shift<<(7-i))
        # This means first extracted bit goes to position 7 (MSB), second to position 6, etc.
        result_bytes = bytearray()
        for i in range(0, len(result_bits), 8):
            if i + 8 <= len(result_bits):
                byte_bits = result_bits[i : i + 8]
                byte_val = 0
                # Pack MSB-first: first bit at position 7, last bit at position 0
                for bit_pos, bit in enumerate(byte_bits):
                    byte_val |= bit << (7 - bit_pos)
                result_bytes.append(byte_val)

        return bytes(result_bytes)

    def pack_bits(self, bits: list[int]) -> bytes:
        """Pack a list of bits into bytes using MSB-first packing.

        Args:
            bits: List of bits (0 or 1)

        Returns:
            Packed bytes
        """
        result_bytes = bytearray()
        for i in range(0, len(bits), 8):
            if i + 8 <= len(bits):
                byte_bits = bits[i : i + 8]
                byte_val = 0
                # Pack MSB-first: first bit at position 7, last bit at position 0
                for bit_pos, bit in enumerate(byte_bits):
                    byte_val |= bit << (7 - bit_pos)
                result_bytes.append(byte_val)

        return bytes(result_bytes)

    def detect_flag_patterns(self, data: bytes) -> Optional[str]:
        """Detect common CTF flag patterns in data.

        Searches for patterns like picoCTF{...}, flag{...}, HTB{...}, etc.
        """
        import re

        try:
            # Decode as much as possible, ignoring errors
            text = data.decode("latin-1")

            # Common flag patterns
            patterns = [
                r"picoCTF\{[^}]{5,}\}",
                r"flag\{[^}]{5,}\}",
                r"FLAG\{[^}]{5,}\}",
                r"HTB\{[^}]{5,}\}",
                r"CTF\{[^}]{5,}\}",
            ]

            for pattern in patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    return match.group()

        except Exception:
            pass

        return None

    def detect_file_type(self, data: bytes) -> Optional[str]:
        """Detect file type from magic bytes (like zsteg does)."""
        if not data or len(data) < 4:
            return None

        # Common file signatures
        signatures = [
            (b"\x89PNG\r\n\x1a\n", "PNG image data"),
            (b"\xff\xd8\xff", "JPEG image data"),
            (b"GIF87a", "GIF image data, version 87a"),
            (b"GIF89a", "GIF image data, version 89a"),
            (b"BM", "PC bitmap"),
            (b"%PDF", "PDF document"),
            (b"PK\x03\x04", "Zip archive data"),
            (b"\x1f\x8b", "gzip compressed data"),
            (b"\x50\x4b\x03\x04", "Zip archive data"),
            (b"Rar!", "RAR archive data"),
            (b"\x7fELF", "ELF"),
            (b"MZ", "DOS/MBR boot sector"),
            (b"\x00\x00\x01\x00", "MS Windows icon resource"),
            # OpenPGP signatures (common in stego)
            (b"\x99\x01", "OpenPGP Public Key"),
            (b"\x95\x01", "OpenPGP Secret Key"),
            (b"\x99\x00", "OpenPGP Public Key"),
            (b"\x95\x00", "OpenPGP Secret Key"),
            # Targa image patterns (zsteg detects these)
            (b"\x00\x00\x02\x00", "Targa image data"),
            (b"\x00\x00\x03\x00", "Targa image data"),
            (b"\x00\x00\x0a\x00", "Targa image data"),
            (b"\x00\x00\x0b\x00", "Targa image data"),
        ]

        for sig, desc in signatures:
            if data.startswith(sig):
                # Add more details for Targa images (like zsteg does)
                if "Targa" in desc and len(data) >= 18:
                    try:
                        data[0]
                        color_map_type = data[1]
                        image_type = data[2]
                        width = struct.unpack("<H", data[12:14])[0]
                        height = struct.unpack("<H", data[14:16])[0]
                        pixel_depth = data[16]
                        descriptor = data[17]
                        alpha_bits = descriptor & 0x0F

                        # Build detailed description like zsteg
                        details = "Targa image data"
                        if image_type == 1:
                            details += " - Map"
                        elif image_type == 2:
                            details += " - RGB"
                        elif image_type == 3:
                            details += " - Mono"

                        if color_map_type:
                            details += f" {width} x {height}"
                        else:
                            details += f" ({width}-{height})"

                        details += f" {width} x {height}"

                        if pixel_depth:
                            details += f" x {pixel_depth}"

                        if alpha_bits:
                            details += f" +{alpha_bits}"

                        # Direction flags
                        direction_flags = (descriptor >> 4) & 0x03
                        if direction_flags == 0:
                            details += " - right"
                        elif direction_flags == 1:
                            details += " - left"
                        elif direction_flags == 2:
                            details += " - right/bottom"
                        elif direction_flags == 3:
                            details += " - left/bottom"

                        if alpha_bits:
                            details += f" - {alpha_bits}-bit alpha"

                        return details
                    except Exception:
                        pass

                return desc

        # Check for Alliant virtual executable (zsteg detects this)
        if len(data) >= 8:
            # Alliant virtual executable pattern
            if data[0:2] == b"\x01\x03" or data[0:2] == b"\x01\x07":
                return "0420 Alliant virtual executable not stripped"

        # Check for Applesoft BASIC (zsteg detects this)
        if len(data) >= 4:
            if data[0] in (0x00, 0x01) and data[2] in range(0x00, 0x20):
                # Could be Applesoft BASIC
                first_line = struct.unpack("<H", data[0:2])[0]
                if 1 <= first_line <= 65535:
                    return f"Applesoft BASIC program data, first line number {first_line}"

        return None

    def detect_printable_strings(self, data: bytes) -> Optional[str]:
        """Detect ASCII printable strings in data."""
        if not data:
            return None

        # Look for printable ASCII strings
        current_string = []
        longest_string = ""

        for byte in data[:1024]:  # Check first 1KB
            if 32 <= byte <= 126:  # Printable ASCII
                current_string.append(chr(byte))
            else:
                if len(current_string) >= self.min_string_len:
                    s = "".join(current_string)
                    if len(s) > len(longest_string):
                        longest_string = s
                current_string = []

        # Check final string
        if len(current_string) >= self.min_string_len:
            s = "".join(current_string)
            if len(s) > len(longest_string):
                longest_string = s

        return longest_string if longest_string else None

    def detect_zlib(self, data: bytes) -> Optional[bytes]:
        """Try to decompress data as zlib."""
        if not data or len(data) < 2:
            return None

        # Try different offsets for zlib header
        for offset in range(min(16, len(data) - 2)):
            try:
                decompressed = zlib.decompress(data[offset:])
                if len(decompressed) > 0:
                    return decompressed
            except zlib.error:
                continue

        return None

    def detect_base64(self, data: bytes) -> Optional[bytes]:
        """Detect and decode base64 data."""
        import base64
        import re

        try:
            # Look for base64 pattern - check first 500 bytes
            text = data[:500].decode("ascii", errors="ignore")
            # Base64 pattern: only A-Za-z0-9+/= chars, at least 20 chars
            base64_pattern = re.compile(r"([A-Za-z0-9+/]{20,}={0,2})")
            matches = base64_pattern.findall(text)

            for b64_str in matches:
                try:
                    # Pad if necessary
                    missing_padding = len(b64_str) % 4
                    if missing_padding:
                        b64_str += "=" * (4 - missing_padding)

                    decoded = base64.b64decode(b64_str)
                    # Only return if decoded data looks meaningful (at least 10 bytes)
                    if len(decoded) >= 10:
                        return decoded
                except Exception:
                    continue
        except Exception:
            pass

        return None


class PNGStegoDetector:
    """Detect steganography in PNG files."""

    def __init__(self):
        self.extractor = LSBExtractor()

    def extract_png_metadata(self, data: bytes) -> list[StegoResult]:
        """Extract metadata from PNG text chunks (tEXt, iTXt, zTXt).

        This mimics zsteg's metadata extraction behavior.
        """
        results = []

        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            return results

        offset = 8  # Skip PNG signature

        while offset < len(data):
            if offset + 8 > len(data):
                break

            try:
                # Read chunk length and type
                chunk_len = struct.unpack(">I", data[offset : offset + 4])[0]
                chunk_type = data[offset + 4 : offset + 8]
                chunk_data_start = offset + 8
                chunk_data_end = chunk_data_start + chunk_len

                if chunk_data_end > len(data):
                    break

                chunk_data = data[chunk_data_start:chunk_data_end]

                # tEXt chunk: keyword\0text
                if chunk_type == b"tEXt":
                    null_pos = chunk_data.find(b"\0")
                    if null_pos > 0:
                        keyword = chunk_data[:null_pos].decode("latin1", errors="ignore")
                        text = chunk_data[null_pos + 1 :].decode("latin1", errors="ignore")

                        # Check for flags
                        flag = self.extractor.detect_flag_patterns(text.encode("utf-8"))
                        confidence = 1.0 if flag else 0.7

                        results.append(
                            StegoResult(
                                method=f"meta {keyword}",
                                channel="tEXt",
                                bit_plane=0,
                                order="metadata",
                                data=text.encode("utf-8"),
                                data_type="text",
                                description=f'text: "{text}"' if not flag else f"FLAG: {flag}",
                                confidence=confidence,
                                offset=chunk_data_start,
                                size=len(text),
                            )
                        )

                # iTXt chunk: keyword\0compression\0language\0translated_keyword\0text
                elif chunk_type == b"iTXt":
                    null_pos = chunk_data.find(b"\0")
                    if null_pos > 0:
                        keyword = chunk_data[:null_pos].decode("utf-8", errors="ignore")
                        remaining = chunk_data[null_pos + 1 :]

                        if len(remaining) >= 2:
                            compression_flag = remaining[0]
                            remaining[1]

                            # Find language and text
                            remaining = remaining[2:]
                            null_pos2 = remaining.find(b"\0")
                            if null_pos2 >= 0:
                                remaining[:null_pos2].decode("utf-8", errors="ignore")
                                remaining = remaining[null_pos2 + 1 :]

                                # Skip translated keyword
                                null_pos3 = remaining.find(b"\0")
                                if null_pos3 >= 0:
                                    text_data = remaining[null_pos3 + 1 :]

                                    # Decompress if needed
                                    if compression_flag == 1:
                                        try:
                                            text_data = zlib.decompress(text_data)
                                        except Exception:
                                            pass

                                    text = text_data.decode("utf-8", errors="ignore")

                                    # Check for flags
                                    flag = self.extractor.detect_flag_patterns(text.encode("utf-8"))
                                    confidence = 1.0 if flag else 0.75

                                    results.append(
                                        StegoResult(
                                            method=f"meta {keyword}",
                                            channel="iTXt",
                                            bit_plane=0,
                                            order="metadata",
                                            data=text.encode("utf-8"),
                                            data_type="text",
                                            description=(
                                                f"file: {text[:100]}"
                                                if len(text) > 100
                                                else f'text: "{text}"'
                                            ),
                                            confidence=confidence,
                                            offset=chunk_data_start,
                                            size=len(text),
                                        )
                                    )

                # zTXt chunk: keyword\0compression_method\compressed_text
                elif chunk_type == b"zTXt":
                    null_pos = chunk_data.find(b"\0")
                    if null_pos > 0:
                        keyword = chunk_data[:null_pos].decode("latin1", errors="ignore")

                        if len(chunk_data) > null_pos + 2:
                            chunk_data[null_pos + 1]
                            compressed_text = chunk_data[null_pos + 2 :]

                            try:
                                text = zlib.decompress(compressed_text).decode(
                                    "latin1", errors="ignore"
                                )

                                # Check for flags
                                flag = self.extractor.detect_flag_patterns(text.encode("utf-8"))
                                confidence = 1.0 if flag else 0.7

                                results.append(
                                    StegoResult(
                                        method=f"meta {keyword}",
                                        channel="zTXt",
                                        bit_plane=0,
                                        order="metadata",
                                        data=text.encode("utf-8"),
                                        data_type="text",
                                        description=(
                                            f'text: "{text}"' if not flag else f"FLAG: {flag}"
                                        ),
                                        confidence=confidence,
                                        offset=chunk_data_start,
                                        size=len(text),
                                    )
                                )
                            except Exception as e:
                                logger.debug(f"Failed to decompress zTXt chunk: {e}")

                # tIME chunk: last modification time
                elif chunk_type == b"tIME" and len(chunk_data) >= 7:
                    year = struct.unpack(">H", chunk_data[0:2])[0]
                    month = chunk_data[2]
                    day = chunk_data[3]
                    hour = chunk_data[4]
                    minute = chunk_data[5]
                    second = chunk_data[6]

                    time_str = (
                        f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}"
                    )

                    results.append(
                        StegoResult(
                            method="meta,tIME",
                            channel="tIME",
                            bit_plane=0,
                            order="metadata",
                            data=time_str.encode("utf-8"),
                            data_type="timestamp",
                            description=f"PNG modification time: {time_str}",
                            confidence=0.5,
                            offset=chunk_data_start,
                            size=7,
                        )
                    )

                # Move to next chunk
                if chunk_type == b"IEND":
                    break

                offset += 12 + chunk_len  # length(4) + type(4) + data(chunk_len) + CRC(4)

            except Exception as e:
                logger.debug(f"Error parsing PNG chunk at offset {offset}: {e}")
                break

        return results

    def parse_png(self, data: bytes) -> Optional[dict]:
        """Parse PNG using PIL for reliable pixel extraction.

        Returns pixels in RGBA format, row by row (xy order),
        which matches zsteg's zpng behavior.
        """
        # First, extract raw IDAT data manually (needed for imagedata analysis)
        raw_idat_decompressed = b""
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            offset = 8
            idat_compressed = b""

            while offset < len(data):
                if offset + 8 > len(data):
                    break

                try:
                    chunk_len = struct.unpack(">I", data[offset : offset + 4])[0]
                    chunk_type = data[offset + 4 : offset + 8]
                    chunk_data = data[offset + 8 : offset + 8 + chunk_len]

                    if chunk_type == b"IDAT":
                        idat_compressed += chunk_data
                    elif chunk_type == b"IEND":
                        break

                    offset += 12 + chunk_len
                except Exception:
                    break

            if idat_compressed:
                try:
                    raw_idat_decompressed = zlib.decompress(idat_compressed)
                except Exception:
                    pass

        try:
            from PIL import Image
            import io

            img = Image.open(io.BytesIO(data))

            # Convert to RGBA if needed (same as zsteg)
            if img.mode != "RGBA":
                img = img.convert("RGBA")

            # Get pixel data as flat array
            # PIL returns pixels in row-major order (left-to-right, top-to-bottom)
            # Each pixel is 4 bytes: R, G, B, A
            # This matches zpng's pixel iteration order
            pixels = bytearray(img.tobytes())

            return {
                "width": img.width,
                "height": img.height,
                "mode": img.mode,
                "clean_pixels": bytes(pixels),
                "raw_idat_decompressed": raw_idat_decompressed,
            }
        except ImportError:
            logger.warning("PIL not available, falling back to manual PNG parsing")
            return self._manual_png_parse(data)
        except Exception as e:
            logger.debug(f"Failed to load PNG with PIL: {e}")
            return None

    def _manual_png_parse(self, data: bytes) -> Optional[dict]:
        """Fallback manual PNG parser."""
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            return None

        info = {
            "width": 0,
            "height": 0,
            "bit_depth": 0,
            "color_type": 0,
            "image_data": b"",
            "chunks": [],
            "clean_pixels": b"",
            "raw_idat_decompressed": b"",  # Store raw decompressed data
        }

        offset = 8  # Skip PNG signature

        while offset < len(data):
            if offset + 8 > len(data):
                break

            # Read chunk length and type
            chunk_len = struct.unpack(">I", data[offset : offset + 4])[0]
            chunk_type = data[offset + 4 : offset + 8]
            chunk_data = data[offset + 8 : offset + 8 + chunk_len]

            info["chunks"].append((chunk_type.decode("latin1", errors="ignore"), chunk_len))

            if chunk_type == b"IHDR" and len(chunk_data) >= 13:
                info["width"] = struct.unpack(">I", chunk_data[0:4])[0]
                info["height"] = struct.unpack(">I", chunk_data[4:8])[0]
                info["bit_depth"] = chunk_data[8]
                info["color_type"] = chunk_data[9]
            elif chunk_type == b"IDAT":
                info["image_data"] += chunk_data
            elif chunk_type == b"IEND":
                break

            offset += 12 + chunk_len  # length + type + data + CRC

        # Decompress and remove filter bytes
        if info["image_data"]:
            try:
                decompressed = zlib.decompress(info["image_data"])
                info["raw_idat_decompressed"] = decompressed  # Store raw decompressed data

                # Remove PNG filter bytes (first byte of each scanline)
                bytes_per_pixel = 4 if info["color_type"] == 6 else 3  # RGBA or RGB
                bytes_per_row = info["width"] * bytes_per_pixel + 1  # +1 for filter byte

                clean_pixels = bytearray()
                for y in range(info["height"]):
                    row_start = y * bytes_per_row
                    if row_start + bytes_per_row <= len(decompressed):
                        # Skip filter byte (first byte of row)
                        row_data = decompressed[row_start + 1 : row_start + bytes_per_row]
                        clean_pixels.extend(row_data)

                info["clean_pixels"] = bytes(clean_pixels)
            except Exception as e:
                logger.debug(f"Failed to process PNG pixels: {e}")

        return info

    def reorder_pixels(self, pixels: bytes, width: int, height: int, pixel_order: str) -> bytes:
        """Reorder pixels according to traversal order.

        Args:
            pixels: Raw pixel data in RGBA format (row-major, left-to-right, top-to-bottom)
            width: Image width
            height: Image height
            pixel_order: Order to traverse pixels ('xy', 'yx', 'XY', 'YX')
                xy: left-to-right, top-to-bottom (standard)
                yx: top-to-bottom, left-to-right
                XY: right-to-left, top-to-bottom
                YX: bottom-to-top, left-to-right

        Returns:
            Reordered pixel data
        """
        bytes_per_pixel = 4  # RGBA

        # xy order is already the native format
        if pixel_order == "xy":
            return pixels

        result = bytearray()

        if pixel_order == "yx":
            # Top-to-bottom, left-to-right (column-major)
            for x in range(width):
                for y in range(height):
                    pixel_offset = (y * width + x) * bytes_per_pixel
                    result.extend(pixels[pixel_offset : pixel_offset + bytes_per_pixel])

        elif pixel_order == "XY":
            # Right-to-left, top-to-bottom
            for y in range(height):
                for x in range(width - 1, -1, -1):
                    pixel_offset = (y * width + x) * bytes_per_pixel
                    result.extend(pixels[pixel_offset : pixel_offset + bytes_per_pixel])

        elif pixel_order == "YX":
            # Bottom-to-top, left-to-right
            for x in range(width):
                for y in range(height - 1, -1, -1):
                    pixel_offset = (y * width + x) * bytes_per_pixel
                    result.extend(pixels[pixel_offset : pixel_offset + bytes_per_pixel])

        else:
            # Unknown order, return original
            return pixels

        return bytes(result)

    def extract_channel_data(
        self, pixels: bytes, channels: str, bits_per_channel: int = 1, bit_order: str = "lsb"
    ) -> bytes:
        """Extract data from specific color channels (zsteg-compatible).

        This properly handles multi-bit extraction by directly packing nibbles/bytes.

        Args:
            pixels: Raw pixel data in RGBA format (4 bytes per pixel)
            channels: Which channels to extract ('rgb', 'rgba', 'r', 'g', 'b', 'a', 'bgr', 'abgr', etc.)
            bits_per_channel: Number of bits to extract per channel (1-8)
            bit_order: 'lsb' for least significant bits first, 'msb' for most significant bits first

        Returns:
            Extracted bytes
        """
        bytes_per_pixel = 4  # RGBA
        num_pixels = len(pixels) // bytes_per_pixel

        # Collect extracted nibbles/bytes as integer values
        extracted_values = []

        for i in range(num_pixels):
            pixel_start = i * bytes_per_pixel
            r = pixels[pixel_start]
            g = pixels[pixel_start + 1]
            b = pixels[pixel_start + 2]
            a = pixels[pixel_start + 3]

            # Extract values from requested channels in order
            for channel in channels:
                if channel == "r":
                    value = r
                elif channel == "g":
                    value = g
                elif channel == "b":
                    value = b
                elif channel == "a":
                    value = a
                else:
                    continue

                # Extract N bits from this channel value
                if bit_order == "lsb":
                    # Extract LSBs: mask to get lowest N bits
                    # e.g., for 4 bits from 0xAB, get 0x0B
                    mask = (1 << bits_per_channel) - 1  # e.g., 0x0F for 4 bits
                    extracted_val = value & mask
                else:
                    # Extract MSBs: shift right to get highest N bits
                    # e.g., for 4 bits from 0xAB, shift right 4 to get 0x0A
                    shift = 8 - bits_per_channel
                    extracted_val = value >> shift

                extracted_values.append(extracted_val)

        # Now pack the extracted values into bytes
        # Each value contains bits_per_channel bits
        if bits_per_channel == 8:
            # Direct byte packing
            return bytes(extracted_values)
        elif bits_per_channel == 4:
            # Pack two nibbles per byte
            result = bytearray()
            for i in range(0, len(extracted_values), 2):
                if i + 1 < len(extracted_values):
                    # Pack two nibbles: first value in high nibble, second in low nibble
                    byte_val = (extracted_values[i] << 4) | extracted_values[i + 1]
                    result.append(byte_val)
                else:
                    # Odd number of nibbles, pack last one in high nibble
                    result.append(extracted_values[i] << 4)
            return bytes(result)
        elif bits_per_channel == 2:
            # Pack four 2-bit values per byte
            result = bytearray()
            for i in range(0, len(extracted_values), 4):
                byte_val = 0
                for j in range(4):
                    if i + j < len(extracted_values):
                        byte_val = (byte_val << 2) | extracted_values[i + j]
                result.append(byte_val)
            return bytes(result)
        else:  # bits_per_channel == 1
            # Pack eight 1-bit values per byte
            result = bytearray()
            for i in range(0, len(extracted_values), 8):
                byte_val = 0
                for j in range(8):
                    if i + j < len(extracted_values):
                        byte_val = (byte_val << 1) | extracted_values[i + j]
                result.append(byte_val)
            return bytes(result)

    def analyze_imagedata(
        self, data: bytes, raw_idat_decompressed: bytes = None
    ) -> Optional[StegoResult]:
        """Analyze raw pixel data for patterns (like zsteg's imagedata).

        This looks at the decompressed IDAT data (before filter byte removal)
        to find readable patterns or text.

        Args:
            data: Clean pixel data (for fallback)
            raw_idat_decompressed: Raw decompressed IDAT data (with filter bytes)
        """
        # Prefer raw IDAT data if available
        analyze_data = raw_idat_decompressed if raw_idat_decompressed else data

        # Look through the entire data for printable sequences
        best_text = None
        best_length = 0

        # Scan through data looking for printable sequences
        i = 0
        while i < len(analyze_data):
            # Start collecting printable characters
            printable_chars = []

            while i < len(analyze_data):
                byte = analyze_data[i]
                if 32 <= byte <= 126 or byte in (9, 10, 13):  # Printable or whitespace
                    printable_chars.append(chr(byte))
                    i += 1
                else:
                    break

            # If we found a good sequence, keep track of it
            if len(printable_chars) >= 8:
                text = "".join(printable_chars)
                if len(text) > best_length:
                    best_text = text
                    best_length = len(text)

            i += 1

        if best_text and len(best_text) >= 8:
            # Limit display to reasonable length
            display_text = best_text[:100] if len(best_text) > 100 else best_text

            # Use repr to properly escape special characters
            display_text = repr(display_text)[1:-1]  # Remove outer quotes

            return StegoResult(
                method="imagedata",
                channel="pixels",
                bit_plane=0,
                order="raw",
                data=best_text.encode("utf-8"),
                data_type="text",
                description=f'text: "{display_text}"',
                confidence=0.6,
                offset=0,
                size=len(best_text),
            )

        return None

    def detect(self, data: bytes) -> list[StegoResult]:
        """
        Detect LSB steganography in PNG file.

        Args:
            data: PNG file data

        Returns:
            List of steganography results found
        """
        results = []

        # First, extract PNG metadata chunks (tEXt, iTXt, zTXt) - like zsteg does
        metadata_results = self.extract_png_metadata(data)
        results.extend(metadata_results)

        png_info = self.parse_png(data)
        if not png_info or not png_info["clean_pixels"]:
            return results

        # Use clean pixel data (RGBA format)
        image_data = png_info["clean_pixels"]

        # Analyze raw imagedata (decompressed IDAT with filter bytes) - like zsteg
        raw_idat = png_info.get("raw_idat_decompressed", b"")
        imagedata_result = self.analyze_imagedata(image_data, raw_idat)
        if imagedata_result:
            results.append(imagedata_result)

        # Test different bit planes and channels (matching zsteg's comprehensive scan)
        test_configs = [
            # b1 (1-bit) LSB tests - xy order (standard: left-to-right, top-to-bottom)
            (1, "rgba", "lsb", "xy"),
            (1, "rgb", "lsb", "xy"),
            (1, "r", "lsb", "xy"),
            (1, "g", "lsb", "xy"),
            (1, "b", "lsb", "xy"),
            (1, "a", "lsb", "xy"),
            (1, "bgr", "lsb", "xy"),
            (1, "abgr", "lsb", "xy"),
            # b2 (2-bit) LSB tests
            (2, "rgba", "lsb", "xy"),
            (2, "rgb", "lsb", "xy"),
            (2, "r", "lsb", "xy"),
            (2, "g", "lsb", "xy"),
            (2, "b", "lsb", "xy"),
            (2, "a", "lsb", "xy"),
            # b4 (4-bit) LSB tests
            (4, "rgba", "lsb", "xy"),
            (4, "rgb", "lsb", "xy"),
            (4, "bgr", "lsb", "xy"),
            (4, "r", "lsb", "xy"),
            (4, "g", "lsb", "xy"),
            (4, "b", "lsb", "xy"),
            # b1 (1-bit) LSB tests - yx order (column-major)
            (1, "rgba", "lsb", "yx"),
            (1, "rgb", "lsb", "yx"),
            (1, "b", "lsb", "yx"),
            # b1 (1-bit) LSB tests - XY order (reversed horizontal)
            (1, "rgba", "lsb", "XY"),
            (1, "rgb", "lsb", "XY"),
            # b1 (1-bit) LSB tests - YX order (reversed vertical)
            (1, "rgba", "lsb", "YX"),
            (1, "rgb", "lsb", "YX"),
            # b1 (1-bit) MSB tests - xy order
            (1, "rgba", "msb", "xy"),
            (1, "rgb", "msb", "xy"),
            (1, "r", "msb", "xy"),
            (1, "g", "msb", "xy"),
            (1, "b", "msb", "xy"),
            (1, "a", "msb", "xy"),
            (1, "abgr", "msb", "xy"),
            # b2 (2-bit) MSB tests
            (2, "rgba", "msb", "xy"),
            (2, "rgb", "msb", "xy"),
            (2, "r", "msb", "xy"),
            (2, "g", "msb", "xy"),
            (2, "b", "msb", "xy"),
            # b4 (4-bit) MSB tests
            (4, "rgba", "msb", "xy"),
            (4, "rgb", "msb", "xy"),
            (4, "r", "msb", "xy"),
            (4, "g", "msb", "xy"),
            (4, "b", "msb", "xy"),
            # b1 MSB tests - yx order
            (1, "rgba", "msb", "yx"),
            (1, "rgb", "msb", "yx"),
        ]

        width = png_info.get("width", 0)
        height = png_info.get("height", 0)

        for bits, channels, bit_order, px_order in test_configs:
            # Reorder pixels according to pixel order
            reordered_pixels = self.reorder_pixels(image_data, width, height, px_order)

            # Extract data from specific color channels
            extracted = self.extract_channel_data(reordered_pixels, channels, bits, bit_order)

            if not extracted:
                continue

            # First, check for file type (like zsteg does)
            file_type = self.extractor.detect_file_type(extracted)
            if file_type:
                # Show first bytes as preview
                " ".join(
                    f"\\{ord(c):03o}" if c < " " or c > "~" else c
                    for c in extracted[:50].decode("latin-1", errors="ignore")
                )
                results.append(
                    StegoResult(
                        method=f"b{bits},{channels},{bit_order},{px_order}",
                        channel=channels,
                        bit_plane=bits,
                        order=px_order,
                        data=extracted,
                        data_type="file",
                        description=f"file: {file_type}",
                        confidence=0.95,
                        size=len(extracted),
                    )
                )

            # Check for flag patterns (highest priority for text)
            flag = self.extractor.detect_flag_patterns(extracted)
            if flag:
                results.append(
                    StegoResult(
                        method=f"b{bits},{channels},{bit_order},{px_order}",
                        channel=channels,
                        bit_plane=bits,
                        order=px_order,
                        data=flag.encode(),
                        data_type="flag",
                        description=f'text: "{flag}"',
                        confidence=1.0,
                        size=len(flag),
                    )
                )

            # Check for printable strings
            printable_str = self.extractor.detect_printable_strings(extracted)
            if printable_str and not flag:  # Don't duplicate if we already found a flag
                # Truncate long strings to match zsteg's output style (max ~250 chars)
                display_str = printable_str[:250] if len(printable_str) > 250 else printable_str
                results.append(
                    StegoResult(
                        method=f"b{bits},{channels},{bit_order},{px_order}",
                        channel=channels,
                        bit_plane=bits,
                        order=px_order,
                        data=printable_str.encode(),
                        data_type="text",
                        description=f'text: "{display_str}"',
                        confidence=0.75,
                        size=len(printable_str),
                    )
                )

            # Check for zlib compressed data
            zlib_data = self.extractor.detect_zlib(extracted)
            if zlib_data:
                # Detect what the decompressed data is
                desc = "zlib compressed data"
                if zlib_data.startswith(b"%PDF"):
                    desc = "zlib: PDF document"
                elif zlib_data.startswith(b"\x89PNG"):
                    desc = "zlib: PNG image"

                # Try to find printable content
                printable = self.extractor.detect_printable_strings(zlib_data)
                if printable:
                    desc += f', contains: "{printable[:50]}"'

                results.append(
                    StegoResult(
                        method=f"b{bits},{channels},{bit_order},{px_order}",
                        channel=channels,
                        bit_plane=bits,
                        order=px_order,
                        data=zlib_data,
                        data_type="zlib",
                        description=desc,
                        confidence=0.95,
                        size=len(zlib_data),
                    )
                )

            # Check for base64 encoded data
            base64_data = self.extractor.detect_base64(extracted)
            if base64_data:
                desc = "base64 encoded data"
                # Look for printable strings in the decoded data
                printable = self.extractor.detect_printable_strings(base64_data)
                if printable:
                    desc += f': "{printable[:50]}"'

                results.append(
                    StegoResult(
                        method=f"b{bits},{channels},{bit_order},{px_order}",
                        channel=channels,
                        bit_plane=bits,
                        order=px_order,
                        data=base64_data,
                        data_type="base64",
                        description=desc,
                        confidence=0.85,
                        size=len(base64_data),
                    )
                )

        return results


class BMPStegoDetector:
    """Detect steganography in BMP files."""

    def __init__(self):
        self.extractor = LSBExtractor()

    def parse_bmp(self, data: bytes) -> Optional[dict]:
        """Parse BMP structure."""
        if not data.startswith(b"BM"):
            return None

        if len(data) < 54:  # Minimum BMP header size
            return None

        info = {
            "file_size": struct.unpack("<I", data[2:6])[0],
            "pixel_offset": struct.unpack("<I", data[10:14])[0],
            "width": struct.unpack("<I", data[18:22])[0],
            "height": struct.unpack("<I", data[22:26])[0],
            "bit_depth": struct.unpack("<H", data[28:30])[0],
        }

        if info["pixel_offset"] < len(data):
            info["image_data"] = data[info["pixel_offset"] :]
        else:
            info["image_data"] = b""

        return info

    def detect(self, data: bytes) -> list[StegoResult]:
        """Detect LSB steganography in BMP file."""
        results = []

        bmp_info = self.parse_bmp(data)
        if not bmp_info or not bmp_info["image_data"]:
            return results

        image_data = bmp_info["image_data"]

        # Test configurations similar to PNG
        test_configs = [
            (1, "bgr", "lsb", "xy"),
            (1, "rgb", "lsb", "xy"),
            (1, "b", "lsb", "xy"),
            (1, "g", "lsb", "xy"),
            (1, "r", "lsb", "xy"),
            (2, "bgr", "lsb", "xy"),
        ]

        for bits, channels, bit_order, px_order in test_configs:
            extracted = self.extractor.extract_bits(
                image_data, bits=bits, order=BitOrder.LSB if bit_order == "lsb" else BitOrder.MSB
            )

            if not extracted:
                continue

            # Check for strings
            printable_str = self.extractor.detect_printable_strings(extracted)
            if printable_str:
                results.append(
                    StegoResult(
                        method=f"b{bits},{channels},{bit_order},{px_order}",
                        channel=channels,
                        bit_plane=bits,
                        order=px_order,
                        data=printable_str.encode(),
                        data_type="text",
                        description=f'text: "{printable_str}"',
                        confidence=0.9,
                        size=len(printable_str),
                    )
                )

            # Check for zlib
            zlib_data = self.extractor.detect_zlib(extracted)
            if zlib_data:
                desc = "zlib compressed data"
                printable = self.extractor.detect_printable_strings(zlib_data)
                if printable:
                    desc += f', contains: "{printable[:50]}"'

                results.append(
                    StegoResult(
                        method=f"b{bits},{channels},{bit_order},{px_order}",
                        channel=channels,
                        bit_plane=bits,
                        order=px_order,
                        data=zlib_data,
                        data_type="zlib",
                        description=desc,
                        confidence=0.95,
                        size=len(zlib_data),
                    )
                )

        return results


class PDFMetadataDetector:
    """Detect steganography in PDF metadata."""

    def __init__(self):
        self.extractor = LSBExtractor()

    def extract_metadata(self, data: bytes) -> dict:
        """Extract PDF metadata fields."""
        metadata = {}

        if not data.startswith(b"%PDF"):
            return metadata

        # Find the Info dictionary
        # Look for /Info reference in trailer
        trailer_match = data.rfind(b"trailer")
        if trailer_match == -1:
            return metadata

        # Search for metadata fields in the PDF
        # Common fields: /Author, /Title, /Subject, /Keywords, /Creator, /Producer
        fields = [b"/Author", b"/Title", b"/Subject", b"/Keywords", b"/Creator", b"/Producer"]

        for field in fields:
            field_name = field.decode("ascii").lstrip("/")

            # Find field in PDF
            pos = 0
            while True:
                pos = data.find(field, pos)
                if pos == -1:
                    break

                # Extract the value (usually in parentheses or angle brackets)
                # Format: /Author (value) or /Author <hex>
                value_start = pos + len(field)

                # Skip whitespace
                while value_start < len(data) and data[value_start : value_start + 1] in b" \t\n\r":
                    value_start += 1

                if value_start >= len(data):
                    break

                # Extract based on delimiter
                if data[value_start : value_start + 1] == b"(":
                    # Parentheses format: (value)
                    value_end = data.find(b")", value_start)
                    if value_end != -1:
                        value = data[value_start + 1 : value_end]
                        try:
                            metadata[field_name] = value.decode("utf-8", errors="ignore")
                        except Exception:
                            metadata[field_name] = value.decode("latin-1", errors="ignore")
                        break
                elif data[value_start : value_start + 1] == b"<":
                    # Hex format: <hex>
                    value_end = data.find(b">", value_start)
                    if value_end != -1:
                        hex_value = data[value_start + 1 : value_end]
                        try:
                            # Decode hex
                            value = bytes.fromhex(hex_value.decode("ascii"))
                            metadata[field_name] = value.decode("utf-8", errors="ignore")
                        except Exception:
                            pass
                        break

                pos = value_start

        return metadata

    def detect(self, data: bytes) -> list[StegoResult]:
        """Detect steganography in PDF metadata."""
        results = []

        metadata = self.extract_metadata(data)

        if not metadata:
            return results

        # Check each metadata field for hidden data
        for field_name, field_value in metadata.items():
            if not field_value or len(field_value) < 10:
                continue

            # Check for base64
            base64_data = self.extractor.detect_base64(field_value.encode())
            if base64_data:
                desc = f"PDF metadata ({field_name})"
                printable = self.extractor.detect_printable_strings(base64_data)
                if printable:
                    desc += f': "{printable[:50]}"'

                results.append(
                    StegoResult(
                        method=f"metadata,{field_name.lower()}",
                        channel=field_name,
                        bit_plane=0,
                        order="metadata",
                        data=base64_data,
                        data_type="metadata",
                        description=desc,
                        confidence=0.95,
                        size=len(base64_data),
                    )
                )

            # Also show raw metadata if it contains printable strings
            elif len(field_value) > 20:
                printable = self.extractor.detect_printable_strings(field_value.encode())
                if printable and printable != field_value[: len(printable)]:
                    # Found something different from the raw value
                    results.append(
                        StegoResult(
                            method=f"metadata,{field_name.lower()}",
                            channel=field_name,
                            bit_plane=0,
                            order="metadata",
                            data=printable.encode(),
                            data_type="metadata",
                            description=f'PDF metadata ({field_name}): "{field_value[:100]}"',
                            confidence=0.7,
                            size=len(printable),
                        )
                    )

        return results


class TrailingDataDetector:
    """Detect data appended after file end markers."""

    def __init__(self):
        self.extractor = LSBExtractor()

    def find_file_end(self, data: bytes, format_hint: Optional[str] = None) -> Optional[int]:
        """Find the logical end of a file based on its format."""

        # JPEG: Find last FF D9 (EOI marker)
        if format_hint == "jpeg" or data.startswith(b"\xff\xd8\xff"):
            pos = data.rfind(b"\xff\xd9")
            if pos != -1:
                return pos + 2  # After the EOI marker

        # PNG: Find IEND chunk
        elif format_hint == "png" or data.startswith(b"\x89PNG"):
            pos = data.find(b"IEND")
            if pos != -1:
                # IEND is followed by 4-byte CRC
                return pos + 8

        # PDF: Find %%EOF
        elif format_hint == "pdf" or data.startswith(b"%PDF"):
            pos = data.rfind(b"%%EOF")
            if pos != -1:
                # Skip any whitespace after EOF
                end_pos = pos + 5
                while end_pos < len(data) and data[end_pos : end_pos + 1] in b"\r\n\t ":
                    end_pos += 1
                return end_pos

        # GIF: Find trailer (0x3B)
        elif format_hint == "gif" or data.startswith(b"GIF8"):
            pos = data.rfind(b"\x3b")
            if pos != -1:
                return pos + 1

        return None

    def detect(self, data: bytes, format_hint: Optional[str] = None) -> list[StegoResult]:
        """Detect trailing data after file end marker."""
        results = []

        # Auto-detect format
        if format_hint is None:
            if data.startswith(b"\xff\xd8\xff"):
                format_hint = "jpeg"
            elif data.startswith(b"\x89PNG"):
                format_hint = "png"
            elif data.startswith(b"%PDF"):
                format_hint = "pdf"
            elif data.startswith(b"GIF8"):
                format_hint = "gif"

        end_pos = self.find_file_end(data, format_hint)

        if end_pos is None or end_pos >= len(data):
            return results

        # Extract trailing data
        trailing = data[end_pos:]

        if len(trailing) < 4:  # Ignore very small trailing data
            return results

        # Check for printable text
        printable = self.extractor.detect_printable_strings(trailing)
        if printable:
            display_str = printable[:100] if len(printable) > 100 else printable
            results.append(
                StegoResult(
                    method=f"trailing,{format_hint or 'unknown'}",
                    channel="EOI",
                    bit_plane=0,
                    order="trailing",
                    data=printable.encode(),
                    data_type="trailing",
                    description=f'Trailing data after {format_hint.upper()} end: "{display_str}"',
                    confidence=0.95,
                    offset=end_pos,
                    size=len(printable),
                )
            )

        # Check for base64 in trailing data
        base64_data = self.extractor.detect_base64(trailing)
        if base64_data:
            desc = f"Trailing data ({format_hint.upper()})"
            printable_b64 = self.extractor.detect_printable_strings(base64_data)
            if printable_b64:
                desc += f': "{printable_b64[:50]}"'

            results.append(
                StegoResult(
                    method=f"trailing,{format_hint or 'unknown'},base64",
                    channel="EOI",
                    bit_plane=0,
                    order="trailing",
                    data=base64_data,
                    data_type="trailing",
                    description=desc,
                    confidence=0.9,
                    offset=end_pos,
                    size=len(base64_data),
                )
            )

        return results


class SVGStegoDetector:
    """Detect hidden text and steganography in SVG files."""

    def __init__(self):
        self.extractor = LSBExtractor()

    def detect(self, data: bytes) -> list[StegoResult]:
        """Detect hidden text in SVG files."""
        results = []

        try:
            # Parse as text
            svg_text = data.decode("utf-8", errors="ignore")

            # Check if it's actually SVG
            if not ("<svg" in svg_text.lower() or "<?xml" in svg_text.lower()):
                return results

            # Find all text elements with their properties
            hidden_texts = []

            # Parse with ElementTree
            try:
                # Remove namespace to make parsing easier
                svg_clean = re.sub(r'\sxmlns[^=]*="[^"]*"', "", svg_text)
                svg_clean = re.sub(r'\s+xmlns:[^=]+="[^"]*"', "", svg_clean)

                root = ET.fromstring(svg_clean.encode("utf-8"))

                # Find all text and tspan elements
                for elem in root.iter():
                    tag = elem.tag.lower() if isinstance(elem.tag, str) else str(elem.tag).lower()

                    if "text" in tag or "tspan" in tag:
                        text = elem.text or ""
                        style = elem.get("style", "")
                        font_size_attr = elem.get("font-size", "")

                        # Extract font size from style or attribute
                        font_size = None

                        # Check style attribute
                        font_match = re.search(r"font-size:\s*([\d.]+)", style)
                        if font_match:
                            font_size = float(font_match.group(1))
                        elif font_size_attr:
                            font_size_match = re.search(r"([\d.]+)", font_size_attr)
                            if font_size_match:
                                font_size = float(font_size_match.group(1))

                        # Detect suspicious text
                        is_tiny = font_size is not None and font_size < 0.1
                        is_white = "fill:#ffffff" in style or "fill:white" in style.lower()
                        has_flag = self.extractor.detect_flag_patterns(
                            text.encode("utf-8", errors="ignore")
                        )

                        if text and (is_tiny or (is_white and has_flag)):
                            hidden_texts.append(
                                {
                                    "text": text,
                                    "font_size": font_size,
                                    "style": style,
                                    "is_tiny": is_tiny,
                                    "is_white": is_white,
                                    "has_flag": has_flag,
                                }
                            )

            except ET.ParseError:
                # Fallback to regex if XML parsing fails
                pass

            # Regex fallback for finding tiny text
            tiny_text_pattern = r"font-size:\s*0\.\d+px[^>]*>([^<]+)"
            for match in re.finditer(tiny_text_pattern, svg_text):
                text_content = match.group(1).strip()
                if text_content:
                    hidden_texts.append(
                        {
                            "text": text_content,
                            "font_size": 0.0,
                            "style": "tiny",
                            "is_tiny": True,
                            "is_white": False,
                            "has_flag": self.extractor.detect_flag_patterns(
                                text_content.encode("utf-8", errors="ignore")
                            ),
                        }
                    )

            # Process found hidden texts
            if hidden_texts:
                # Combine all text
                all_text = " ".join([ht["text"] for ht in hidden_texts])

                # Clean up - remove extra spaces between single characters (common in SVG stego)
                cleaned_text = re.sub(r"(?<=[a-zA-Z0-9_{}])\s+(?=[a-zA-Z0-9_{}])", "", all_text)

                # Check for flags
                flags = self.extractor.detect_flag_patterns(
                    cleaned_text.encode("utf-8", errors="ignore")
                )

                if flags:
                    confidence = 1.0
                    desc = f"Hidden SVG text (font-size < 0.1px): {flags[:100]}"
                    display_text = flags
                else:
                    confidence = 0.8
                    desc = f"Hidden SVG text (font-size < 0.1px): {cleaned_text[:100]}"
                    display_text = cleaned_text

                results.append(
                    StegoResult(
                        method="svg,hidden_text",
                        channel="text",
                        bit_plane=0,
                        order="xml",
                        data=display_text.encode("utf-8"),
                        data_type="text",
                        description=desc,
                        confidence=confidence,
                        offset=0,
                        size=len(display_text),
                    )
                )

            # Also check for suspicious comments
            comments = re.findall(r"<!--\s*(.+?)\s*-->", svg_text, re.DOTALL)
            for comment in comments:
                comment_clean = comment.strip()
                if len(comment_clean) > 20:  # Ignore short comments
                    flags = self.extractor.detect_flag_patterns(
                        comment_clean.encode("utf-8", errors="ignore")
                    )
                    if flags or any(
                        keyword in comment_clean.lower()
                        for keyword in ["flag", "secret", "hidden", "password"]
                    ):
                        results.append(
                            StegoResult(
                                method="svg,comment",
                                channel="xml",
                                bit_plane=0,
                                order="xml",
                                data=comment_clean.encode("utf-8"),
                                data_type="comment",
                                description=f"Suspicious SVG comment: {comment_clean[:100]}",
                                confidence=0.7 if flags else 0.5,
                                offset=0,
                                size=len(comment_clean),
                            )
                        )

        except Exception as e:
            logger.debug(f"SVG stego detection error: {e}")

        return results


def detect_steganography(data, format_hint: Optional[str] = None) -> list[StegoResult]:
    """
    Detect steganography in various file formats.

    Supports:
    - PNG/BMP: LSB analysis
    - PDF: Metadata analysis
    - JPEG/PNG/PDF/GIF: Trailing data after EOI/IEND/EOF markers

    Args:
        data: File data (bytes or file path)
        format_hint: Optional format hint ('png', 'bmp', 'pdf', 'jpeg', 'gif')

    Returns:
        List of steganography results
    """
    # If data is a string, treat it as a file path
    if isinstance(data, str):
        with open(data, "rb") as f:
            data = f.read()

    results = []

    # Auto-detect format if not provided
    if format_hint is None:
        if data.startswith(b"\x89PNG"):
            format_hint = "png"
        elif data.startswith(b"BM"):
            format_hint = "bmp"
        elif data.startswith(b"%PDF"):
            format_hint = "pdf"
        elif data.startswith(b"\xff\xd8\xff"):
            format_hint = "jpeg"
        elif data.startswith(b"GIF8"):
            format_hint = "gif"
        elif data.startswith(b"<?xml") or data.startswith(b"<svg"):
            format_hint = "svg"

    # LSB analysis for images
    if format_hint == "png" or data.startswith(b"\x89PNG"):
        detector = PNGStegoDetector()
        results.extend(detector.detect(data))

    if format_hint == "bmp" or data.startswith(b"BM"):
        detector = BMPStegoDetector()
        results.extend(detector.detect(data))

    # Metadata analysis for PDFs
    if format_hint == "pdf" or data.startswith(b"%PDF"):
        detector = PDFMetadataDetector()
        results.extend(detector.detect(data))

    # SVG hidden text detection
    if format_hint == "svg" or data.startswith(b"<?xml") or data.startswith(b"<svg"):
        detector = SVGStegoDetector()
        results.extend(detector.detect(data))

    # Trailing data detection for all formats
    trailing_detector = TrailingDataDetector()
    results.extend(trailing_detector.detect(data, format_hint))

    # Sort by confidence
    results.sort(key=lambda x: x.confidence, reverse=True)

    return results
