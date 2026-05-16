"""
PCAP Analysis Module

Basic PCAP file analyzer for CTF challenges.
Focuses on quick triage and data extraction without heavy dependencies.
"""

import struct
import re
from dataclasses import dataclass
from typing import Optional, List, Tuple
from collections import Counter
import logging

logger = logging.getLogger(__name__)


@dataclass
class PCAPStats:
    """Statistics from PCAP analysis."""

    packet_count: int
    total_bytes: int
    protocols: Counter[str]
    strings: List[str]
    base64_data: List[Tuple[str, str]]  # (raw, decoded)
    flags: List[str]
    http_requests: List[str]
    file_size: int


class PCAPAnalyzer:
    """Analyze PCAP files for CTF challenges."""

    def __init__(self) -> None:
        self.packet_count = 0
        self.total_bytes = 0
        self.protocols: Counter[str] = Counter()
        self.strings: list[str] = []
        self.base64_data: list[tuple[str, str]] = []
        self.flags: list[str] = []
        self.http_requests: list[str] = []

    def parse_pcap(self, data: bytes) -> Optional[PCAPStats]:
        """Parse PCAP file and extract relevant information.

        Args:
            data: Raw PCAP file data

        Returns:
            PCAPStats or None if parsing fails
        """
        try:
            # Check PCAP magic number
            if len(data) < 24:
                return None

            magic = struct.unpack("<I", data[0:4])[0]

            # pcap magic numbers (little-endian and big-endian)
            if magic == 0xA1B2C3D4:
                endian = "<"  # little-endian
            elif magic == 0xD4C3B2A1:
                endian = ">"  # big-endian
            else:
                return None

            # Parse global header
            # magic(4) version_major(2) version_minor(2) thiszone(4) sigfigs(4) snaplen(4) network(4)
            offset = 24

            # Parse packets
            payloads = []
            while offset < len(data):
                if offset + 16 > len(data):
                    break

                # Packet header: ts_sec(4) ts_usec(4) incl_len(4) orig_len(4)
                try:
                    incl_len = struct.unpack(f"{endian}I", data[offset + 8 : offset + 12])[0]
                    struct.unpack(f"{endian}I", data[offset + 12 : offset + 16])[0]
                except Exception:
                    break

                offset += 16

                if offset + incl_len > len(data):
                    break

                # Extract packet data
                packet_data = data[offset : offset + incl_len]
                payloads.append(packet_data)

                self.packet_count += 1
                self.total_bytes += incl_len

                # Try to identify protocol
                self._analyze_packet(packet_data)

                offset += incl_len

            # Extract strings from all payloads
            all_payload = b"".join(payloads)
            self._extract_strings(all_payload)
            self._extract_base64(all_payload)
            self._extract_flags(all_payload)
            self._extract_http(all_payload)

            return PCAPStats(
                packet_count=self.packet_count,
                total_bytes=self.total_bytes,
                protocols=self.protocols,
                strings=self.strings[:50],  # Limit to 50 most interesting
                base64_data=self.base64_data[:20],
                flags=self.flags,
                http_requests=self.http_requests[:20],
                file_size=len(data),
            )

        except Exception as e:
            logger.debug(f"PCAP parsing error: {e}")
            return None

    def _analyze_packet(self, packet: bytes) -> None:
        """Analyze a single packet to identify protocols."""
        if len(packet) < 14:
            return

        # Ethernet header is 14 bytes
        # We can check EtherType (bytes 12-13)
        try:
            ethertype = struct.unpack(">H", packet[12:14])[0]

            if ethertype == 0x0800:  # IPv4
                self.protocols["IPv4"] += 1
                self._analyze_ipv4(packet[14:])
            elif ethertype == 0x0806:  # ARP
                self.protocols["ARP"] += 1
            elif ethertype == 0x86DD:  # IPv6
                self.protocols["IPv6"] += 1
        except Exception:
            pass

    def _analyze_ipv4(self, ip_packet: bytes) -> None:
        """Analyze IPv4 packet."""
        if len(ip_packet) < 20:
            return

        try:
            protocol = ip_packet[9]

            if protocol == 6:  # TCP
                self.protocols["TCP"] += 1
            elif protocol == 17:  # UDP
                self.protocols["UDP"] += 1
            elif protocol == 1:  # ICMP
                self.protocols["ICMP"] += 1
        except Exception:
            pass

    def _extract_strings(self, data: bytes) -> None:
        """Extract printable ASCII strings."""
        current = []
        min_len = 8

        for byte in data:
            if 32 <= byte <= 126:
                current.append(chr(byte))
            else:
                if len(current) >= min_len:
                    s = "".join(current)
                    # Filter out common noise
                    if not all(c in "0123456789ABCDEFabcdef" for c in s):
                        self.strings.append(s)
                current = []

        # Check final string
        if len(current) >= min_len:
            s = "".join(current)
            if not all(c in "0123456789ABCDEFabcdef" for c in s):
                self.strings.append(s)

        # Remove duplicates while preserving order
        seen = set()
        unique = []
        for s in self.strings:
            if s not in seen:
                seen.add(s)
                unique.append(s)
        self.strings = unique

    def _extract_base64(self, data: bytes) -> None:
        """Extract and decode base64 patterns."""
        import base64

        try:
            text = data.decode("latin-1")
            # Base64 pattern: at least 20 chars
            pattern = re.compile(r"([A-Za-z0-9+/]{20,}={0,2})")
            matches = pattern.findall(text)

            for b64_str in matches[:20]:  # Limit to first 20
                try:
                    # Pad if necessary
                    missing = len(b64_str) % 4
                    if missing:
                        b64_str += "=" * (4 - missing)

                    decoded = base64.b64decode(b64_str)
                    # Only keep if it decodes to printable text
                    if all(32 <= b <= 126 or b in (9, 10, 13) for b in decoded):
                        decoded_str = decoded.decode("utf-8", errors="ignore")
                        self.base64_data.append((b64_str[:50], decoded_str))
                except Exception:
                    pass
        except Exception:
            pass

    def _extract_flags(self, data: bytes) -> None:
        """Extract common CTF flag patterns."""
        try:
            text = data.decode("latin-1")

            patterns = [
                r"picoCTF\{[^}]{5,}\}",
                r"flag\{[^}]{5,}\}",
                r"FLAG\{[^}]{5,}\}",
                r"HTB\{[^}]{5,}\}",
                r"CTF\{[^}]{5,}\}",
            ]

            for pattern in patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                self.flags.extend(matches)
        except Exception:
            pass

    def _extract_http(self, data: bytes) -> None:
        """Extract HTTP requests and interesting headers."""
        try:
            text = data.decode("latin-1")

            # Find HTTP request lines
            http_pattern = re.compile(r"(GET|POST|PUT|DELETE|HEAD|OPTIONS) ([^\s]+) HTTP/[\d.]+")
            matches = http_pattern.findall(text)

            for method, path in matches:
                self.http_requests.append(f"{method} {path}")

            # Also look for Host headers to construct full URLs
            host_pattern = re.compile(r"Host: ([^\r\n]+)")
            host_pattern.findall(text)

        except Exception:
            pass


def analyze_pcap(file_path: str) -> Optional[PCAPStats]:
    """Analyze a PCAP file.

    Args:
        file_path: Path to PCAP file

    Returns:
        PCAPStats or None if not a valid PCAP
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        analyzer = PCAPAnalyzer()
        return analyzer.parse_pcap(data)
    except Exception as e:
        logger.error(f"Failed to analyze PCAP: {e}")
        return None
