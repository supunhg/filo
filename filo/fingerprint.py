"""
Temporal & Tool Fingerprinting - Forensic Attribution Engine

Identifies how, when, and with what tools a file was created.
Goes beyond format detection to answer: Who made this? When? How?
"""
import struct
import re
from datetime import datetime
from typing import List, Optional

from filo.models import Fingerprint


class ToolFingerprinter:
    """Extract tool/creator signatures from file formats."""
    
    def __init__(self):
        self.zip_os_map = {
            0: "MS-DOS/FAT",
            1: "Amiga",
            2: "OpenVMS",
            3: "Unix",
            4: "VM/CMS",
            5: "Atari ST",
            6: "OS/2 HPFS",
            7: "Macintosh",
            8: "Z-System",
            9: "CP/M",
            10: "Windows NTFS",
            11: "MVS",
            12: "VSE",
            13: "Acorn RISC",
            14: "VFAT",
            15: "Alternate MVS",
            16: "BeOS",
            17: "Tandem",
            18: "OS/400",
            19: "OS X Darwin"
        }
        
        self.zip_tool_hints = {
            (20, 3): "Unix (Info-ZIP)",
            (45, 3): "Unix (7-Zip)",
            (51, 3): "Unix (WinZip)",
            (20, 0): "Windows (early)",
            (45, 10): "Windows (7-Zip 9.20+)",
            (51, 10): "Windows (WinZip)",
            (63, 10): "Windows (modern)"
        }
        
        self.pdf_producers = {
            "Adobe": re.compile(rb"Adobe\s+(Acrobat|PDF Library|PDFMaker)\s+([\d.]+)"),
            "Microsoft": re.compile(rb"Microsoft\s+(Word|Excel|PowerPoint)\s+([\d.]+)"),
            "LibreOffice": re.compile(rb"LibreOffice\s+([\d.]+)"),
            "iText": re.compile(rb"iText\s+([\d.]+)"),
            "FPDF": re.compile(rb"FPDF\s+([\d.]+)"),
            "wkhtmltopdf": re.compile(rb"wkhtmltopdf\s+([\d.]+)"),
            "Chromium": re.compile(rb"Chromium|Chrome PDF Plugin"),
            "PDFKit": re.compile(rb"PDFKit\.NET\s+([\d.]+)"),
            "ReportLab": re.compile(rb"ReportLab\s+PDF\s+Library\s+([\d.]+)"),
            "Prince": re.compile(rb"Prince\s+([\d.]+)"),
        }
        
        self.office_build_patterns = {
            "Word": re.compile(rb"Microsoft Office Word ([\d.]+)"),
            "Excel": re.compile(rb"Microsoft Excel ([\d.]+)"),
            "PowerPoint": re.compile(rb"Microsoft PowerPoint ([\d.]+)"),
            "LibreOffice": re.compile(rb"LibreOffice_([\d.]+)"),
            "OpenOffice": re.compile(rb"OpenOffice\.org_([\d.]+)"),
        }
    
    def fingerprint_file(self, data: bytes, format_hint: Optional[str] = None) -> List[Fingerprint]:
        """Extract all fingerprints from file data."""
        fingerprints = []
        
        if format_hint == "zip" or data.startswith(b"PK"):
            fingerprints.extend(self._fingerprint_zip(data))
        
        if format_hint == "pdf" or data.startswith(b"%PDF"):
            fingerprints.extend(self._fingerprint_pdf(data))
        
        if format_hint in ("docx", "xlsx", "pptx", "odt", "ods", "odp"):
            fingerprints.extend(self._fingerprint_office(data, format_hint))
        
        return fingerprints
    
    def _fingerprint_zip(self, data: bytes) -> List[Fingerprint]:
        """Extract ZIP tool signatures from extra fields and headers."""
        fingerprints = []
        
        pos = 0
        while pos < len(data) - 30:
            if data[pos:pos+4] == b"PK\x03\x04":
                try:
                    version_needed = struct.unpack("<H", data[pos+4:pos+6])[0]
                    version_made = version_needed
                    struct.unpack("<H", data[pos+6:pos+8])[0]
                    method = struct.unpack("<H", data[pos+8:pos+10])[0]
                    mod_time = struct.unpack("<H", data[pos+10:pos+12])[0]
                    mod_date = struct.unpack("<H", data[pos+12:pos+14])[0]
                    
                    filename_len = struct.unpack("<H", data[pos+26:pos+28])[0]
                    extra_len = struct.unpack("<H", data[pos+28:pos+30])[0]
                    
                    timestamp = self._parse_dos_datetime(mod_date, mod_time)
                    
                    if data[pos:pos+4] == b"PK\x01\x02":
                        version_made = struct.unpack("<H", data[pos+4:pos+6])[0]
                    
                    os_code = (version_made >> 8) & 0xFF
                    zip_version = version_made & 0xFF
                    
                    os_name = self.zip_os_map.get(os_code, f"Unknown ({os_code})")
                    
                    tool_hint = self.zip_tool_hints.get((zip_version, os_code))
                    confidence = 0.85 if tool_hint else 0.70
                    
                    fingerprints.append(Fingerprint(
                        category="zip_creator",
                        tool=tool_hint.split("(")[1].rstrip(")") if tool_hint else None,
                        version=f"{zip_version / 10:.1f}",
                        os_hint=os_name,
                        timestamp=timestamp,
                        confidence=confidence,
                        evidence=f"Version {zip_version}, OS code {os_code}, method {method}"
                    ))
                    
                    if extra_len > 0 and pos + 30 + filename_len + extra_len <= len(data):
                        extra_start = pos + 30 + filename_len
                        extra_data = data[extra_start:extra_start + extra_len]
                        
                        extra_pos = 0
                        while extra_pos < len(extra_data) - 4:
                            header_id = struct.unpack("<H", extra_data[extra_pos:extra_pos+2])[0]
                            data_size = struct.unpack("<H", extra_data[extra_pos+2:extra_pos+4])[0]
                            
                            if header_id == 0x5455:
                                fingerprints.append(Fingerprint(
                                    category="zip_extended_timestamp",
                                    tool=None,
                                    version=None,
                                    os_hint="Unix",
                                    timestamp=None,
                                    confidence=0.90,
                                    evidence="Extended timestamp field (0x5455) - Unix origin"
                                ))
                            elif header_id == 0x7875:
                                fingerprints.append(Fingerprint(
                                    category="zip_unix_uid",
                                    tool=None,
                                    version=None,
                                    os_hint="Unix",
                                    timestamp=None,
                                    confidence=0.95,
                                    evidence="Unix UID/GID field (0x7875)"
                                ))
                            
                            extra_pos += 4 + data_size
                    
                    break
                
                except (struct.error, ValueError):
                    pass
            
            pos += 1
        
        return fingerprints
    
    def _fingerprint_pdf(self, data: bytes) -> List[Fingerprint]:
        """Extract PDF producer and creator metadata."""
        fingerprints = []
        
        search_data = data[:min(len(data), 100000)]
        
        for tool_name, pattern in self.pdf_producers.items():
            match = pattern.search(search_data)
            if match:
                version = match.group(2).decode('latin-1', errors='ignore') if match.lastindex >= 2 else None
                match.group(1).decode('latin-1', errors='ignore') if match.lastindex >= 1 else tool_name
                
                fingerprints.append(Fingerprint(
                    category="pdf_producer",
                    tool=tool_name,
                    version=version,
                    os_hint=None,
                    timestamp=None,
                    confidence=0.92,
                    evidence=f"Producer string: {match.group(0).decode('latin-1', errors='ignore')}"
                ))
        
        creation_date = re.search(rb"/CreationDate\s*\(D:(\d{14})", search_data)
        if creation_date:
            try:
                date_str = creation_date.group(1).decode('ascii')
                timestamp = datetime.strptime(date_str, "%Y%m%d%H%M%S")
                
                fingerprints.append(Fingerprint(
                    category="pdf_creation_date",
                    tool=None,
                    version=None,
                    os_hint=None,
                    timestamp=timestamp,
                    confidence=0.88,
                    evidence=f"Creation date: {timestamp.isoformat()}"
                ))
            except (ValueError, AttributeError):
                pass
        
        mod_date = re.search(rb"/ModDate\s*\(D:(\d{14})", search_data)
        if mod_date:
            try:
                date_str = mod_date.group(1).decode('ascii')
                timestamp = datetime.strptime(date_str, "%Y%m%d%H%M%S")
                
                fingerprints.append(Fingerprint(
                    category="pdf_modification_date",
                    tool=None,
                    version=None,
                    os_hint=None,
                    timestamp=timestamp,
                    confidence=0.88,
                    evidence=f"Modification date: {timestamp.isoformat()}"
                ))
            except (ValueError, AttributeError):
                pass
        
        return fingerprints
    
    def _fingerprint_office(self, data: bytes, format_hint: str) -> List[Fingerprint]:
        """Extract Office document build fingerprints."""
        fingerprints = []
        
        search_data = data[:min(len(data), 100000)]
        
        for app_name, pattern in self.office_build_patterns.items():
            match = pattern.search(search_data)
            if match:
                version = match.group(1).decode('latin-1', errors='ignore')
                
                os_hint = "Windows" if "Microsoft" in app_name else "Cross-platform"
                
                fingerprints.append(Fingerprint(
                    category="office_application",
                    tool=app_name,
                    version=version,
                    os_hint=os_hint,
                    timestamp=None,
                    confidence=0.90,
                    evidence=f"Application: {app_name} {version}"
                ))
        
        app_version = re.search(rb"AppVersion\s*=\s*\"([\d.]+)\"", search_data)
        if app_version:
            version = app_version.group(1).decode('ascii')
            fingerprints.append(Fingerprint(
                category="office_app_version",
                tool=None,
                version=version,
                os_hint=None,
                timestamp=None,
                confidence=0.85,
                evidence=f"AppVersion property: {version}"
            ))
        
        return fingerprints
    
    def _parse_dos_datetime(self, dos_date: int, dos_time: int) -> Optional[datetime]:
        """Convert DOS date/time to Python datetime."""
        try:
            year = ((dos_date >> 9) & 0x7F) + 1980
            month = (dos_date >> 5) & 0x0F
            day = dos_date & 0x1F
            
            hour = (dos_time >> 11) & 0x1F
            minute = (dos_time >> 5) & 0x3F
            second = (dos_time & 0x1F) * 2
            
            if 1980 <= year <= 2107 and 1 <= month <= 12 and 1 <= day <= 31:
                return datetime(year, month, day, hour, minute, second)
        except (ValueError, OverflowError):
            pass
        
        return None
