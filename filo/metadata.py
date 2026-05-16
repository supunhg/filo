"""
Metadata extraction for various file formats.
Extracts EXIF, IPTC, XMP, and other metadata from images and documents.
"""

import struct
import logging
from typing import List, Optional, Any
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class MetadataField(BaseModel):
    """Individual metadata field"""

    key: str = Field(description="Metadata field name")
    value: Any = Field(description="Field value")
    group: str = Field(description="Metadata group (e.g., 'EXIF', 'IPTC', 'XMP', 'File')")
    tag_id: Optional[int] = Field(default=None, description="Numeric tag ID if applicable")
    description: Optional[str] = Field(default=None, description="Human-readable description")


class MetadataResult(BaseModel):
    """Complete metadata extraction result"""

    format: str = Field(description="File format")
    fields: List[MetadataField] = Field(
        default_factory=list, description="Extracted metadata fields"
    )
    warnings: List[str] = Field(default_factory=list, description="Parsing warnings")
    has_suspicious: bool = Field(default=False, description="Contains suspicious/hidden data")
    suspicious_fields: List[str] = Field(
        default_factory=list, description="List of suspicious field names"
    )


class JPEGMetadataExtractor:
    """Extract metadata from JPEG files (JFIF, EXIF, IPTC, XMP)"""

    # EXIF tag names (most common ones)
    EXIF_TAGS = {
        # TIFF Tags
        0x010F: "Make",
        0x0110: "Model",
        0x0112: "Orientation",
        0x011A: "XResolution",
        0x011B: "YResolution",
        0x0128: "ResolutionUnit",
        0x0131: "Software",
        0x0132: "DateTime",
        0x013B: "Artist",
        0x8298: "Copyright",
        # EXIF Tags
        0x829A: "ExposureTime",
        0x829D: "FNumber",
        0x8822: "ExposureProgram",
        0x8827: "ISOSpeedRatings",
        0x9000: "ExifVersion",
        0x9003: "DateTimeOriginal",
        0x9004: "DateTimeDigitized",
        0x9101: "ComponentsConfiguration",
        0x9102: "CompressedBitsPerPixel",
        0x9201: "ShutterSpeedValue",
        0x9202: "ApertureValue",
        0x9203: "BrightnessValue",
        0x9204: "ExposureBiasValue",
        0x9205: "MaxApertureValue",
        0x9206: "SubjectDistance",
        0x9207: "MeteringMode",
        0x9208: "LightSource",
        0x9209: "Flash",
        0x920A: "FocalLength",
        0x927C: "MakerNote",
        0x9286: "UserComment",
        0xA000: "FlashpixVersion",
        0xA001: "ColorSpace",
        0xA002: "PixelXDimension",
        0xA003: "PixelYDimension",
        0xA20E: "FocalPlaneXResolution",
        0xA20F: "FocalPlaneYResolution",
        0xA210: "FocalPlaneResolutionUnit",
        0xA217: "SensingMethod",
        0xA300: "FileSource",
        0xA301: "SceneType",
    }

    def extract(self, data: bytes) -> MetadataResult:
        """Extract all metadata from JPEG file"""
        result = MetadataResult(format="JPEG")

        if not data.startswith(b"\xff\xd8\xff"):
            result.warnings.append("Not a valid JPEG file")
            return result

        # Track width/height for computed fields
        image_width = None
        image_height = None
        encoding_process = None
        subsampling = None

        # Extract basic file info
        result.fields.append(
            MetadataField(key="FileType", value="JPEG", group="File", description="JPEG image")
        )

        result.fields.append(
            MetadataField(key="MIMEType", value="image/jpeg", group="File", description="MIME type")
        )

        result.fields.append(
            MetadataField(key="FileSize", value=f"{len(data)} bytes", group="File")
        )

        # Parse JPEG segments
        offset = 2  # Skip SOI marker (FFD8)

        while offset < len(data) - 1:
            # Look for marker
            if data[offset] != 0xFF:
                break

            marker = data[offset + 1]
            offset += 2

            # Check for markers without length
            if marker in (0xD8, 0xD9, 0x01) or (0xD0 <= marker <= 0xD7):
                continue

            # EOI marker
            if marker == 0xD9:
                break

            # Read segment length
            if offset + 2 > len(data):
                break

            segment_len = struct.unpack(">H", data[offset : offset + 2])[0]
            segment_data = data[offset + 2 : offset + segment_len]

            # APP0 - JFIF
            if marker == 0xE0 and segment_data.startswith(b"JFIF\x00"):
                self._extract_jfif(segment_data, result)

            # APP1 - EXIF
            elif marker == 0xE1 and segment_data.startswith(b"Exif\x00\x00"):
                self._extract_exif(segment_data[6:], result)

            # APP1 - XMP
            elif marker == 0xE1 and segment_data.startswith(b"http://ns.adobe.com/xap/1.0/\x00"):
                self._extract_xmp(segment_data[29:], result)

            # APP2 - ICC Profile
            elif marker == 0xE2 and segment_data.startswith(b"ICC_PROFILE\x00"):
                self._extract_icc_profile(segment_data[12:], result)

            # APP13 - IPTC/Photoshop
            elif marker == 0xED and segment_data.startswith(b"Photoshop 3.0\x00"):
                self._extract_iptc(segment_data[14:], result)

            # COM - Comment
            elif marker == 0xFE:
                comment = segment_data.decode("utf-8", errors="ignore").strip()
                if comment:
                    result.fields.append(
                        MetadataField(
                            key="Comment",
                            value=comment,
                            group="JPEG",
                            description="JPEG comment marker",
                        )
                    )
                    # Check for suspicious patterns
                    if self._is_suspicious(comment):
                        result.has_suspicious = True
                        result.suspicious_fields.append("Comment")

            # SOF markers - image info
            elif marker in (
                0xC0,
                0xC1,
                0xC2,
                0xC3,
                0xC5,
                0xC6,
                0xC7,
                0xC9,
                0xCA,
                0xCB,
                0xCD,
                0xCE,
                0xCF,
            ):
                if len(segment_data) >= 6:
                    bits_per_sample = segment_data[0]
                    height = struct.unpack(">H", segment_data[1:3])[0]
                    width = struct.unpack(">H", segment_data[3:5])[0]
                    num_components = segment_data[5]

                    image_width = width
                    image_height = height

                    # Determine encoding process
                    sof_types = {
                        0xC0: "Baseline DCT, Huffman coding",
                        0xC1: "Extended sequential DCT, Huffman coding",
                        0xC2: "Progressive DCT, Huffman coding",
                        0xC3: "Lossless, Huffman coding",
                        0xC5: "Differential sequential DCT, Huffman coding",
                        0xC6: "Differential progressive DCT, Huffman coding",
                        0xC7: "Differential lossless, Huffman coding",
                        0xC9: "Extended sequential DCT, Arithmetic coding",
                        0xCA: "Progressive DCT, Arithmetic coding",
                        0xCB: "Lossless, Arithmetic coding",
                        0xCD: "Differential sequential DCT, Arithmetic coding",
                        0xCE: "Differential progressive DCT, Arithmetic coding",
                        0xCF: "Differential lossless, Arithmetic coding",
                    }
                    encoding_process = sof_types.get(marker, f"Unknown SOF marker 0x{marker:02X}")

                    # Extract subsampling if available
                    if len(segment_data) >= 17 and num_components == 3:
                        # YCbCr subsampling
                        y_h = (segment_data[7] >> 4) & 0x0F
                        y_v = segment_data[7] & 0x0F
                        cb_h = (segment_data[10] >> 4) & 0x0F
                        cb_v = segment_data[10] & 0x0F

                        subsampling = f"YCbCr4:{cb_h*4//y_h}:{cb_v*4//y_v} ({y_h} {y_v})"

                    result.fields.append(
                        MetadataField(
                            key="ImageWidth",
                            value=width,
                            group="JPEG",
                            description="Image width in pixels",
                        )
                    )
                    result.fields.append(
                        MetadataField(
                            key="ImageHeight",
                            value=height,
                            group="JPEG",
                            description="Image height in pixels",
                        )
                    )
                    result.fields.append(
                        MetadataField(key="EncodingProcess", value=encoding_process, group="JPEG")
                    )
                    result.fields.append(
                        MetadataField(key="BitsPerSample", value=bits_per_sample, group="JPEG")
                    )
                    result.fields.append(
                        MetadataField(key="ColorComponents", value=num_components, group="JPEG")
                    )
                    if subsampling:
                        result.fields.append(
                            MetadataField(key="YCbCrSubSampling", value=subsampling, group="JPEG")
                        )

            offset += segment_len

        # Add computed fields
        if image_width and image_height:
            result.fields.append(
                MetadataField(
                    key="ImageSize", value=f"{image_width}x{image_height}", group="Computed"
                )
            )
            megapixels = (image_width * image_height) / 1_000_000
            result.fields.append(
                MetadataField(key="Megapixels", value=f"{megapixels:.1f}", group="Computed")
            )

        return result

    def _extract_jfif(self, data: bytes, result: MetadataResult) -> None:
        """Extract JFIF metadata"""
        if len(data) < 14:
            return

        version = f"{data[5]}.{data[6]:02d}"
        density_units_map = {0: "None", 1: "inches", 2: "cm"}
        density_units = density_units_map.get(data[7], "Unknown")
        x_density = struct.unpack(">H", data[8:10])[0]
        y_density = struct.unpack(">H", data[10:12])[0]

        result.fields.append(MetadataField(key="JFIFVersion", value=version, group="JFIF"))
        result.fields.append(MetadataField(key="ResolutionUnit", value=density_units, group="JFIF"))
        result.fields.append(MetadataField(key="XResolution", value=x_density, group="JFIF"))
        result.fields.append(MetadataField(key="YResolution", value=y_density, group="JFIF"))

    def _extract_exif(self, data: bytes, result: MetadataResult) -> None:
        """Extract EXIF metadata"""
        if len(data) < 8:
            return

        # Check byte order
        byte_order = data[0:2]
        if byte_order == b"II":  # Intel (little-endian)
            endian = "<"
        elif byte_order == b"MM":  # Motorola (big-endian)
            endian = ">"
        else:
            result.warnings.append("Invalid EXIF byte order")
            return

        # Verify TIFF magic number
        magic = struct.unpack(f"{endian}H", data[2:4])[0]
        if magic != 42:
            result.warnings.append("Invalid TIFF magic number in EXIF")
            return

        # Get IFD0 offset
        ifd0_offset = struct.unpack(f"{endian}I", data[4:8])[0]

        # Parse IFD0
        self._parse_ifd(data, ifd0_offset, endian, result, "EXIF")

    def _parse_ifd(self, data: bytes, offset: int, endian: str, result: MetadataResult, group: str) -> None:
        """Parse an Image File Directory (IFD)"""
        if offset + 2 > len(data):
            return

        num_entries = struct.unpack(f"{endian}H", data[offset : offset + 2])[0]
        offset += 2

        for i in range(num_entries):
            if offset + 12 > len(data):
                break

            tag = struct.unpack(f"{endian}H", data[offset : offset + 2])[0]
            field_type = struct.unpack(f"{endian}H", data[offset + 2 : offset + 4])[0]
            count = struct.unpack(f"{endian}I", data[offset + 4 : offset + 8])[0]
            value_offset = offset + 8

            # Extract value based on type
            value = self._extract_exif_value(data, value_offset, field_type, count, endian)

            # Get tag name
            tag_name = self.EXIF_TAGS.get(tag, f"Tag_{tag:04X}")

            if value is not None:
                result.fields.append(
                    MetadataField(key=tag_name, value=value, group=group, tag_id=tag)
                )

                # Check for suspicious content
                if isinstance(value, str) and self._is_suspicious(value):
                    result.has_suspicious = True
                    result.suspicious_fields.append(tag_name)

            offset += 12

    def _extract_exif_value(
        self, data: bytes, offset: int, field_type: int, count: int, endian: str
    ) -> Any:
        """Extract EXIF field value based on type"""
        try:
            # Type 1: BYTE
            if field_type == 1:
                if count == 1:
                    return data[offset]
                return list(data[offset : offset + count])

            # Type 2: ASCII
            elif field_type == 2:
                if offset + count > len(data):
                    # Value is stored at offset specified in value field
                    value_offset = struct.unpack(f"{endian}I", data[offset : offset + 4])[0]
                    if value_offset + count <= len(data):
                        return (
                            data[value_offset : value_offset + count]
                            .rstrip(b"\x00")
                            .decode("utf-8", errors="ignore")
                        )
                else:
                    return (
                        data[offset : offset + count]
                        .rstrip(b"\x00")
                        .decode("utf-8", errors="ignore")
                    )

            # Type 3: SHORT
            elif field_type == 3:
                if count == 1:
                    return struct.unpack(f"{endian}H", data[offset : offset + 2])[0]
                values = []
                for i in range(min(count, 2)):
                    values.append(
                        struct.unpack(f"{endian}H", data[offset + i * 2 : offset + i * 2 + 2])[0]
                    )
                return values if len(values) > 1 else values[0]

            # Type 4: LONG
            elif field_type == 4:
                if count == 1:
                    return struct.unpack(f"{endian}I", data[offset : offset + 4])[0]

            # Type 5: RATIONAL
            elif field_type == 5:
                if count == 1:
                    value_offset = struct.unpack(f"{endian}I", data[offset : offset + 4])[0]
                    if value_offset + 8 <= len(data):
                        numerator = struct.unpack(
                            f"{endian}I", data[value_offset : value_offset + 4]
                        )[0]
                        denominator = struct.unpack(
                            f"{endian}I", data[value_offset + 4 : value_offset + 8]
                        )[0]
                        if denominator != 0:
                            return f"{numerator}/{denominator}"

            # Type 7: UNDEFINED
            elif field_type == 7:
                if count <= 4:
                    return data[offset : offset + count]

            # Type 9: SLONG
            elif field_type == 9:
                if count == 1:
                    return struct.unpack(f"{endian}i", data[offset : offset + 4])[0]

            # Type 10: SRATIONAL
            elif field_type == 10:
                if count == 1:
                    value_offset = struct.unpack(f"{endian}I", data[offset : offset + 4])[0]
                    if value_offset + 8 <= len(data):
                        numerator = struct.unpack(
                            f"{endian}i", data[value_offset : value_offset + 4]
                        )[0]
                        denominator = struct.unpack(
                            f"{endian}i", data[value_offset + 4 : value_offset + 8]
                        )[0]
                        if denominator != 0:
                            return f"{numerator}/{denominator}"

        except Exception as e:
            logger.debug(f"Failed to extract EXIF value: {e}")

        return None

    def _extract_xmp(self, data: bytes, result: MetadataResult) -> None:
        """Extract XMP metadata (parse key fields from XML)"""
        try:
            xmp = data.decode("utf-8", errors="ignore")

            # Extract common XMP fields using simple parsing
            import re

            # cc:license - often contains hidden data
            license_match = re.search(r"<cc:license[^>]*rdf:resource=['\"]([^'\"]+)['\"]", xmp)
            if license_match:
                license_value = license_match.group(1)
                result.fields.append(
                    MetadataField(
                        key="License",
                        value=license_value,
                        group="XMP",
                        description="Creative Commons license",
                    )
                )
                if self._is_suspicious(license_value):
                    result.has_suspicious = True
                    result.suspicious_fields.append("License")

            # dc:rights
            rights_match = re.search(
                r"<dc:rights>\s*<rdf:Alt>\s*<rdf:li[^>]*>([^<]+)", xmp, re.DOTALL
            )
            if rights_match:
                rights_value = rights_match.group(1).strip()
                result.fields.append(MetadataField(key="Rights", value=rights_value, group="XMP"))

            # dc:creator
            creator_match = re.search(r"<dc:creator>\s*<rdf:Seq>\s*<rdf:li>([^<]+)", xmp)
            if creator_match:
                result.fields.append(
                    MetadataField(key="Creator", value=creator_match.group(1), group="XMP")
                )

            # dc:title
            title_match = re.search(
                r"<dc:title>\s*<rdf:Alt>\s*<rdf:li[^>]*>([^<]+)", xmp, re.DOTALL
            )
            if title_match:
                result.fields.append(
                    MetadataField(key="Title", value=title_match.group(1).strip(), group="XMP")
                )

            # xmp:CreatorTool / tiff:Software
            tool_match = re.search(r"<(?:xmp:CreatorTool|tiff:Software)>([^<]+)", xmp)
            if tool_match:
                result.fields.append(
                    MetadataField(key="XMPToolkit", value=tool_match.group(1), group="XMP")
                )

            # Store full XMP as well (truncated for display)
            result.fields.append(
                MetadataField(
                    key="XMP_Raw",
                    value=xmp[:500] if len(xmp) > 500 else xmp,
                    group="XMP",
                    description=(
                        "Raw XMP metadata (truncated)" if len(xmp) > 500 else "Raw XMP metadata"
                    ),
                )
            )

        except Exception as e:
            result.warnings.append(f"Failed to extract XMP: {e}")

    def _extract_iptc(self, data: bytes, result: MetadataResult) -> None:
        """Extract IPTC metadata"""
        try:
            # IPTC uses 8BIM resource blocks
            offset = 0
            while offset < len(data) - 12:
                # Look for 8BIM signature
                if data[offset : offset + 4] == b"8BIM":
                    resource_id = struct.unpack(">H", data[offset + 4 : offset + 6])[0]

                    # Skip name (pascal string)
                    name_len = data[offset + 6]
                    # Name length is padded to even
                    name_padding = 1 if name_len % 2 == 0 else 0
                    name_offset = offset + 7 + name_len + name_padding

                    if name_offset + 4 > len(data):
                        break

                    # Resource data size
                    data_size = struct.unpack(">I", data[name_offset : name_offset + 4])[0]
                    data_start = name_offset + 4

                    if data_start + data_size > len(data):
                        break

                    # Resource 0x0404 = IPTC data
                    if resource_id == 0x0404:
                        iptc_data = data[data_start : data_start + data_size]
                        self._parse_iptc_records(iptc_data, result)
                        return

                    # Move to next resource (pad to even)
                    offset = data_start + data_size
                    if data_size % 2 == 1:
                        offset += 1
                else:
                    offset += 1

            # If we didn't find detailed IPTC, just note presence
            result.fields.append(
                MetadataField(
                    key="IPTC",
                    value="Present",
                    group="IPTC",
                    description="IPTC/Photoshop metadata block found",
                )
            )
        except Exception as e:
            logger.debug(f"Failed to extract IPTC: {e}")

    def _parse_iptc_records(self, data: bytes, result: MetadataResult) -> None:
        """Parse IPTC records from data"""
        offset = 0
        while offset < len(data) - 5:
            # IPTC record format: 0x1C, record number, dataset number, length
            if data[offset] != 0x1C:
                offset += 1
                continue

            record_num = data[offset + 1]
            dataset_num = data[offset + 2]

            # Get length (can be 2 or 4 bytes)
            if offset + 4 > len(data):
                break

            length_bytes = struct.unpack(">H", data[offset + 3 : offset + 5])[0]

            # Extended format (length > 32767)
            if length_bytes > 0x7FFF:
                if offset + 7 > len(data):
                    break
                length = struct.unpack(">I", data[offset + 5 : offset + 9])[0]
                value_start = offset + 9
            else:
                length = length_bytes
                value_start = offset + 5

            if value_start + length > len(data):
                break

            value_data = data[value_start : value_start + length]

            # Common IPTC fields (Application Record 2)
            if record_num == 2:
                iptc_fields = {
                    5: "ObjectName",
                    25: "Keywords",
                    40: "SpecialInstructions",
                    80: "ByLine",  # Author
                    85: "ByLineTitle",
                    90: "City",
                    95: "ProvinceState",
                    100: "CountryCode",
                    101: "CountryName",
                    105: "Headline",
                    110: "Credit",
                    115: "Source",
                    116: "CopyrightNotice",
                    118: "Contact",
                    120: "Caption",
                    122: "CaptionWriter",
                }

                field_name = iptc_fields.get(dataset_num)
                if field_name:
                    try:
                        value = value_data.decode("utf-8", errors="ignore").strip()
                        if value:
                            result.fields.append(
                                MetadataField(key=field_name, value=value, group="IPTC")
                            )

                            # Check for suspicious content
                            if self._is_suspicious(value):
                                result.has_suspicious = True
                                result.suspicious_fields.append(field_name)
                    except Exception:
                        pass

            offset = value_start + length

    def _extract_icc_profile(self, data: bytes, result: MetadataResult) -> None:
        """Extract ICC color profile metadata"""
        if len(data) < 128:
            return

        try:
            # ICC Profile header structure
            # Bytes 0-3: Profile size
            # Bytes 4-7: CMM Type
            # Bytes 8-11: Profile version
            # Bytes 12-15: Profile class
            # Bytes 16-19: Color space
            # Bytes 20-23: PCS (Profile Connection Space)

            if len(data) >= 4:
                # Skip sequence number (first 2 bytes in APP2 ICC)
                if data[0] in range(1, 256) and data[1] in range(1, 256):
                    data = data[2:]  # Skip sequence marker

            if len(data) >= 128:
                # CMM Type (bytes 4-7)
                cmm_type = data[4:8].decode("ascii", errors="ignore").strip()
                if cmm_type:
                    result.fields.append(
                        MetadataField(key="ProfileCMMType", value=cmm_type, group="ICC_Profile")
                    )

                # Profile version (bytes 8-11)
                if len(data) >= 12:
                    major = data[8]
                    minor = data[9] >> 4
                    patch = data[9] & 0x0F
                    version = f"{major}.{minor}.{patch}"
                    result.fields.append(
                        MetadataField(key="ProfileVersion", value=version, group="ICC_Profile")
                    )

                # Profile class (bytes 12-15)
                if len(data) >= 16:
                    profile_class_map = {
                        b"scnr": "Input Device Profile",
                        b"mntr": "Display Device Profile",
                        b"prtr": "Output Device Profile",
                        b"link": "DeviceLink Profile",
                        b"spac": "ColorSpace Profile",
                        b"abst": "Abstract Profile",
                        b"nmcl": "NamedColor Profile",
                    }
                    profile_class_sig = data[12:16]
                    profile_class = profile_class_map.get(
                        profile_class_sig, profile_class_sig.decode("ascii", errors="ignore")
                    )
                    result.fields.append(
                        MetadataField(key="ProfileClass", value=profile_class, group="ICC_Profile")
                    )

                # Color space (bytes 16-19)
                if len(data) >= 20:
                    color_space = data[16:20].decode("ascii", errors="ignore").strip()
                    result.fields.append(
                        MetadataField(key="ColorSpaceData", value=color_space, group="ICC_Profile")
                    )

                # Profile Connection Space (bytes 20-23)
                if len(data) >= 24:
                    pcs = data[20:24].decode("ascii", errors="ignore").strip()
                    result.fields.append(
                        MetadataField(key="ProfileConnectionSpace", value=pcs, group="ICC_Profile")
                    )

                # Copyright (tag 'cprt' - search in tag table)
                # Profile Description (tag 'desc')
                if len(data) >= 128:
                    # Simple search for common text tags
                    desc_start = data.find(b"desc\x00\x00\x00\x00")
                    if desc_start > 0 and desc_start + 12 < len(data):
                        # Try to extract description
                        desc_offset = struct.unpack(">I", data[desc_start + 4 : desc_start + 8])[0]
                        desc_size = struct.unpack(">I", data[desc_start + 8 : desc_start + 12])[0]
                        if desc_offset < len(data) and desc_size < 1000:
                            try:
                                # Skip to actual description text (usually has length prefix)
                                desc_data = data[desc_offset : desc_offset + min(desc_size, 200)]
                                if len(desc_data) > 12:
                                    # Skip length prefix and try to extract text
                                    desc_text = (
                                        desc_data[12:]
                                        .split(b"\x00")[0]
                                        .decode("ascii", errors="ignore")
                                    )
                                    if desc_text:
                                        result.fields.append(
                                            MetadataField(
                                                key="ProfileDescription",
                                                value=desc_text,
                                                group="ICC_Profile",
                                            )
                                        )
                            except Exception:
                                pass

        except Exception as e:
            logger.debug(f"Failed to extract ICC profile: {e}")

    def _is_suspicious(self, text: str) -> bool:
        """Check if text contains suspicious patterns (base64, encoded data, etc.)"""
        if not text:
            return False

        # Check for base64-like patterns
        import re

        # Long base64 strings (likely encoded data) - reduced threshold for CTF scenarios
        if re.search(r"[A-Za-z0-9+/]{20,}={0,2}", text):
            return True

        # Steghide signature
        if "steghide" in text.lower():
            return True

        # Common encoding prefixes
        suspicious_patterns = [
            "data:",
            "base64:",
            "encrypted:",
            "hidden:",
            "0x[0-9a-fA-F]{20,}",
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True

        return False


class PNGMetadataExtractor:
    """Extract metadata from PNG files"""

    def extract(self, data: bytes) -> MetadataResult:
        """Extract PNG metadata from text chunks"""
        result = MetadataResult(format="PNG")

        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            result.warnings.append("Not a valid PNG file")
            return result

        result.fields.append(MetadataField(key="FileType", value="PNG", group="File"))

        offset = 8  # Skip PNG signature

        while offset < len(data):
            if offset + 8 > len(data):
                break

            try:
                chunk_len = struct.unpack(">I", data[offset : offset + 4])[0]
                chunk_type = data[offset + 4 : offset + 8]
                chunk_data = data[offset + 8 : offset + 8 + chunk_len]

                # IHDR - Image header
                if chunk_type == b"IHDR" and len(chunk_data) >= 13:
                    width = struct.unpack(">I", chunk_data[0:4])[0]
                    height = struct.unpack(">I", chunk_data[4:8])[0]
                    bit_depth = chunk_data[8]
                    color_type = chunk_data[9]

                    result.fields.append(MetadataField(key="ImageWidth", value=width, group="PNG"))
                    result.fields.append(
                        MetadataField(key="ImageHeight", value=height, group="PNG")
                    )
                    result.fields.append(
                        MetadataField(key="BitDepth", value=bit_depth, group="PNG")
                    )
                    result.fields.append(
                        MetadataField(key="ColorType", value=color_type, group="PNG")
                    )

                # tEXt chunk
                elif chunk_type == b"tEXt":
                    null_pos = chunk_data.find(b"\x00")
                    if null_pos > 0:
                        keyword = chunk_data[:null_pos].decode("latin1", errors="ignore")
                        text = chunk_data[null_pos + 1 :].decode("latin1", errors="ignore")

                        result.fields.append(
                            MetadataField(key=keyword, value=text, group="PNG_Text")
                        )

                        if self._is_suspicious(text):
                            result.has_suspicious = True
                            result.suspicious_fields.append(keyword)

                # zTXt chunk (compressed text)
                elif chunk_type == b"zTXt":
                    null_pos = chunk_data.find(b"\x00")
                    if null_pos > 0:
                        keyword = chunk_data[:null_pos].decode("latin1", errors="ignore")
                        if len(chunk_data) > null_pos + 2:
                            import zlib

                            try:
                                text = zlib.decompress(chunk_data[null_pos + 2 :]).decode(
                                    "latin1", errors="ignore"
                                )
                                result.fields.append(
                                    MetadataField(key=keyword, value=text, group="PNG_Text")
                                )

                                if self._is_suspicious(text):
                                    result.has_suspicious = True
                                    result.suspicious_fields.append(keyword)
                            except Exception:
                                pass

                # tIME chunk
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

                    result.fields.append(
                        MetadataField(key="ModificationTime", value=time_str, group="PNG")
                    )

                # pHYs chunk - physical pixel dimensions
                elif chunk_type == b"pHYs" and len(chunk_data) >= 9:
                    x_pixels = struct.unpack(">I", chunk_data[0:4])[0]
                    y_pixels = struct.unpack(">I", chunk_data[4:8])[0]
                    unit = chunk_data[8]

                    unit_str = "meters" if unit == 1 else "unknown"
                    result.fields.append(
                        MetadataField(
                            key="PixelsPerUnit",
                            value=f"{x_pixels}x{y_pixels} per {unit_str}",
                            group="PNG",
                        )
                    )

                # IEND - end of PNG
                elif chunk_type == b"IEND":
                    break

                offset += 12 + chunk_len

            except Exception as e:
                logger.debug(f"Error parsing PNG chunk at offset {offset}: {e}")
                break

        return result

    def _is_suspicious(self, text: str) -> bool:
        """Check if text contains suspicious patterns"""
        if not text:
            return False

        import re

        # Base64-like patterns - reduced threshold for CTF scenarios
        if re.search(r"[A-Za-z0-9+/]{20,}={0,2}", text):
            return True

        # Steghide
        if "steghide" in text.lower():
            return True

        return False


def extract_metadata(data: bytes, format_hint: Optional[str] = None) -> MetadataResult:
    """
    Extract metadata from file.

    Args:
        data: File data or path
        format_hint: Optional format hint ('jpeg', 'png', etc.)

    Returns:
        MetadataResult with extracted fields
    """
    # If data is a string, treat it as a file path
    if isinstance(data, str):
        with open(data, "rb") as f:
            data = f.read()

    # Auto-detect format
    if format_hint is None:
        if data.startswith(b"\xff\xd8\xff"):
            format_hint = "jpeg"
        elif data.startswith(b"\x89PNG"):
            format_hint = "png"

    # Extract based on format
    if format_hint == "jpeg" or data.startswith(b"\xff\xd8\xff"):
        extractor: JPEGMetadataExtractor | PNGMetadataExtractor = JPEGMetadataExtractor()
        return extractor.extract(data)

    elif format_hint == "png" or data.startswith(b"\x89PNG"):
        extractor = PNGMetadataExtractor()
        return extractor.extract(data)

    # Unsupported format
    return MetadataResult(format="unknown", warnings=["Unsupported format for metadata extraction"])
