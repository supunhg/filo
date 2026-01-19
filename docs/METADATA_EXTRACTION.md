# Metadata Extraction 🔍📋

**Quick, forensic-grade metadata extraction for image files - like exiftool, but CTF-optimized.**

## 🎯 Overview

Filo's metadata extractor (`filo meta`) provides comprehensive metadata extraction from image files with built-in suspicious content detection. Perfect for CTF challenges, forensic analysis, and steganography investigation.

### Key Features

- **📷 JPEG Support**: JFIF, EXIF, IPTC, XMP, ICC profiles, comments
- **🖼️ PNG Support**: tEXt, zTXt, iTXt chunks, modification times, physical dimensions
- **🚨 Suspicious Detection**: Auto-flags base64, steghide hints, encoded data
- **⚡ Fast Analysis**: Quick `-s` flag for suspicious-only filtering
- **📊 Multiple Outputs**: Rich console display or JSON for automation

---

## 🚀 Quick Start

### Basic Usage

```bash
# Extract all metadata
filo meta photo.jpg

# Show only suspicious fields (CTF mode)
filo meta image.png -s

# JSON output for scripting
filo meta file.jpg --json
```

### CTF Workflow Examples

#### Example 1: Steghide Password in JPEG Comment

**Challenge**: Find hidden steghide password in image metadata

```bash
# Step 1: Quick suspicious scan
$ filo meta challenge.jpg -s

🚨 Suspicious Metadata Found:

JPEG:Comment:
  c3RlZ2hpZGU6Y0VGNmVuZHZjbVE=

⚠ 1 suspicious field(s) detected
```

```bash
# Step 2: Decode base64
$ echo "c3RlZ2hpZGU6Y0VGNmVuZHZjbVE=" | base64 -d
steghide:cEF6endvcmQ=

$ echo "cEF6endvcmQ=" | base64 -d
pAzzword
```

```bash
# Step 3: Extract with steghide
$ steghide extract -sf challenge.jpg -p pAzzword
wrote extracted data to "flag.txt"
```

#### Example 2: Flag in XMP License (picoCTF "information")

**Challenge**: Metadata contains the flag

```bash
# Step 1: Quick suspicious scan
$ filo meta cat.jpg -s

🚨 Suspicious Metadata Found:

XMP:License:
  cGljb0NURnt0aGVfbTN0YWRhdGFfMXNfbW9kaWZpZWR9
```

```bash
# Step 2: Decode base64
$ echo "cGljb0NURnt0aGVfbTN0YWRhdGFfMXNfbW9kaWZpZWR9" | base64 -d
picoCTF{the_m3tadata_1s_modified}
```

**Why this works**: Filo parses XMP License field from XML and flags base64 content automatically.

---
$ steghide extract -sf challenge.jpg -p pAzzword
wrote extracted data to "flag.txt".
```

---

## 📖 Supported Formats

### JPEG Metadata

#### File Information
- **FileType**: Format identification
- **MIMEType**: `image/jpeg`
- **FileSize**: Size in bytes

#### JFIF Data
- **JFIFVersion**: JFIF format version (e.g., `1.01`)
- **ResolutionUnit**: `None`, `inches`, or `cm`
- **XResolution** / **YResolution**: DPI/DPCM values

#### Image Properties
- **ImageWidth** / **ImageHeight**: Dimensions in pixels
- **EncodingProcess**: Compression method (e.g., `Baseline DCT, Huffman coding`)
- **BitsPerSample**: Bit depth per color channel
- **ColorComponents**: Number of color channels (3 for RGB)
- **YCbCrSubSampling**: Chroma subsampling (e.g., `YCbCr4:2:0 (2 2)`)

#### EXIF Tags (when present)
- **Make** / **Model**: Camera manufacturer and model
- **Software**: Editing software used
- **DateTime** / **DateTimeOriginal**: Timestamps
- **Artist** / **Copyright**: Creator information
- **ExposureTime**, **FNumber**, **ISO**: Camera settings
- **UserComment**, **MakerNote**: Custom fields

#### ICC Color Profiles
- **ProfileCMMType**: Color Management Module (e.g., `Linotronic`)
- **ProfileVersion**: ICC profile version
- **ProfileClass**: Device profile type
- **ColorSpaceData**: Color space (e.g., `RGB`)
- **ProfileDescription**: Profile name (e.g., `sRGB IEC61966-2.1`)

#### Computed Fields
- **ImageSize**: Width×Height (e.g., `2999x2249`)
- **Megapixels**: Computed from dimensions (e.g., `6.7`)

#### IPTC Metadata
- **CopyrightNotice**: Copyright information (⚠ **auto-flagged if suspicious**)
- **Keywords**: Image keywords/tags
- **ByLine**: Author/photographer
- **Caption**: Image description
- **Headline**: Brief title
- **Credit**, **Source**: Attribution fields
- **Contact**, **City**, **CountryName**: Location/contact metadata

#### XMP Metadata (Parsed from XML)
- **License**: Creative Commons license (⚠ **auto-flagged if suspicious** - common CTF flag location)
- **Rights**: Copyright/rights statement
- **Creator**: Content creator
- **Title**: Document title
- **XMPToolkit**: Tool that created XMP
- **XMP_Raw**: Full XML metadata (truncated to 500 chars)

#### Comments
- **Comment**: JPEG comment marker (⚠ **auto-flagged if suspicious**)

---

### PNG Metadata

#### File Information
- **FileType**: `PNG`
- **MIMEType**: `image/png`

#### Image Header (IHDR)
- **ImageWidth** / **ImageHeight**: Dimensions
- **BitDepth**: Bits per channel (1, 2, 4, 8, 16)
- **ColorType**: Grayscale, RGB, Palette, RGBA, etc.

#### Text Chunks
- **tEXt**: Uncompressed text (keyword: value)
- **zTXt**: Compressed text (auto-decompressed)
- **iTXt**: International text (UTF-8, compressed/uncompressed)

#### Timestamps & Physical Dimensions
- **ModificationTime**: tIME chunk (e.g., `2024-01-15 14:30:45`)
- **PixelsPerUnit**: pHYs chunk resolution

---

## 🔍 Suspicious Content Detection

Filo automatically flags metadata fields containing:

### Base64-Encoded Data
- Strings with 20+ consecutive alphanumeric characters ending in `=` or `==`
- **Common CTF location**: XMP License field (e.g., `cGljb0NURnt0aGVfbTN0YWRhdGFfMXNfbW9kaWZpZWR9`)
- Also found in JPEG Comments, IPTC fields

### Steganography Hints
- Keywords: `steghide`, `stegseek`, `hidden`, `encrypted`
- Password hints in comments

### Encoding Prefixes
- `data:` (data URIs)
- `base64:`, `encrypted:`, `hidden:`
- Long hex strings (`0x...`)

**Example Output**:
```
JPEG
  ⚠ Comment: c3RlZ2hpZGU6cEF6endvcmQ=
         ↑ Yellow highlight indicates suspicious content

⚠ 1 suspicious field(s) detected
These may contain encoded/hidden data (e.g., base64, steghide passwords)
Use -s or --sus to filter suspicious fields only
```

---

## 💻 Command Reference

### `filo meta`

Extract metadata from image files.

**Aliases**: `metadata`, `meta`

**Usage**:
```bash
filo meta FILE [OPTIONS]
```

**Options**:
- `--json` - Output as JSON (for scripting/automation)
- `-s`, `--sus` - Show only suspicious fields

**Examples**:
```bash
# Full metadata extraction
filo meta image.jpg

# Suspicious fields only (fast CTF triage)
filo meta stego.png -s

# JSON for pipeline processing
filo meta file.jpg --json | jq '.metadata[] | select(.group=="EXIF")'
```

---

## 📊 Output Formats

### Console Output (Default)

Grouped by metadata category:
```
File: photo.jpg
Format: JPEG

File
  FileType: JPEG
  MIMEType: image/jpeg
  FileSize: 2295191 bytes

JFIF
  JFIFVersion: 1.01
  ResolutionUnit: inches
  XResolution: 72
  YResolution: 72

ICC_Profile
  ProfileCMMType: Linotronic
  ProfileVersion: 2.1.0
  ProfileClass: Display Device Profile
  ColorSpaceData: RGB
  ProfileDescription: sRGB IEC61966-2.1

JPEG
  ImageWidth: 2999
  ImageHeight: 2249
  EncodingProcess: Baseline DCT, Huffman coding
  BitsPerSample: 8
  ColorComponents: 3
  YCbCrSubSampling: YCbCr4:2:0 (2 2)

Computed
  ImageSize: 2999x2249
  Megapixels: 6.7
```

### JSON Output

```json
{
  "file": "photo.jpg",
  "format": "JPEG",
  "metadata": [
    {
      "group": "File",
      "key": "FileType",
      "value": "JPEG",
      "tag_id": null,
      "description": "JPEG image"
    },
    {
      "group": "JPEG",
      "key": "Comment",
      "value": "c3RlZ2hpZGU6cGFzcw==",
      "tag_id": null,
      "description": "JPEG comment marker"
    }
  ],
  "warnings": [],
  "has_suspicious": true,
  "suspicious_fields": ["Comment"]
}
```

---

## 🎓 Use Cases

### 1. CTF Steganography Challenges

**Problem**: Hidden data in image metadata

```bash
# Quick scan for suspicious fields
filo meta challenge.jpg -s

# Found base64 in Comment field → decode → steghide password
```

### 2. Forensic Image Analysis

**Problem**: Verify image authenticity, detect manipulation

```bash
# Extract camera EXIF data
filo meta evidence.jpg | grep -A20 "EXIF"

# Check for editing software traces
filo meta photo.jpg | grep Software

# Verify timestamps
filo meta image.png | grep -i time
```

### 3. Malware Triage

**Problem**: Images used as malware droppers

```bash
# Look for suspicious embedded data
filo meta suspicious.jpg -s

# Check for unusual ICC profiles or XMP data
filo meta payload.png --json | jq '.metadata[] | select(.group=="ICC_Profile")'
```

### 4. Batch Processing

**Problem**: Analyze metadata across multiple files

```bash
# Extract all comments from directory
for f in *.jpg; do
  echo "$f:"
  filo meta "$f" --json | jq -r '.metadata[] | select(.key=="Comment") | .value'
done

# Find all images with suspicious metadata
for f in *.{jpg,png}; do
  filo meta "$f" --json | jq -r 'select(.has_suspicious) | .file'
done
```

---

## 🔬 Technical Details

### JPEG Parsing

Filo parses JPEG markers sequentially:

1. **SOI (0xFFD8)**: Start of Image
2. **APP0 (0xFFE0)**: JFIF metadata
3. **APP1 (0xFFE1)**: EXIF, XMP
4. **APP2 (0xFFE2)**: ICC Profile
5. **APP13 (0xFFED)**: IPTC/Photoshop metadata (8BIM resources)
6. **COM (0xFFFE)**: Comment marker
7. **SOF0-SOF15 (0xFFC0-0xFFCF)**: Image dimensions, encoding
8. **EOI (0xFFD9)**: End of Image

### IPTC Record Parsing

IPTC metadata uses 8BIM resource blocks (APP13 segment):

- **Resource 0x0404**: IPTC-NAA records
- Record format: `0x1C` (tag marker) + record number + dataset number + length + value
- Application Record 2 (most common):
  - Dataset 116: CopyrightNotice
  - Dataset 80: ByLine (author)
  - Dataset 25: Keywords
  - Dataset 120: Caption
  - Dataset 110: Credit
  - Dataset 90-101: Location metadata (City, Country)

### XMP Metadata Parsing

XMP uses RDF/XML structure embedded in APP1 segments:

- Namespace: `http://ns.adobe.com/xap/1.0/`
- Common fields extracted via regex:
  - `cc:license` (Creative Commons license - **common CTF flag location**)
  - `dc:rights` (Copyright statement)
  - `dc:creator` (Content creator)
  - `dc:title` (Document title)
- Full XML preserved in `XMP_Raw` field (truncated to 500 chars)

### PNG Chunk Parsing

PNG files consist of chunks with 4-byte type codes:

- **IHDR**: Image header (dimensions, bit depth, color type)
- **tEXt**: Latin-1 text (keyword + value)
- **zTXt**: Compressed text (zlib-compressed)
- **iTXt**: International text (UTF-8, optionally compressed)
- **tIME**: Last modification timestamp
- **pHYs**: Physical pixel dimensions
- **IEND**: End of PNG

### EXIF Tag Extraction

EXIF uses TIFF-based Image File Directory (IFD) structure:

- Supports both little-endian (Intel) and big-endian (Motorola) byte order
- Extracts 90+ common EXIF tags
- Handles multiple data types: BYTE, ASCII, SHORT, LONG, RATIONAL
- Tag ID displayed for forensic verification

### ICC Profile Parsing

ICC profiles embedded in APP2 segments:

- Extracts header fields (CMM type, version, class)
- Identifies color space (RGB, CMYK, LAB, etc.)
- Reads profile description from tag table
- Supports fragmented profiles (sequential APP2 markers)

---

## 🆚 Comparison: Filo vs. exiftool

| Feature | exiftool | filo meta |
|---------|----------|-----------|
| **JPEG EXIF** | ✅ Comprehensive | ✅ Common tags |
| **PNG tEXt/zTXt** | ✅ Full support | ✅ Full support |
| **ICC Profiles** | ✅ Detailed | ✅ Essential fields |
| **Suspicious Detection** | ❌ Manual | ✅ **Automatic** |
| **CTF-Optimized** | ❌ Verbose | ✅ `-s` flag |
| **JSON Output** | ✅ Yes | ✅ Yes |
| **Speed** | Slower | **Faster** |
| **File System Metadata** | ✅ Yes | ❌ No (by design) |

**Filo's Advantage**: Built-in steganography detection, CTF workflows, suspicious content auto-flagging.

---

## 🐛 Known Limitations

### Not Extracted (By Design)
- **File system metadata** (modification times, permissions) - use `exiftool` or `stat`
- **Maker-specific EXIF tags** (e.g., Canon/Nikon proprietary data)
- **Advanced ICC profile tags** (tone curves, rendering intents)
- **IPTC application records** (beyond presence detection)

### Partial Support
- **XMP**: Extracted as raw XML (not parsed into structured data)
- **Multi-segment ICC profiles**: Combines segments but may not parse complex profiles
- **Unusual EXIF data types**: UNDEFINED, SLONG, SRATIONAL (basic extraction only)

### Future Enhancements
- WebP metadata extraction
- HEIC/HEIF support
- GIF comment blocks
- TIFF metadata
- Video file metadata (MP4, MOV)

---

## 📚 Related Features

- **[Steganography Detection](STEGANOGRAPHY_DETECTION.md)**: LSB analysis, trailing data, zsteg-compatible extraction
- **[Embedded Detection](EMBEDDED_DETECTION.md)**: Find files hidden within other files
- **[Polyglot Detection](POLYGLOT_DETECTION.md)**: Detect files valid as multiple formats

---

## 🔗 References

- [JPEG File Interchange Format (JFIF)](https://www.w3.org/Graphics/JPEG/jfif3.pdf)
- [EXIF 2.3 Specification](https://www.cipa.jp/std/documents/e/DC-008-2012_E.pdf)
- [PNG Specification](http://www.libpng.org/pub/png/spec/1.2/PNG-Contents.html)
- [ICC Profile Format](https://www.color.org/specification/ICC1v43_2010-12.pdf)
- [XMP Specification](https://www.adobe.com/devnet/xmp.html)

---

**When you need to know what's really in those pixels - and what's hiding there.** 🔍

> *"Metadata tells the story the image doesn't show."*
