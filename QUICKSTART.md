# Filo Quick Start Guide (v0.3.0)

Welcome to Filo! This guide will get you up and running in 5 minutes.

> ✨ **New in v0.3.0**: YARA scanning, Office VBA macro analysis, entropy visualization, strings extraction, CI/CD, Docker, and 22 new format specs!

## Installation

Filo works on **Linux, macOS, and Windows** (Python 3.10+ required).

### Option 1: pip install (cross-platform) - Recommended

Works on all platforms:

```bash
pip install filo-forensics
```

**With optional features:**
```bash
pip install filo-forensics[yara]   # YARA scanning support
pip install filo-forensics[all]    # all optional features
```

**Benefits:**
- ✅ Works on Linux, macOS, and Windows
- ✅ No cloning or building required
- ✅ Automatic dependency resolution
- ✅ Works from anywhere (global `filo` command)

### Option 2: Docker (cross-platform)

Works anywhere Docker runs:

```bash
docker pull ghcr.io/supunhg/filo:latest
docker run --rm -v $(pwd):/data filo:latest analyze /data/target_file
```

**Benefits:**
- ✅ No Python installation needed
- ✅ Isolated environment
- ✅ Same experience on all OSes

### Option 3: From Source (development)

```bash
git clone https://github.com/supunhg/Filo
cd Filo
pip install -e .
```

> **Windows users**: Use `py -m pip install -e .` or `python -m pip install -e .`
> 
> **macOS/Linux users**: Use `python3 -m pip install -e .`

### Option 4: .deb package (Linux only)

**For Ubuntu/Debian users:**

```bash
git clone https://github.com/supunhg/Filo
cd Filo
./build-deb.sh
sudo dpkg -i filo-forensics_0.3.0_all.deb
```

## Basic Usage

### 1. Analyze a File

Identify what type of file you're dealing with:

```bash
filo analyze mysterious_file.bin
```

**Example Output:**
```
Detected Format: elf
Confidence: 63.6%

🖥️  CPU Architecture:
  • AMD x86-64 (64-bit, Little-endian)
    Format: ELF | Machine Code: 0x003E

File Size: 158,632 bytes
Entropy: 2.26 bits/byte
SHA256: 833d6f9c...
```

**For CTF Architecture Challenges:**
```bash
# Instantly identify obscure CPU architectures
filo analyze astronaut

🖥️  CPU Architecture:
  • Tensilica Xtensa Architecture (32-bit, Little-endian)
    Format: ELF | Machine Code: 0x005E
```

### 2. List Available Formats

See what formats Filo can detect:

```bash
filo formats list
```

**Example Output:**
```
┌────────┬──────────────┬────────────────┬────────────┐
│ Format │ Category     │ Extensions     │ Signatures │
├────────┼──────────────┼────────────────┼────────────┤
│ png    │ raster_image │ png            │          2 │
│ jpeg   │ raster_image │ jpg, jpeg, jpe │          3 │
│ pdf    │ document     │ pdf            │          2 │
│ zip    │ archive      │ zip            │          3 │
...
```

### 3. Get Format Details

Learn about a specific format:

```bash
filo formats show png
```

**Example Output:**
```
Format: png
Version: 1.2
Category: raster_image

Signatures (2):
  • Offset 0: 89504E470D0A1A0A - PNG signature
  • Offset 8: 0000000D49484452 - IHDR chunk start

Repair Strategies:
  1. reconstruct_from_chunks
  2. generate_minimal_header
```

### 4. Repair Corrupted Files

Fix files with missing or corrupted headers:

```bash
filo repair corrupted.pdf --format=pdf -o repaired.pdf
```

**Example Output:**
```
Status: SUCCESS
Strategy Used: add_pdf_header
Original Size: 34 bytes
Repaired Size: 44 bytes

Changes Made:
  • Added PDF-1.7 header
```

### 5. Batch Process Directories

Analyze entire directories efficiently:

```bash
# Process all files in directory
filo batch ./data

# With filters and parallel processing
filo batch ./data --max-workers=8 --max-size=10485760
```

**Example Output:**
```
     Batch Processing Results     
┏━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┓
┃ Metric      ┃            Value ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━┩
│ Total Files │               42 │
│ Analyzed    │               42 │
│ Failed      │                0 │
│ Duration    │            0.15s │
│ Speed       │   280.0 files/sec│
└─────────────┴──────────────────┘
```

### 6. Export Analysis Results

Export to JSON or SARIF for CI/CD integration:

```bash
# Export to JSON (using --json flag)
filo analyze --json file.bin > report.json

# Export to SARIF (for GitHub Security) via batch command
filo batch --export=sarif --output=scan.sarif ./directory

# Pipe to jq for processing
filo analyze --json file.bin | jq '.primary_format'
```

### 7. Performance Profiling

Identify bottlenecks in large file analysis:

```bash
# Profile file analysis
filo profile large_file.dat

# Show top operations
filo profile --top=20 dataset.bin
```

### 9. Enhanced CLI Output

Color-coded confidence and hex dumps:

```bash
# Show hex dump with analysis
filo analyze --hex-dump file.bin

# Custom hex size
filo analyze --hex-dump --hex-bytes=128 file.bin
```

### 10. Offline ML Learning

Teach Filo when it makes mistakes (fully offline, no cloud):

```bash
# Filo misidentified a file
filo analyze mystery.bin
# Output: png (40% confidence) - Wrong!

# Teach it the correct format
filo teach mystery.bin --format=jpeg

# Now it learns and improves
filo analyze mystery.bin
# Output: jpeg (95% confidence) - Correct!
```

The more you use it and correct it, the better it gets. All learning stays local in `models/learned_patterns.pkl`.

## Python API (v0.2.0)

Filo provides a comprehensive Python API:

```python
from filo import Analyzer, RepairEngine
from filo.batch import analyze_directory, BatchConfig
from filo.export import export_to_file
from filo.container import analyze_archive
from filo.profiler import profile_session

# Core Analysis
analyzer = Analyzer()
result = analyzer.analyze_file("mystery.bin")
print(f"Format: {result.primary_format} ({result.confidence:.0%})")

# Batch Processing
batch_result = analyze_directory("./data", recursive=True, max_workers=8)
print(f"Analyzed {batch_result.analyzed_count} files in {batch_result.duration:.2f}s")

# Export to JSON/SARIF
export_to_file(result, "report.json", format="json")
export_to_file(batch_result, "scan.sarif", format="sarif")

# Container Analysis
container = analyze_archive("archive.zip")
for entry in container.entries:
    print(f"{entry.path}: {entry.format}")

# Performance Profiling
with profile_session() as profiler:
    with profiler.time_operation("batch_analysis"):
        analyze_directory("./data")
    print(profiler.get_report().format_report())

# File Repair
engine = RepairEngine()
repaired, report = engine.repair_file(
    "corrupted.png",
    format_name="png",
    output_path="fixed.png"
)

if report.success:
    print(f"Repaired successfully using {report.strategy_used}")
```

## CTF Challenge Example

Common CTF workflow:

```bash
# You receive a file called "challenge"
file challenge
# Output: challenge: data

# Use Filo to identify it
filo analyze challenge
# Output: Detected Format: png (Confidence: 45%)

# Repair it
filo repair challenge --format=png -o flag.png

# Open it (use your OS image viewer)
open flag.png      # macOS
xdg-open flag.png  # Linux
start flag.png     # Windows
```

## Advanced Features

### Enhanced Analysis Output

```bash
# Analyze with JSON output for scripting
filo analyze --json suspicious.bin
```

### Batch Processing with Filters

```bash
# Process directory with size limit
filo batch ./data --max-size=10485760 --max-workers=8

# Exclude patterns
filo batch ./data --exclude="*.log" --exclude="*.tmp"

# Export batch results
filo batch ./data --export=sarif --output=scan.sarif
```

### Performance Analysis

```bash
# Profile analysis performance
filo profile large_dataset.bin --show-stats

# Note: Batch processing uses parallel workers automatically
filo batch ./data --workers=8
```

### Format Database

```bash
# List all formats
filo formats list

# Filter by category
filo formats list --category=raster_image

# Show format details
filo formats show png
```

## 9. Steganography Detection (NEW v0.2.6)

Detect hidden data in image files and documents:

```bash
# Analyze image for hidden data (LSB/MSB)
filo stego image.png

# Analyze PDF metadata
filo stego document.pdf

# Check JPEG for trailing data
filo stego photo.jpg

# Extract specific channel/method
filo stego image.png --extract="b1,rgb,lsb,xy" -o hidden.txt
```

**Example Output:**
```
🔍 Steganography Analysis: flag.png

✓ Potential Hidden Data Found (3 methods)

Method: b1,rgb,lsb,xy
  Confidence: 95% (FLAG PATTERN DETECTED)
  Data: picoCTF{h1dd3n_1n_LSB_d4t4}
  
Method: b1,r,msb,xy
  Confidence: 65%
  Data: SGVsbG8gV29ybGQh (base64)
  Decoded: Hello World!
```

**Supports:**
- PNG/BMP LSB and MSB extraction
- PDF metadata (Author, Title, Subject, Keywords)
- Trailing data after JPEG EOI, PNG IEND, PDF EOF
- Automatic CTF flag pattern detection
- Base64 and zlib decompression

## 10. PCAP Network Analysis (v0.2.6)

Quick triage for network capture files:

```bash
# Analyze PCAP file
filo pcap capture.pcap
filo pcap dump.pcapng
```

**Example Output:**
```
📊 Statistics
  Packets: 1,234
  Protocols: TCP (800), UDP (400), ICMP (34)

🚩 FLAGS FOUND (2)
  picoCTF{n3tw0rk_f0r3n51c5}
  flag{hidden_in_packets}

📝 Base64 Data (3 found)
  cGljb0NURnsuLi59...
  → picoCTF{b4s364_1n_p4ck3ts}

🌐 HTTP Requests (5 found)
  GET /flag.txt
  POST /submit
```

**Features:**
- Protocol detection (IPv4, IPv6, TCP, UDP, ICMP, ARP)
- String extraction from packet payloads
- Automatic base64 detection and decoding
- CTF flag pattern search
- HTTP request/response extraction
- No Wireshark dependency for quick triage

## Current Capabilities

✅ **Detection**
- 60+ file formats (images, documents, archives, executables, network captures)
- Signature-based analysis
- Structural validation
- Entropy calculation
- Offline ML learning (improves with use)
- Steganography detection (LSB/MSB, metadata, trailing data)
- PCAP network analysis

✅ **Repair**
- Header reconstruction
- Multiple repair strategies per format
- Automatic strategy selection
- Safe backup creation

✅ **Steganography (v0.2.7)**
- zsteg-compatible LSB/MSB extraction (PNG, BMP)
- 60+ bit plane configurations
- Automatic base64 decoding
- File type detection (OpenPGP, Targa, Applesoft BASIC)
- PDF metadata extraction
- Trailing data detection (JPEG, PNG, PDF, GIF)
- Flag pattern recognition (picoCTF{}, flag{}, HTB{})
- Smart result filtering

✅ **Network Forensics**
- PCAP/PCAPNG parsing
- Protocol detection
- String/base64 extraction
- Flag hunting in packets
- HTTP request extraction

✅ **ML Learning**
- Learns from your corrections
- Fully offline (no telemetry, no cloud)
- Incremental pattern learning
- Local model storage

✅ **Intelligence**
- Format specification database
- MIME type mapping
- Extension mapping
- Evidence chain tracking

## What's Next?

Filo is in active development. See [ARCHITECTURE.md](../ARCHITECTURE.md) for the full vision.

**Coming Soon:**
- File carving from disk images
- More format specifications (targeting 500+)
- Advanced container format support
- Machine learning-based classification
- REST API
- Plugin system

## Getting Help

```bash
# General help
filo --help

# Command-specific help
filo analyze --help
filo repair --help
filo formats --help
```

## Contributing

Found a corrupted file that Filo can't handle? Want to add a new format?

1. Add a format specification in `filo/formats/yourformat.yaml`
2. Add tests in `tests/`
3. Submit a PR!

See format specifications in [filo/formats/](../filo/formats/) for examples.

---

**Happy Hunting! 🔍**
