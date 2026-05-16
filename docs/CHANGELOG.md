# Changelog

All notable changes to Filo Forensics will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-05-16

### Added
- **YARA Scanning**: New `YARAScanner` module for rule compilation and file/data scanning
  - `--yara` flag on `filo analyze` to scan with custom rule files
  - Full match result parsing with tags, metadata, and string offsets
  - Optional `[yara]` extra dependency to keep core lightweight
- **Office VBA Macro Analysis**: Lightweight OLE2 compound document parser
  - VBA macro stream detection and extraction
  - Auto-exec macro identification (AutoOpen, Workbook_Open, etc.)
  - 50+ suspicious VBA keyword detection
  - Integrated into analysis pipeline for OLE2-based formats
- **Entropy Visualization**: `--entropy-viz` flag on `filo analyze`
  - `chunk_entropy()` and `format_entropy_bar()` methods in `StatisticalAnalyzer`
  - Color-coded entropy map of first 64KB in 256B chunks
- **Strings Extraction**: New `filo strings` command
  - ASCII and Unicode string extraction with configurable minimum length
  - Entropy filtering, regex search, encoding detection (base64, UTF-8, UTF-16LE)
  - JSON output, offset display, entropy-based coloring
- **Extended File Repair**: ELF header and OLE2 compound document header reconstruction
  - Auto-detection of 32/64-bit and endianness for ELF
- **CI/CD Pipeline**: GitHub Actions for quality checks, PyPI publishing, and release management
  - Ruff lint, Black format check, mypy type-checking, pytest with coverage
  - Tested on Python 3.10, 3.11, 3.12
  - Automated release on tag push: quality → build → PyPI → GitHub Release
- **Docker Support**: Multi-stage build with slim python:3.12-slim base, non-root user
- **Pre-commit Hooks**: ruff, black, mypy, trailing-whitespace, check-yaml, check-added-large-files
- **22 New Format Specs**: OLE2, MSI, MSG, LNK, EML, MFT, EVT, EVTX, PEM, DER, PKCS12, SQLite, JKS, BSON, MessagePack, PCAPNG, LUKS, MBR, GPT, minidump, VHD, VDI (87 total)
- **Cryptographic Analysis**: Entropy-based encryption detection, block cipher analysis, ECB mode identification

### Changed
- Analysis pipeline now integrates YARA, Office macro, and crypto analysis
- Updated `AnalysisResult` model with `yara_matches`, `office_macros`, `crypto_analysis` fields
- Bumped version to 0.3.0

### Fixed
- `UnboundLocalError` for `architecture` variable in analyzer
- `SyntaxWarning` for unescaped regex in strings command docstring
- Encoding detection false positives on binary data (added printable-ratio threshold)

### Added
- **CPU Architecture Detection**: Automatic detection of CPU architecture for executable files
  - ELF executables: 90+ architectures (x86, x86-64, ARM, ARM64, RISC-V, MIPS, PowerPC, Xtensa, SPARC, AVR, etc.)
  - PE/COFF executables: Windows executables (x86, x64, ARM, ARM64, IA-64, etc.)
  - Mach-O executables: macOS/iOS binaries (x86-64, ARM64, PowerPC, etc.)
  - Displays: Architecture name, address width (32/64-bit), endianness, machine code
  - Integrated into `filo analyze` command - shows automatically for executable formats
- Comprehensive test suite: 24 tests covering all major architectures and formats

### Changed
- Architecture information now displayed in analysis output for ELF, PE, and Mach-O files
- Updated models to include `ArchitectureInfo` in `AnalysisResult`

## [0.2.7] - 2026-01-17

### Added
- **Steganography**: Complete zsteg-compatible LSB/MSB extraction
  - 60+ bit plane configurations (b1/b2/b4 × rgb/rgba/bgr/abgr × lsb/msb × xy/yx/XY/YX)
  - Multi-bit extraction for 2-bit and 4-bit channels
  - File type detection (Targa, Alliant, Applesoft BASIC, OpenPGP)
  - Base64 auto-detection and decoding (improvement over zsteg)
  - CLI output formatting matching zsteg style

### Changed
- **Dependencies**: Added Pillow>=10.0.0 for image steganography analysis
- **Stego CLI**: Results filtered by default (use --all for metadata)
- Flag detection now highlights in bright green

### Fixed
- Multi-bit LSB/MSB extraction now correctly packs nibbles and bytes
- Bit extraction order matches zsteg algorithm exactly

## [0.2.6] - 2026-01-15

### Fixed
- **Critical**: Fixed contradiction detection not working for corrupted files
  - Contradiction detector now correctly strips "(corrupted)" suffix from format names
  - Corrupted PNGs, JPEGs, BMPs now properly show structural contradictions
- Fixed missing `_strategy_reconstruct_from_chunks` method in RepairEngine
  - Added implementation for PNG chunk-based reconstruction
  - Resolves "Unknown repair strategy" error when repairing PNG files
- Fixed duplicate "png" key in `advanced_strategies` dictionary
  - Merged PNG repair strategies into single consolidated list

### Changed
- Removed temporary and AI-like comments from codebase
- Improved code cleanliness and production readiness
- Consolidated PNG repair strategies for better organization

### Security
- Enhanced contradiction detection now properly identifies header corruption
- Better detection of embedded executables in image files

## [0.2.5] - 2025-XX-XX

### Added
- Hash-based lineage tracking
- Polyglot file detection
- Tool fingerprinting
- Advanced confidence breakdown system
- Embedded artifact detection

### Improved
- Fuzzy signature matching for corrupted files
- Multi-format container analysis
- ZIP-based format detection (DOCX, XLSX, PPTX, ODT, ODP, ODS)

## [0.2.3] - 2025-XX-XX

### Initial Release
- Core file format detection engine
- Signature-based analysis
- Structural validation
- Basic repair capabilities
- Carving engine
- Batch processing
- Export to JSON/SARIF

[0.2.6]: https://github.com/supunhg/Filo/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/supunhg/Filo/compare/v0.2.3...v0.2.5
[0.2.3]: https://github.com/supunhg/Filo/releases/tag/v0.2.3
