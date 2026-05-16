# Filo Roadmap

> **Status:** v0.3.0 pre-release — core file identification + basic scanning working.
> **Mission:** Become the definitive open-source CLI file analysis toolkit — bridging the gap between simple `file` commands and heavy GUI tools.

---

## v0.3.0 — Polish & CI Health (Current)

- [x] All mypy type errors fixed (138 errors across 19 modules)
- [x] All 15 embedded detector tests passing
- [x] Black formatting applied across codebase
- [x] Badge SVGs removed from README
- [x] CI pipeline functional (ruff, black --check, mypy)

---

## v0.4.0 — Quick Wins (Next)

**Theme:** Fill common analysis gaps with minimal effort.

| Feature | Description |
|---------|-------------|
| **Archive scanning** | Recursive scan inside zip, tar, gz, bz2, 7z, rar |
| **Entropy analysis** | Per-section entropy + whole-file entropy (detect encrypted/packed) |
| **String extraction** | Extract ASCII/Unicode strings with length filters |
| **Hash summary** | MD5, SHA1, SHA256, SHA512, ssdeep, imphash |
| **Magic bytes JSON export** | Export `--json` output of identified file types |
| **Simple polyglot detection** | Flag files with multiple valid magic signatures |
| **Exit codes** | Return meaningful exit codes for scripting |

---

## v0.5.0 — CTF & Forensics Ready

**Theme:** Make Filo a go-to tool for CTF players and forensics analysts.

| Feature | Description |
|---------|-------------|
| **File carving** | Carve files by headers/footers from raw dumps or disk images |
| **Steganography hints** | Detect LSB, EOF trailing data, EXIF anomalies |
| **Metadata extraction** | EXIF, document metadata, PE version info |
| **Entropy heatmap** | Visual block-level entropy via terminal output |
| **Recursive directory scan** | Full tree walking with depth limits and exclusion patterns |
| **File categorization** | Group by type, size, entropy tier, risk level |
| **Diff mode** | Compare two file trees for added/moved/changed files |

---

## v0.6.0 — Malware Triage & Detection

**Theme:** Add lightweight malware analysis capabilities for quick triage.

| Feature | Description |
|---------|-------------|
| **PE analysis** | Imports, exports, sections, compile timestamps, anomalies |
| **ELF analysis** | Sections, symbols, dynamic linking, interpreter |
| **Mach-O analysis** | Fat binary handling, load commands, sections |
| **YARA integration** | Scan against YARA rules (CLI argument) |
| **Signature scanning** | Built-in rules for common packers and cryptors |
| **Packed/obfuscated detection** | Entropy + import + section heuristics |
| **Imphash matching** | Compare against known malware import hashes |

---

## v0.7.0+ — Professional Features

**Theme:** Production-grade analysis with reporting and integration.

| Feature | Description |
|---------|-------------|
| **HTML/PDF reports** | Rich output with charts, entropy graphs, risk scores |
| **Plugin system** | User-extensible scanners via Python plugins |
| **Machine learning hints** | Lightweight classifiers for file type / entropy patterns |
| **Correlation engine** | Cross-file IOC matching, shared strings, imports |
| **GUI frontend** | Optional TUI (Textual) or basic web UI |
| **CI/CD integration** | GitHub Action, pre-commit hook |
| **VS Code extension** | In-editor file analysis |

---

## Ecosystem Integration

| Integration | Phase |
|-------------|-------|
| `file` command replacement / supplement | v0.4.0 |
| `binwalk`-like signature scanning | v0.5.0 |
| `strings` / `trID` / `DIE` alternative | v0.4.0–v0.5.0 |
| `exiftool` metadata subset | v0.5.0 |
| `pefile` / `pyelftools` frontend | v0.6.0 |
| `yara` scanner frontend | v0.6.0 |
| `foremost` / `scalpel` carving alternative | v0.5.0 |

---

## Non-Goals (for now)

- Full-featured disassembly or debugging
- Network traffic / pcap analysis
- Disk image forensic mounting
- Competitive replacement for IDA Pro, Ghidra, or Hopper

---

*Last updated: 2026-05-16*
