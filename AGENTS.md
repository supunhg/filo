# AGENTS.md - Filo Repository Guide

> **⚠️ ARCHIVED** — This Python version is no longer actively developed.
> Development has moved to **[filo-go](https://github.com/supunhg/filo-go)**.

## Project Overview
Filo is a Python CLI tool for file forensics. It analyzes unknown binaries, detects formats (87 YAML definitions), repairs corrupted files, and tracks hash lineage.

## Quick Setup
```bash
pip install -e ".[dev]"        # Install with dev dependencies
pip install -e ".[dev,yara]"   # Include YARA support
```

## Verification Order
Run in this sequence (mirrors CI):
```bash
ruff check .                   # Lint
black --check .                # Format check
mypy filo/                     # Type check
pytest                         # Tests
```

## Single Test / Single File
```bash
pytest tests/test_analyzer.py                          # Single file
pytest tests/test_analyzer.py::test_analyze_png        # Single test
pytest -k "crypto"                                     # Pattern match
```

## Code Style
- **Formatter**: black (line-length=100, target py310)
- **Linter**: ruff
- **Type checker**: mypy strict mode
- Pre-commit hooks enforce all three

## Project Structure
```
filo/           # Main package (26 modules)
  cli.py        # Click CLI entrypoint (filo command)
  analyzer.py   # Core Analyzer class
  formats/      # 87 YAML format definitions (add new formats here)
  ml.py         # ML learning (offline, no external calls)
tests/          # 24 test files
tests/fixtures/ # Shared test data
```

## Key Architecture Notes
- **Entrypoint**: `filo.cli:main` (Click-based CLI)
- **Format database**: `filo/formats/*.yaml` - each file defines signatures for one format
- **ML model**: Stored at `~/.filo/learned_patterns.pkl` (offline only)
- **Lineage DB**: Stored at `~/.filo/lineage.db`
- **Optional deps**: YARA support requires `yara-python` (gracefully degrades if missing)
- **Public API**: See `filo/__init__.py` for exported classes

## CI Details
- Tests run on Python 3.10, 3.11, 3.12
- Uses `uv pip install` in CI (not pip directly)
- Release workflow: lint → test → build → publish to PyPI

## Gotchas
- `mypy filo/` (not `mypy .`) - mypy only checks the filo package
- `ruff check .` excludes `examples/` and `demo/` per pyproject.toml
- Adding a new format: create YAML in `filo/formats/`, it auto-discovers via FormatDatabase
- `.deb` build requires `dpkg-deb` and packaging files in `packaging/DEBIAN/`
