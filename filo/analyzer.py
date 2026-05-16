import hashlib
import logging
from pathlib import Path
from typing import Optional, Union
import mmap

from filo.formats import FormatDatabase
from filo.models import (
    AnalysisResult,
    DetectionResult,
    ConfidenceContribution,
    ArchitectureInfo,
    YARAMatchInfo,
    OfficeMacroInfo,
)
from filo.contradictions import ContradictionDetector
from filo.embedded import EmbeddedDetector
from filo.fingerprint import ToolFingerprinter
from filo.polyglot import PolyglotDetector
from filo.architecture import ArchitectureDetector
from filo.crypto import CryptoDetector

try:
    from filo.yarascanner import YARAScanner

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    from filo.office import analyze_office_file

    OFFICE_AVAILABLE = True
except ImportError:
    OFFICE_AVAILABLE = False

logger = logging.getLogger(__name__)

try:
    from filo.ml import MLDetector, LearningExample, PatternMatch

    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


class SignatureAnalyzer:
    """Signature-based file format detection."""

    def __init__(self, database: FormatDatabase) -> None:
        self.database = database
        self._signature_cache = {}

    def analyze(self, data: bytes, max_bytes: int = 8192) -> list[DetectionResult]:
        """
        Analyze file signatures.

        Args:
            data: File data to analyze
            max_bytes: Maximum bytes to scan for signatures

        Returns:
            List of detection results with confidence scores
        """
        results: list[DetectionResult] = []
        scan_data = data[:max_bytes]

        for format_spec in self.database._formats.values():
            evidence = []
            contributions = []
            total_weight = 0.0
            matched_weight = 0.0

            # Check signatures
            for sig in format_spec.signatures:
                total_weight += sig.weight

                if sig.offset >= len(data):
                    continue

                # Convert hex string to bytes
                sig_bytes = bytes.fromhex(sig.hex)

                # If offset_max is set, scan within the range
                if sig.offset_max is not None:
                    search_end = min(sig.offset_max, len(scan_data) - len(sig_bytes) + 1)
                    for search_offset in range(sig.offset, search_end):
                        if scan_data[search_offset : search_offset + len(sig_bytes)] == sig_bytes:
                            match_contribution = sig.weight * format_spec.confidence_weight
                            matched_weight += sig.weight
                            evidence.append(
                                f"Signature match at offset {search_offset}: {sig.description}"
                            )
                            contributions.append(
                                ConfidenceContribution(
                                    source="signature",
                                    value=match_contribution,
                                    description=f"{sig.description} at offset {search_offset}",
                                )
                            )
                            break
                else:
                    # Exact offset match
                    end_offset = sig.offset + len(sig_bytes)

                    if end_offset <= len(scan_data):
                        if scan_data[sig.offset : end_offset] == sig_bytes:
                            match_contribution = sig.weight * format_spec.confidence_weight
                            matched_weight += sig.weight
                            evidence.append(
                                f"Signature match at offset {sig.offset}: {sig.description}"
                            )
                            contributions.append(
                                ConfidenceContribution(
                                    source="signature",
                                    value=match_contribution,
                                    description=f"{sig.description} at offset {sig.offset}",
                                )
                            )

            # Calculate confidence
            if total_weight > 0:
                confidence = (matched_weight / total_weight) * format_spec.confidence_weight

                if confidence > 0.25:  # Minimum threshold (lowered to detect corrupted files)
                    results.append(
                        DetectionResult(
                            format=format_spec.format,
                            confidence=confidence,
                            evidence=evidence,
                            weight=1.0,
                            contributions=contributions,
                        )
                    )

        return sorted(results, key=lambda r: r.confidence, reverse=True)

    def fuzzy_match(self, data: bytes, max_bytes: int = 8192) -> list[DetectionResult]:
        """
        Detect corrupted file signatures by fuzzy matching.
        Returns possible formats when signatures are partially corrupted.
        """
        results: list[DetectionResult] = []
        scan_data = data[:max_bytes]

        # Focus on formats commonly corrupted in CTF challenges
        priority_formats = ["png", "jpeg", "gif", "pdf", "bmp", "zip"]

        for format_name in priority_formats:
            if format_name not in self.database._formats:
                continue

            format_spec = self.database._formats[format_name]

            for sig in format_spec.signatures:
                if sig.offset >= len(data):
                    continue

                sig_bytes = bytes.fromhex(sig.hex)
                sig_len = len(sig_bytes)

                # Check if we have enough data
                if sig.offset + sig_len > len(scan_data):
                    continue

                actual_bytes = scan_data[sig.offset : sig.offset + sig_len]

                # Count matching bytes
                matches = sum(1 for a, b in zip(actual_bytes, sig_bytes) if a == b)
                match_ratio = matches / sig_len if sig_len > 0 else 0

                # If 40-90% of bytes match, it's likely corrupted
                if 0.4 <= match_ratio < 0.95:
                    # Build corruption details
                    corruptions = []
                    for i, (actual, expected) in enumerate(zip(actual_bytes, sig_bytes)):
                        if actual != expected:
                            corruptions.append(
                                f"byte {i}: 0x{actual:02X} (expected 0x{expected:02X})"
                            )

                    # Limit to first 5 corruptions
                    corruption_desc = "; ".join(corruptions[:5])
                    if len(corruptions) > 5:
                        corruption_desc += f" ... and {len(corruptions) - 5} more"

                    confidence = match_ratio * 0.6  # Lower confidence for fuzzy matches

                    results.append(
                        DetectionResult(
                            format=f"{format_spec.format} (corrupted)",
                            confidence=confidence,
                            evidence=[
                                f"Partially corrupted signature at offset {sig.offset}",
                                f"{matches}/{sig_len} bytes match ({match_ratio*100:.1f}%)",
                                f"Corruptions: {corruption_desc}",
                            ],
                            weight=0.7,
                            contributions=[
                                ConfidenceContribution(
                                    source="fuzzy_signature",
                                    value=confidence,
                                    description=f"Fuzzy match: {match_ratio*100:.1f}% similarity",
                                )
                            ],
                        )
                    )
                    break  # One fuzzy match per format is enough

        return sorted(results, key=lambda r: r.confidence, reverse=True)


class StructuralAnalyzer:
    def __init__(self, database: FormatDatabase) -> None:
        self.database = database

    def analyze(self, data: bytes, suspected_format: Optional[str] = None) -> list[DetectionResult]:
        results: list[DetectionResult] = []

        # If we have a suspected format, validate its structure
        if suspected_format and suspected_format in self.database:
            spec = self.database.get_format(suspected_format)
            if spec and spec.structure:
                evidence = []
                contributions = []
                confidence = 0.8  # Base confidence for structural match

                # Check header size
                if spec.structure.header_size:
                    if len(data) >= spec.structure.header_size:
                        evidence.append(f"Valid header size: {spec.structure.header_size} bytes")
                        contributions.append(
                            ConfidenceContribution(
                                source="structure",
                                value=0.3,
                                description=f"Valid header size ({spec.structure.header_size} bytes)",
                            )
                        )
                    else:
                        penalty = 0.4
                        confidence *= 0.5
                        evidence.append("File too small for expected header")
                        contributions.append(
                            ConfidenceContribution(
                                source="structure",
                                value=-penalty,
                                description="File too small for expected header",
                                is_penalty=True,
                            )
                        )

                # Check footer signatures
                for footer in spec.footers:
                    footer_bytes = bytes.fromhex(footer.hex)
                    if data.endswith(footer_bytes):
                        footer_contribution = 0.15
                        confidence = min(1.0, confidence + footer_contribution)
                        evidence.append(f"Footer match: {footer.description}")
                        contributions.append(
                            ConfidenceContribution(
                                source="structure",
                                value=footer_contribution,
                                description=f"Footer: {footer.description}",
                            )
                        )

                if evidence:
                    results.append(
                        DetectionResult(
                            format=suspected_format,
                            confidence=confidence,
                            evidence=evidence,
                            weight=0.8,
                            contributions=contributions,
                        )
                    )

        return results


class ZipBasedFormatAnalyzer:
    """Analyzer for ZIP-based formats like DOCX, XLSX, PPTX, ODT, ODP, ODS, etc."""

    def __init__(self, database: FormatDatabase) -> None:
        self.database = database

    def analyze(
        self, data: bytes, file_path: Optional[Union[str, Path]] = None
    ) -> list[DetectionResult]:
        """
        Analyze ZIP-based formats by inspecting container contents.

        Args:
            data: File data (may be partial for large files)
            file_path: Optional path to file (used for large ZIPs to read central directory)
        """
        results: list[DetectionResult] = []

        # Check if it's a ZIP file
        if not data.startswith(b"PK\x03\x04"):
            return results

        try:
            import zipfile
            import io

            # For large files, try to use file path directly
            if file_path and Path(file_path).stat().st_size > 10 * 1024 * 1024:
                try:
                    zf = zipfile.ZipFile(file_path, "r")
                    namelist = zf.namelist()
                except Exception:
                    # Fall back to data buffer if file access fails
                    zip_buffer = io.BytesIO(data)
                    zf = zipfile.ZipFile(zip_buffer, "r")
                    namelist = zf.namelist()
            else:
                zip_buffer = io.BytesIO(data)
                zf = zipfile.ZipFile(zip_buffer, "r")
                namelist = zf.namelist()
            # Check for Office Open XML formats (DOCX, PPTX, XLSX)
            # Support both standard and non-standard structures (with subdirectories)
            has_content_types = any("[content_types].xml" in name.lower() for name in namelist)

            if has_content_types:
                # DOCX: Contains word/document.xml (anywhere in structure)
                if any("word/document.xml" in name.lower() for name in namelist):
                    word_doc = next((n for n in namelist if "word/document.xml" in n.lower()), None)
                    contributions = [
                        ConfidenceContribution(
                            source="container", value=0.50, description=f"Contains {word_doc}"
                        ),
                        ConfidenceContribution(
                            source="container",
                            value=0.45,
                            description="Contains [Content_Types].xml",
                        ),
                    ]
                    results.append(
                        DetectionResult(
                            format="docx",
                            confidence=0.95,
                            evidence=[f"Contains {word_doc}", "Contains [Content_Types].xml"],
                            weight=2.0,
                            contributions=contributions,
                        )
                    )

                # PPTX: Contains ppt/presentation.xml
                elif any("ppt/presentation.xml" in name.lower() for name in namelist):
                    ppt_file = next(
                        (n for n in namelist if "ppt/presentation.xml" in n.lower()), None
                    )
                    contributions = [
                        ConfidenceContribution(
                            source="container", value=0.50, description=f"Contains {ppt_file}"
                        ),
                        ConfidenceContribution(
                            source="container",
                            value=0.45,
                            description="Contains [Content_Types].xml",
                        ),
                    ]
                    results.append(
                        DetectionResult(
                            format="pptx",
                            confidence=0.95,
                            evidence=[f"Contains {ppt_file}", "Contains [Content_Types].xml"],
                            weight=2.0,
                            contributions=contributions,
                        )
                    )

                # XLSX: Contains xl/workbook.xml
                elif any("xl/workbook.xml" in name.lower() for name in namelist):
                    xl_file = next((n for n in namelist if "xl/workbook.xml" in n.lower()), None)
                    contributions = [
                        ConfidenceContribution(
                            source="container", value=0.50, description=f"Contains {xl_file}"
                        ),
                        ConfidenceContribution(
                            source="container",
                            value=0.45,
                            description="Contains [Content_Types].xml",
                        ),
                    ]
                    results.append(
                        DetectionResult(
                            format="xlsx",
                            confidence=0.95,
                            evidence=[f"Contains {xl_file}", "Contains [Content_Types].xml"],
                            weight=2.0,
                            contributions=contributions,
                        )
                    )

            # Check for OpenDocument formats (ODT, ODP, ODS)
            if "mimetype" in namelist:
                try:
                    mimetype_content = zf.read("mimetype").decode("utf-8", errors="ignore").strip()

                    # ODT: OpenDocument Text
                    if "application/vnd.oasis.opendocument.text" in mimetype_content:
                        results.append(
                            DetectionResult(
                                format="odt",
                                confidence=0.98,
                                evidence=[f"Mimetype: {mimetype_content}"],
                                weight=2.0,
                                contributions=[
                                    ConfidenceContribution(
                                        source="container",
                                        value=0.98,
                                        description=f"Mimetype: {mimetype_content}",
                                    )
                                ],
                            )
                        )

                    # ODP: OpenDocument Presentation
                    elif "application/vnd.oasis.opendocument.presentation" in mimetype_content:
                        results.append(
                            DetectionResult(
                                format="odp",
                                confidence=0.98,
                                evidence=[f"Mimetype: {mimetype_content}"],
                                weight=2.0,
                                contributions=[
                                    ConfidenceContribution(
                                        source="container",
                                        value=0.98,
                                        description=f"Mimetype: {mimetype_content}",
                                    )
                                ],
                            )
                        )

                    # ODS: OpenDocument Spreadsheet
                    elif "application/vnd.oasis.opendocument.spreadsheet" in mimetype_content:
                        results.append(
                            DetectionResult(
                                format="ods",
                                confidence=0.98,
                                evidence=[f"Mimetype: {mimetype_content}"],
                                weight=2.0,
                                contributions=[
                                    ConfidenceContribution(
                                        source="container",
                                        value=0.98,
                                        description=f"Mimetype: {mimetype_content}",
                                    )
                                ],
                            )
                        )
                except Exception:
                    pass

            # Check for EPUB (electronic publication)
            if "META-INF/container.xml" in namelist and "mimetype" in namelist:
                try:
                    mimetype_content = zf.read("mimetype").decode("utf-8", errors="ignore").strip()
                    if "application/epub+zip" in mimetype_content:
                        results.append(
                            DetectionResult(
                                format="epub",
                                confidence=0.98,
                                evidence=[
                                    f"Mimetype: {mimetype_content}",
                                    "Contains META-INF/container.xml",
                                ],
                                weight=2.0,
                                contributions=[
                                    ConfidenceContribution(
                                        source="container",
                                        value=0.60,
                                        description=f"Mimetype: {mimetype_content}",
                                    ),
                                    ConfidenceContribution(
                                        source="container",
                                        value=0.38,
                                        description="Contains META-INF/container.xml",
                                    ),
                                ],
                            )
                        )
                except Exception:
                    pass

            # Check for JAR (Java Archive)
            if "META-INF/MANIFEST.MF" in namelist:
                results.append(
                    DetectionResult(
                        format="jar",
                        confidence=0.90,
                        evidence=["Contains META-INF/MANIFEST.MF"],
                        weight=2.0,
                        contributions=[
                            ConfidenceContribution(
                                source="container",
                                value=0.90,
                                description="Contains META-INF/MANIFEST.MF",
                            )
                        ],
                    )
                )

            # Check for APK (Android Package)
            if "AndroidManifest.xml" in namelist and "classes.dex" in namelist:
                results.append(
                    DetectionResult(
                        format="apk",
                        confidence=0.95,
                        evidence=["Contains AndroidManifest.xml", "Contains classes.dex"],
                        weight=2.0,
                        contributions=[
                            ConfidenceContribution(
                                source="container",
                                value=0.50,
                                description="Contains AndroidManifest.xml",
                            ),
                            ConfidenceContribution(
                                source="container", value=0.45, description="Contains classes.dex"
                            ),
                        ],
                    )
                )

            # Close ZIP file
            zf.close()

            # If no specific ZIP-based format was detected, it's a plain ZIP archive
            if not results:
                results.append(
                    DetectionResult(
                        format="zip",
                        confidence=0.95,
                        evidence=[f"Standard ZIP archive with {len(namelist)} files"],
                        weight=2.5,
                        contributions=[
                            ConfidenceContribution(
                                source="container",
                                value=0.95,
                                description=f"Standard ZIP archive with {len(namelist)} files",
                            )
                        ],
                    )
                )

        except Exception as e:
            import traceback

            logger.debug(f"ZIP analysis failed: {e}")
            logger.debug(traceback.format_exc())

        return results


class StatisticalAnalyzer:
    @staticmethod
    def calculate_entropy(data: bytes, sample_size: int = 2048) -> float:
        if not data:
            return 0.0

        sample = data[: min(sample_size, len(data))]

        frequencies = [0] * 256
        for byte in sample:
            frequencies[byte] += 1

        import math

        entropy = 0.0
        data_len = len(sample)

        for freq in frequencies:
            if freq > 0:
                probability = freq / data_len
                entropy -= probability * math.log2(probability)

        return entropy

    @staticmethod
    def chunk_entropy(data: bytes, chunk_size: int = 256) -> list[float]:
        if not data:
            return []
        entropies = []
        for i in range(0, len(data), chunk_size):
            chunk = data[i : i + chunk_size]
            entropies.append(StatisticalAnalyzer.calculate_entropy(chunk, sample_size=chunk_size))
        return entropies

    @staticmethod
    def format_entropy_bar(entropies: list[float], width: int = 60) -> str:
        if not entropies:
            return ""
        blocks = []
        max_entropy = 8.0
        for e in entropies:
            ratio = min(1.0, e / max_entropy)
            if ratio < 0.3:
                color = "green"
            elif ratio < 0.6:
                color = "yellow"
            elif ratio < 0.8:
                color = "orange3"
            else:
                color = "red"
            bar_len = max(1, int(ratio * 4))
            bar_char = "█" * bar_len
            blocks.append(f"[{color}]{bar_char}[/{color}]")
        if not blocks:
            return ""
        result = []
        per_segment = max(1, len(blocks) // width)
        for i in range(0, len(blocks), per_segment):
            segment = blocks[i : i + per_segment]
            result.append("".join(segment))
        return "".join(result[:width])


class Analyzer:
    def __init__(
        self,
        database: Optional[FormatDatabase] = None,
        use_ml: bool = True,
        detect_embedded: bool = True,
        fingerprint: bool = True,
        detect_polyglots: bool = True,
        yara_rules: Optional[Union[str, list[str]]] = None,
    ) -> None:
        self.database = database or FormatDatabase()
        self.signature_analyzer = SignatureAnalyzer(self.database)
        self.structural_analyzer = StructuralAnalyzer(self.database)
        self.zip_analyzer = ZipBasedFormatAnalyzer(self.database)
        self.statistical_analyzer = StatisticalAnalyzer()
        self.embedded_detector = EmbeddedDetector(self.database) if detect_embedded else None
        self.fingerprinter = ToolFingerprinter() if fingerprint else None
        self.polyglot_detector = PolyglotDetector() if detect_polyglots else None

        self.ml_detector: Optional["MLDetector"] = None
        if use_ml and ML_AVAILABLE:
            try:
                self.ml_detector = MLDetector()
                logger.info("ML detector enabled")
            except Exception as e:
                logger.warning(f"ML detector failed to initialize: {e}")

        # Initialize YARA scanner
        self.yara_scanner: Optional["YARAScanner"] = None
        if YARA_AVAILABLE:
            self.yara_scanner = YARAScanner()
            if yara_rules:
                if isinstance(yara_rules, str):
                    yara_rules = [yara_rules]
                rule_paths = [Path(r) for r in yara_rules]
                try:
                    self.yara_scanner.load_rule_files(rule_paths)
                    logger.info(f"YARA scanner loaded {len(rule_paths)} rule file(s)")
                except Exception as e:
                    logger.warning(f"YARA rule loading failed: {e}")

        logger.info(f"Analyzer initialized with {self.database.count()} formats")

    def analyze(self, data: bytes, file_path: Optional[Union[str, Path]] = None) -> AnalysisResult:
        checksum = hashlib.sha256(data).hexdigest()[:16]

        sig_results = self.signature_analyzer.analyze(data)

        # Early return for high-confidence matches, BUT NOT for ZIP-based formats
        # (they need container analysis to distinguish between DOCX/XLSX/ODP/etc)
        zip_based_formats = {
            "zip",
            "docx",
            "pptx",
            "xlsx",
            "odt",
            "odp",
            "ods",
            "epub",
            "jar",
            "apk",
        }

        if sig_results and sig_results[0].confidence > 0.95:
            # Skip early return if this is a ZIP-based format (needs container inspection)
            if sig_results[0].format not in zip_based_formats:
                entropy = self.statistical_analyzer.calculate_entropy(data[:2048])

                # Check for contradictions even in early return
                contradictions = []
                try:
                    contradictions = ContradictionDetector.detect_all(data, sig_results[0].format)
                except Exception as e:
                    logger.debug(f"Contradiction detection failed: {e}")

                # Run YARA scanning in early return too
                yara_matches_list = []
                if self.yara_scanner and self.yara_scanner.available:
                    try:
                        yara_result = self.yara_scanner.scan_data(data)
                        if yara_result.matches:
                            yara_matches_list = [
                                YARAMatchInfo(
                                    rule=m.rule,
                                    namespace=m.namespace,
                                    tags=m.tags,
                                    meta=m.meta,
                                    matched_strings=m.strings,
                                )
                                for m in yara_result.matches
                            ]
                    except Exception:
                        pass

                return AnalysisResult(
                    primary_format=sig_results[0].format,
                    confidence=sig_results[0].confidence,
                    alternative_formats=[(r.format, r.confidence) for r in sig_results[1:3]],
                    evidence_chain=[
                        {
                            "module": "signature_analysis",
                            "format": sig_results[0].format,
                            "confidence": sig_results[0].confidence,
                            "evidence": sig_results[0].evidence,
                            "weight": 1.0,
                        }
                    ],
                    contradictions=contradictions,
                    yara_matches=yara_matches_list,
                    file_size=len(data),
                    entropy=entropy,
                    checksum_sha256=checksum,
                )

        struct_results = []
        if sig_results:
            struct_results = self.structural_analyzer.analyze(
                data, suspected_format=sig_results[0].format
            )

        # Check for ZIP-based formats (DOCX, XLSX, PPTX, ODT, ODP, ODS, etc.)
        zip_results = self.zip_analyzer.analyze(data, file_path=file_path)

        entropy = self.statistical_analyzer.calculate_entropy(data[:2048])

        ml_results = []
        if self.ml_detector:
            ml_results = self.ml_detector.predict(data, entropy, len(data))

        format_scores: dict[str, float] = {}
        evidence_chain: list[dict] = []

        for result in sig_results:
            format_scores[result.format] = format_scores.get(result.format, 0.0) + (
                result.confidence * result.weight * 0.6
            )
            evidence_chain.append(
                {
                    "module": "signature_analysis",
                    "format": result.format,
                    "confidence": result.confidence,
                    "evidence": result.evidence,
                    "weight": result.weight,
                    "contributions": (
                        [c.model_dump() for c in result.contributions]
                        if result.contributions
                        else []
                    ),
                }
            )

        for result in struct_results:
            format_scores[result.format] = format_scores.get(result.format, 0.0) + (
                result.confidence * result.weight * 0.4
            )
            evidence_chain.append(
                {
                    "module": "structural_analysis",
                    "format": result.format,
                    "confidence": result.confidence,
                    "evidence": result.evidence,
                    "weight": result.weight,
                    "contributions": (
                        [c.model_dump() for c in result.contributions]
                        if result.contributions
                        else []
                    ),
                }
            )

        # ZIP-based format detection has highest weight for accurate container detection
        for result in zip_results:
            format_scores[result.format] = format_scores.get(result.format, 0.0) + (
                result.confidence * result.weight * 0.8
            )
            evidence_chain.append(
                {
                    "module": "zip_container_analysis",
                    "format": result.format,
                    "confidence": result.confidence,
                    "evidence": result.evidence,
                    "weight": result.weight,
                    "contributions": (
                        [c.model_dump() for c in result.contributions]
                        if result.contributions
                        else []
                    ),
                }
            )

        for fmt, ml_confidence in ml_results:
            format_scores[fmt] = format_scores.get(fmt, 0.0) + (ml_confidence * 0.2)
            evidence_chain.append(
                {
                    "module": "ml_prediction",
                    "format": fmt,
                    "confidence": ml_confidence,
                    "evidence": ["Learned pattern match"],
                    "weight": 0.2,
                }
            )

        # Determine primary format
        if format_scores:
            primary_format = max(format_scores, key=format_scores.get)  # type: ignore
            confidence = min(1.0, format_scores[primary_format])

            alternatives = [
                (fmt, score) for fmt, score in format_scores.items() if fmt != primary_format
            ]
            alternatives.sort(key=lambda x: x[1], reverse=True)
        else:
            # No format detected - try fuzzy matching for corrupted files
            fuzzy_results = self.signature_analyzer.fuzzy_match(data)

            if fuzzy_results:
                # Report the best fuzzy match
                best_match = fuzzy_results[0]
                primary_format = best_match.format
                confidence = best_match.confidence

                evidence_chain.append(
                    {
                        "module": "fuzzy_signature_analysis",
                        "format": best_match.format,
                        "confidence": best_match.confidence,
                        "evidence": best_match.evidence,
                        "weight": best_match.weight,
                        "contributions": (
                            [c.model_dump() for c in best_match.contributions]
                            if best_match.contributions
                            else []
                        ),
                    }
                )

                alternatives = [(r.format, r.confidence) for r in fuzzy_results[1:3]]
            else:
                primary_format = "unknown"
                confidence = 0.0
                alternatives = []

        # Detect contradictions
        contradictions = []
        try:
            # Strip " (corrupted)" suffix for format comparison (fuzzy matches append this)
            clean_format = primary_format.replace(" (corrupted)", "")

            # Gather context for contradiction checks
            context = {}
            if clean_format in ["docx", "xlsx", "pptx", "zip", "odt", "odp", "ods"]:
                # Get ZIP namelist if available
                for evidence in evidence_chain:
                    if evidence.get("module") == "zip_container_analysis":
                        try:
                            import zipfile
                            import io

                            with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                                context["namelist"] = zf.namelist()
                        except Exception:
                            pass
                        break

            # Run contradiction detection with clean format name
            contradictions = ContradictionDetector.detect_all(data, clean_format, **context)
        except Exception as e:
            logger.debug(f"Contradiction detection failed: {e}")

        # Detect embedded objects
        embedded_objects = []
        if self.embedded_detector:
            try:
                # Use higher confidence threshold and pass parent format for exclusion rules
                embedded_objects = self.embedded_detector.detect_embedded(
                    data,
                    min_confidence=0.80,  # Raised from 0.70 to reduce false positives
                    parent_format=primary_format,
                )

                if primary_format in ["pe", "elf", "zip"]:
                    overlay = self.embedded_detector.detect_overlay(data, primary_format)
                    if overlay:
                        embedded_objects.append(overlay)

                if embedded_objects:
                    logger.info(f"Detected {len(embedded_objects)} embedded object(s)")
            except Exception as e:
                logger.debug(f"Embedded detection failed: {e}")

        # Extract tool/creator fingerprints
        fingerprints = []
        if self.fingerprinter:
            try:
                fingerprints = self.fingerprinter.fingerprint_file(data, primary_format)
                if fingerprints:
                    logger.info(f"Extracted {len(fingerprints)} fingerprint(s)")
            except Exception as e:
                logger.debug(f"Fingerprinting failed: {e}")

        # Detect polyglot files
        polyglots = []
        if self.polyglot_detector:
            try:
                polyglots = self.polyglot_detector.detect_polyglots(data, primary_format)
                if polyglots:
                    logger.info(f"Detected {len(polyglots)} polyglot combination(s)")
            except Exception as e:
                logger.debug(f"Polyglot detection failed: {e}")

        # Detect CPU architecture for executable formats
        architecture = None
        if primary_format in ["elf", "exe", "dll", "macho"]:
            try:
                arch_detector = ArchitectureDetector()
                arch_info = arch_detector.detect(data)
                if arch_info:
                    architecture = ArchitectureInfo(**arch_info)
                    logger.info(
                        f"Detected architecture: {arch_info['architecture']} ({arch_info['bits']})"
                    )
            except Exception as e:
                logger.debug(f"Architecture detection failed: {e}")

        # Perform cryptographic analysis
        crypto_analysis = None
        try:
            crypto_result = CryptoDetector.analyze(data, entropy)
            if crypto_result.is_likely_encrypted or crypto_result.encryption_indicators:
                crypto_analysis = crypto_result.model_dump()
                logger.info(f"Crypto analysis: {crypto_result.entropy_interpretation}")
                if crypto_result.is_likely_encrypted:
                    logger.info(f"Likely encrypted (confidence: {crypto_result.confidence:.0%})")
        except Exception as e:
            logger.debug(f"Crypto analysis failed: {e}")

        # Run YARA scanning
        yara_matches_list: list[YARAMatchInfo] = []
        if self.yara_scanner and self.yara_scanner.available:
            try:
                yara_result = self.yara_scanner.scan_data(data)
                if yara_result.matches:
                    for m in yara_result.matches:
                        desc = m.meta.get("description", "") if m.meta else ""
                        yara_matches_list.append(
                            YARAMatchInfo(
                                rule=m.rule,
                                namespace=m.namespace,
                                tags=m.tags,
                                meta=m.meta,
                                matched_strings=m.strings,
                                description=desc,
                            )
                        )
                    logger.info(f"YARA: {len(yara_matches_list)} rule(s) matched")
            except Exception as e:
                logger.debug(f"YARA scanning failed: {e}")

        # Run Office macro analysis for OLE2-based files
        office_macros_info: Optional[OfficeMacroInfo] = None
        clean_fmt = primary_format.replace(" (corrupted)", "")
        if OFFICE_AVAILABLE and clean_fmt in ("ole2", "msi", "msg", "doc", "xls", "ppt"):
            try:
                office_result = analyze_office_file(data)
                if office_result and (
                    office_result.has_macros or office_result.suspicious_keywords
                ):
                    office_macros_info = OfficeMacroInfo(
                        has_macros=office_result.has_macros,
                        macro_count=office_result.macro_count,
                        auto_exec_macros=office_result.auto_exec_macros,
                        suspicious_keywords=office_result.suspicious_keywords,
                        keyword_count=office_result.keyword_count,
                        app_name=office_result.app_name,
                        is_encrypted=office_result.is_encrypted,
                        is_protected=office_result.is_protected,
                    )
                    if office_result.has_macros:
                        logger.info(
                            f"Office macros detected: {office_result.macro_count} module(s)"
                        )
            except Exception as e:
                logger.debug(f"Office analysis failed: {e}")

        return AnalysisResult(
            primary_format=primary_format,
            confidence=confidence,
            alternative_formats=alternatives,
            evidence_chain=evidence_chain,
            contradictions=contradictions,
            embedded_objects=embedded_objects,
            fingerprints=fingerprints,
            polyglots=polyglots,
            architecture=architecture,
            crypto_analysis=crypto_analysis,
            yara_matches=yara_matches_list,
            office_macros=office_macros_info,
            file_size=len(data),
            entropy=entropy,
            checksum_sha256=checksum,
        )

    def teach(
        self, data: bytes, correct_format: str, incorrect_guess: Optional[str] = None
    ) -> None:
        if not self.ml_detector:
            logger.warning("ML detector not available for teaching")
            return

        entropy = self.statistical_analyzer.calculate_entropy(data[:8192])
        file_hash = hashlib.sha256(data).hexdigest()

        patterns = []

        # First, try to extract known signatures for this format
        spec = self.database.get_format(correct_format)
        if spec:
            for sig in spec.signatures:
                sig_bytes = bytes.fromhex(sig.hex)
                if len(data) > sig.offset + len(sig_bytes):
                    if data[sig.offset : sig.offset + len(sig_bytes)] == sig_bytes:
                        patterns.append(
                            PatternMatch(
                                offset=sig.offset,
                                pattern=sig_bytes,
                                format=correct_format,
                                weight=sig.weight,
                            )
                        )

        # Also extract discriminative patterns automatically from the file
        auto_patterns = self.ml_detector.extract_discriminative_patterns(data, max_patterns=15)
        for pattern in auto_patterns:
            pattern.format = correct_format
            patterns.append(pattern)

        # Extract rich statistical features
        features = self.ml_detector.extract_features(data)

        # Build n-gram profile
        ngram_profile = self.ml_detector.build_ngram_profile(data, n=3)

        incorrect_formats = []
        if incorrect_guess:
            incorrect_formats.append(incorrect_guess)

        example = LearningExample(
            file_hash=file_hash,
            patterns=patterns,
            correct_format=correct_format,
            file_size=len(data),
            entropy=entropy,
            incorrect_formats=incorrect_formats,
            features=features,
            ngram_profile=ngram_profile,
        )

        self.ml_detector.learn(example)
        logger.info(
            f"Learned from example: {correct_format} ({len(patterns)} patterns, {len(features)} features, {len(ngram_profile)} n-grams)"
        )

    def analyze_file(self, file_path: Union[str, Path]) -> AnalysisResult:
        path = Path(file_path)
        file_size = path.stat().st_size

        # Read file data (limited for large files to save memory)
        if file_size > 10 * 1024 * 1024:
            with open(path, "rb") as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped:
                    data = bytes(mmapped[: min(1024 * 1024, file_size)])
        else:
            with open(path, "rb") as f:
                data = f.read()

        # Pass file path so ZIP analyzer can open the full file if needed
        return self.analyze(data, file_path=path)
