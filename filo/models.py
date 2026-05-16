from typing import Any, Optional, List, Dict
from datetime import datetime
from pydantic import BaseModel, Field


class YARAMatchInfo(BaseModel):
    """Result from YARA rule scanning"""

    rule: str = Field(description="YARA rule name")
    namespace: str = Field(default="default", description="Rule namespace")
    tags: list[str] = Field(default_factory=list, description="Rule tags")
    meta: dict[str, str] = Field(default_factory=dict, description="Rule metadata")
    matched_strings: list[dict[str, Any]] = Field(
        default_factory=list, description="Matched string offsets and data"
    )
    description: str = Field(default="", description="Description from meta if available")


class OfficeMacroInfo(BaseModel):
    """Information about detected Office macros"""

    has_macros: bool = Field(default=False, description="Whether VBA macros were detected")
    macro_count: int = Field(default=0, description="Number of VBA macro modules")
    auto_exec_macros: list[str] = Field(
        default_factory=list, description="Auto-executable macro names"
    )
    suspicious_keywords: list[str] = Field(
        default_factory=list, description="Suspicious VBA keywords detected"
    )
    keyword_count: int = Field(default=0, description="Count of suspicious keywords")
    app_name: Optional[str] = Field(default=None, description="Detected Office application")
    is_encrypted: bool = Field(default=False, description="Whether document is encrypted")
    is_protected: bool = Field(default=False, description="Whether document is write-protected")


class PolyglotMatch(BaseModel):
    """File valid as multiple formats simultaneously"""

    formats: List[str] = Field(description="List of valid formats")
    pattern: str = Field(description="Polyglot pattern name (e.g., 'gifar', 'png_zip')")
    confidence: float = Field(ge=0.0, le=1.0, description="Detection confidence")
    description: str = Field(description="Human-readable description")
    risk_level: str = Field(description="Security risk: 'low', 'medium', 'high'")
    evidence: str = Field(description="Evidence for polyglot detection")


class Fingerprint(BaseModel):
    """Tool/creator attribution fingerprint"""

    category: str = Field(description="Fingerprint category (e.g., 'zip_creator', 'pdf_producer')")
    tool: Optional[str] = Field(default=None, description="Tool/application name")
    version: Optional[str] = Field(default=None, description="Tool version")
    os_hint: Optional[str] = Field(default=None, description="Operating system hint")
    timestamp: Optional[datetime] = Field(
        default=None, description="Creation/modification timestamp"
    )
    confidence: float = Field(ge=0.0, le=1.0, description="Fingerprint confidence")
    evidence: str = Field(description="Technical evidence for this fingerprint")


class EmbeddedObject(BaseModel):
    """File embedded within another file"""

    offset: int = Field(description="Byte offset where embedded object starts")
    format: str = Field(description="Detected format of embedded object")
    confidence: float = Field(ge=0.0, le=1.0, description="Detection confidence")
    size: Optional[int] = Field(default=None, description="Estimated size in bytes")
    description: str = Field(default="", description="Human-readable description")
    data_snippet: bytes = Field(default=b"", description="First 16 bytes for verification")


class Signature(BaseModel):
    """File signature specification"""

    offset: int = Field(description="Byte offset from file start")
    hex: str = Field(description="Hex string signature (e.g., '89504E47')")
    description: str = Field(description="Human-readable description")
    weight: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence weight")
    offset_max: Optional[int] = Field(
        default=None, description="Maximum offset to scan (creates range from offset to offset_max)"
    )


class ChunkSpec(BaseModel):
    """Chunk/block specification for structured formats"""

    id: str = Field(description="Chunk identifier")
    required: bool = Field(default=False, description="Whether chunk is required")
    position: Optional[int] = Field(default=None, description="Expected position in file")
    min_count: int = Field(default=1, description="Minimum occurrences")
    validation: Optional[str] = Field(default=None, description="Validation function name")


class Structure(BaseModel):
    """File structure specification"""

    chunks: list[ChunkSpec] = Field(default_factory=list, description="Chunk specifications")
    endianness: Optional[str] = Field(default=None, description="big or little")
    header_size: Optional[int] = Field(default=None, description="Fixed header size in bytes")


class Footer(BaseModel):
    """File footer signature"""

    hex: str = Field(description="Hex string signature")
    description: str = Field(description="Human-readable description")


class Template(BaseModel):
    """Header generation template"""

    hex: str = Field(description="Template hex with {{variable}} placeholders")
    variables: dict[str, str] = Field(
        default_factory=dict, description="Variable types (e.g., uint32be)"
    )


class RepairStrategy(BaseModel):
    """Repair strategy specification"""

    name: str = Field(description="Strategy function name")
    priority: int = Field(description="Priority order (lower = higher priority)")
    description: Optional[str] = Field(default=None, description="Strategy description")


class ValidationCommand(BaseModel):
    """External validation command"""

    command: list[str] = Field(description="Command with {file} placeholder")
    success_codes: list[int] = Field(default_factory=lambda: [0], description="Success exit codes")
    description: str = Field(description="Validation description")


class FormatSpec(BaseModel):
    """Complete file format specification"""

    format: str = Field(description="Format identifier (e.g., 'png')")
    version: str = Field(description="Format version")
    mime: list[str] = Field(description="MIME types")
    category: str = Field(description="Format category (e.g., 'raster_image')")
    confidence_weight: float = Field(
        default=0.9, ge=0.0, le=1.0, description="Overall format confidence weight"
    )
    extensions: list[str] = Field(default_factory=list, description="Common file extensions")

    # Detection
    signatures: list[Signature] = Field(default_factory=list, description="File signatures")
    footers: list[Footer] = Field(default_factory=list, description="Footer signatures")

    # Structure
    structure: Optional[Structure] = Field(default=None, description="File structure")

    # Templates
    templates: dict[str, Template] = Field(
        default_factory=dict, description="Header generation templates"
    )

    # Repair
    repair_strategies: list[RepairStrategy] = Field(
        default_factory=list, description="Repair strategies"
    )

    # Validation
    validation: list[ValidationCommand] = Field(
        default_factory=list, description="External validation commands"
    )

    # Metadata
    description: Optional[str] = Field(default=None, description="Format description")
    references: list[str] = Field(default_factory=list, description="Specification URLs")
    extraction: Optional[str] = Field(default=None, description="Common extraction command(s)")


class ConfidenceContribution(BaseModel):
    """Individual contribution to confidence score"""

    source: str = Field(
        description="Source of contribution (e.g., 'signature', 'structure', 'container', 'ml')"
    )
    value: float = Field(description="Contribution value (can be positive or negative)")
    description: str = Field(description="Human-readable description of what contributed")
    is_penalty: bool = Field(
        default=False, description="Whether this is a penalty (negative contribution)"
    )


class ArchitectureInfo(BaseModel):
    """CPU architecture information from executable file"""

    architecture: str = Field(
        description="CPU architecture name (e.g., 'x86-64', 'ARM64', 'Xtensa')"
    )
    bits: str = Field(description="Address width: '32-bit', '64-bit', etc.")
    endian: str = Field(description="Byte order: 'Little-endian' or 'Big-endian'")
    machine_code: int = Field(description="Machine type code from executable header")
    format: str = Field(description="Executable format: 'ELF', 'PE', 'Mach-O'")


class Contradiction(BaseModel):
    """Detected format contradiction or structural anomaly"""

    severity: str = Field(description="Severity level: 'warning', 'error', 'critical'")
    claimed_format: str = Field(description="Format the file claims to be")
    issue: str = Field(description="What's wrong or contradictory")
    details: str = Field(description="Technical details about the contradiction")
    category: str = Field(description="Type: 'compression', 'structure', 'embedded', 'missing'")


class DetectionResult(BaseModel):
    """Result of format detection"""

    format: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list, description="Supporting evidence")
    contributions: list[ConfidenceContribution] = Field(
        default_factory=list, description="Detailed breakdown of confidence contributions"
    )
    weight: float = Field(default=1.0, description="Module weight")


class AnalysisResult(BaseModel):
    """Complete analysis result"""

    primary_format: str
    confidence: float = Field(ge=0.0, le=1.0)
    alternative_formats: list[tuple[str, float]] = Field(
        default_factory=list, description="Other possible formats with confidence"
    )
    evidence_chain: list[dict[str, Any]] = Field(
        default_factory=list, description="Decision tree evidence"
    )
    contradictions: list[Contradiction] = Field(
        default_factory=list, description="Detected format contradictions and anomalies"
    )
    embedded_objects: list[EmbeddedObject] = Field(
        default_factory=list, description="Files embedded within this file"
    )
    fingerprints: list[Fingerprint] = Field(
        default_factory=list, description="Tool/creator attribution fingerprints"
    )
    polyglots: list[PolyglotMatch] = Field(
        default_factory=list, description="Polyglot format detections (valid as multiple formats)"
    )
    architecture: Optional[ArchitectureInfo] = Field(
        default=None, description="CPU architecture info for executable files"
    )
    crypto_analysis: Optional[Dict[str, Any]] = Field(
        default=None, description="Cryptographic analysis results"
    )
    yara_matches: list[YARAMatchInfo] = Field(default_factory=list, description="YARA rule matches")
    office_macros: Optional[OfficeMacroInfo] = Field(
        default=None, description="Office VBA macro analysis"
    )
    file_size: int
    entropy: Optional[float] = None
    checksum_sha256: str
