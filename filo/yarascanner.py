import logging
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class YARAError(Exception):
    pass


@dataclass
class YARAMatch:
    rule: str
    namespace: str
    tags: list[str]
    meta: dict
    strings: list[dict]
    data: bytes = b""


@dataclass
class YARAScanResult:
    matches: list[YARAMatch] = field(default_factory=list)
    rule_count: int = 0
    error: Optional[str] = None


class YARAScanner:
    def __init__(self):
        self._yara = None
        self._rules = None
        self._init_yara()

    def _init_yara(self):
        try:
            import yara

            self._yara = yara
        except ImportError:
            logger.debug("yara-python not available")

    @property
    def available(self) -> bool:
        return self._yara is not None

    def compile_rules(self, source: str) -> None:
        if not self.available:
            raise YARAError("yara-python not installed. Install with: pip install yara-python")
        self._rules = self._yara.compile(source=source)

    def load_rule_file(self, path: Path, namespace: Optional[str] = None) -> None:
        if not self.available:
            raise YARAError("yara-python not installed. Install with: pip install yara-python")
        if not path.exists():
            raise YARAError(f"Rule file not found: {path}")
        if namespace:
            sources = {namespace: str(path)}
            self._rules = self._yara.compile(filepaths=sources)
        else:
            self._rules = self._yara.compile(filepath=str(path))

    def load_rule_files(self, paths: list[Path]) -> None:
        if not self.available:
            raise YARAError("yara-python not installed. Install with: pip install yara-python")
        sources = {}
        for path in paths:
            ns = path.stem.lower().replace(" ", "_")
            if not path.exists():
                logger.warning("YARA rule file not found: %s", path)
                continue
            sources[ns] = str(path)
        if sources:
            self._rules = self._yara.compile(filepaths=sources)

    def scan_file(self, path: Path, timeout: int = 60) -> YARAScanResult:
        if not self.available:
            return YARAScanResult(error="yara-python not installed")
        if self._rules is None:
            return YARAScanResult(error="No rules loaded")
        try:
            raw = self._rules.match(str(path), timeout=timeout)
            return self._process_matches(raw)
        except Exception as e:
            return YARAScanResult(error=str(e))

    def scan_data(self, data: bytes, timeout: int = 60) -> YARAScanResult:
        if not self.available:
            return YARAScanResult(error="yara-python not installed")
        if self._rules is None:
            return YARAScanResult(error="No rules loaded")
        try:
            raw = self._rules.match(data=data, timeout=timeout)
            return self._process_matches(raw)
        except Exception as e:
            return YARAScanResult(error=str(e))

    def _process_matches(self, raw_matches) -> YARAScanResult:
        matches = []
        for m in raw_matches:
            string_matches = []
            for s in getattr(m, "strings", []):
                for inst in getattr(s, "instances", []):
                    string_matches.append(
                        {
                            "identifier": s.identifier,
                            "offset": inst.offset,
                            "data": inst.matched_data,
                            "length": inst.matched_length,
                        }
                    )
            matches.append(
                YARAMatch(
                    rule=m.rule,
                    namespace=getattr(m, "namespace", "default"),
                    tags=list(getattr(m, "tags", [])),
                    meta=dict(getattr(m, "meta", {})),
                    strings=string_matches,
                )
            )
        return YARAScanResult(
            matches=matches,
            rule_count=len(matches),
        )
