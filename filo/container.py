"""
Container detection and recursive analysis for ZIP, TAR, ISO, and other archives.
"""

import io
import logging
import tarfile
import zipfile
from dataclasses import dataclass
from typing import List, Optional

from filo.analyzer import Analyzer
from filo.models import AnalysisResult

logger = logging.getLogger(__name__)


@dataclass
class ContainerEntry:
    """Entry within a container."""
    path: str
    size: int
    is_dir: bool
    result: Optional[AnalysisResult] = None
    error: Optional[str] = None


@dataclass
class ContainerAnalysis:
    """Analysis result for a container file."""
    container_format: str
    total_entries: int
    analyzed_entries: int
    entries: List[ContainerEntry]
    warnings: List[str]


class ContainerDetector:
    """
    Detect and analyze container formats.
    
    Supported formats:
    - ZIP archives
    - TAR archives (tar, tar.gz, tar.bz2, tar.xz)
    - ISO 9660 images (basic support)
    """
    
    def __init__(self, max_depth: int = 3) -> None:
        """
        Initialize container detector.
        
        Args:
            max_depth: Maximum recursion depth for nested containers
        """
        self.max_depth = max_depth
        self.analyzer = Analyzer(use_ml=False)
        self._depth = 0
    
    def is_container(self, data: bytes) -> Optional[str]:
        """
        Check if data is a container format.
        
        Args:
            data: Binary data to check
            
        Returns:
            Container format name or None
        """
        # ZIP
        if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
            return "zip"
        
        # TAR (POSIX ustar)
        if len(data) >= 512:
            # Check for ustar magic at offset 257
            if data[257:262] == b"ustar":
                return "tar"
        
        # ISO 9660
        if len(data) >= 32768 + 6:
            # Check for CD001 signature at offset 32769
            if data[32769:32774] == b"CD001":
                return "iso"
        
        # GZIP (often used with tar)
        if data.startswith(b"\x1f\x8b"):
            return "gzip"
        
        # BZIP2
        if data.startswith(b"BZ"):
            return "bzip2"
        
        # XZ
        if data.startswith(b"\xfd7zXZ\x00"):
            return "xz"
        
        return None
    
    def analyze_container(self, data: bytes, recursive: bool = True) -> Optional[ContainerAnalysis]:
        """
        Analyze container contents.
        
        Args:
            data: Container file data
            recursive: Recursively analyze nested containers
            
        Returns:
            ContainerAnalysis or None if not a container
        """
        container_type = self.is_container(data)
        
        if not container_type:
            return None
        
        logger.info(f"Detected {container_type} container")
        
        if container_type == "zip":
            return self._analyze_zip(data, recursive)
        elif container_type == "tar":
            return self._analyze_tar(data, recursive)
        elif container_type in ("gzip", "bzip2", "xz"):
            logger.warning(f"{container_type} compression detected - may contain TAR archive")
            return None
        elif container_type == "iso":
            logger.warning("ISO 9660 support is basic - full analysis not implemented")
            return None
        
        return None
    
    def _analyze_zip(self, data: bytes, recursive: bool) -> ContainerAnalysis:
        """Analyze ZIP archive."""
        entries = []
        warnings = []
        analyzed = 0
        
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                len(zf.namelist())
                
                for name in zf.namelist():
                    info = zf.getinfo(name)
                    
                    entry = ContainerEntry(
                        path=name,
                        size=info.file_size,
                        is_dir=info.is_dir()
                    )
                    
                    # Analyze file contents
                    if not info.is_dir() and info.file_size > 0:
                        try:
                            member_data = zf.read(name)
                            
                            # Check if nested container
                            if recursive and self._depth < self.max_depth:
                                nested = self.is_container(member_data)
                                if nested:
                                    self._depth += 1
                                    nested_analysis = self.analyze_container(member_data, recursive)
                                    self._depth -= 1
                                    
                                    if nested_analysis:
                                        warnings.append(f"Nested {nested} container: {name}")
                            
                            # Analyze content
                            result = self.analyzer.analyze(member_data)
                            entry.result = result
                            analyzed += 1
                            
                        except Exception as e:
                            entry.error = str(e)
                            logger.error(f"Error analyzing {name}: {e}")
                    
                    entries.append(entry)
                
        except zipfile.BadZipFile as e:
            warnings.append(f"Corrupted ZIP: {e}")
        
        return ContainerAnalysis(
            container_format="zip",
            total_entries=len(entries),
            analyzed_entries=analyzed,
            entries=entries,
            warnings=warnings
        )
    
    def _analyze_tar(self, data: bytes, recursive: bool) -> ContainerAnalysis:
        """Analyze TAR archive."""
        entries = []
        warnings = []
        analyzed = 0
        
        try:
            with tarfile.open(fileobj=io.BytesIO(data)) as tf:
                members = tf.getmembers()
                
                for member in members:
                    entry = ContainerEntry(
                        path=member.name,
                        size=member.size,
                        is_dir=member.isdir()
                    )
                    
                    # Analyze file contents
                    if member.isfile() and member.size > 0:
                        try:
                            f = tf.extractfile(member)
                            if f:
                                member_data = f.read()
                                
                                # Check if nested container
                                if recursive and self._depth < self.max_depth:
                                    nested = self.is_container(member_data)
                                    if nested:
                                        self._depth += 1
                                        nested_analysis = self.analyze_container(member_data, recursive)
                                        self._depth -= 1
                                        
                                        if nested_analysis:
                                            warnings.append(f"Nested {nested} container: {member.name}")
                                
                                # Analyze content
                                result = self.analyzer.analyze(member_data)
                                entry.result = result
                                analyzed += 1
                                
                        except Exception as e:
                            entry.error = str(e)
                            logger.error(f"Error analyzing {member.name}: {e}")
                    
                    entries.append(entry)
                
        except tarfile.TarError as e:
            warnings.append(f"Corrupted TAR: {e}")
        
        return ContainerAnalysis(
            container_format="tar",
            total_entries=len(entries),
            analyzed_entries=analyzed,
            entries=entries,
            warnings=warnings
        )


def analyze_archive(data: bytes, recursive: bool = True, max_depth: int = 3) -> Optional[ContainerAnalysis]:
    """
    Convenience function to analyze container/archive files.
    
    Args:
        data: Archive file data
        recursive: Recursively analyze nested containers
        max_depth: Maximum recursion depth
        
    Returns:
        ContainerAnalysis or None
    """
    detector = ContainerDetector(max_depth=max_depth)
    return detector.analyze_container(data, recursive)
