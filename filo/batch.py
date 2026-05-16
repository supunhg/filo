"""
Batch processing for analyzing entire directories efficiently.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Callable
import time

from filo.analyzer import Analyzer
from filo.models import AnalysisResult

logger = logging.getLogger(__name__)


@dataclass
class BatchResult:
    """Result from batch analysis."""

    total_files: int
    analyzed_files: int
    failed_files: int
    skipped_files: int
    results: List[tuple[Path, AnalysisResult]]
    errors: List[tuple[Path, Exception]]
    duration: float
    files_per_second: float


@dataclass
class BatchConfig:
    """Configuration for batch processing."""

    max_workers: int = 4
    max_file_size: int = 100 * 1024 * 1024  # 100MB default
    recursive: bool = True
    follow_symlinks: bool = False
    include_patterns: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=lambda: ["*.git*", "*.pyc", "__pycache__"])
    progress_callback: Optional[Callable[[int, int], None]] = None


class BatchProcessor:
    """
    Efficient batch processing for directory analysis.

    Features:
    - Parallel processing with thread pool
    - File size filtering
    - Pattern matching (include/exclude)
    - Progress tracking
    - Error handling and reporting
    """

    def __init__(self, config: Optional[BatchConfig] = None) -> None:
        """
        Initialize batch processor.

        Args:
            config: Batch processing configuration
        """
        self.config = config or BatchConfig()
        self.analyzer = Analyzer(use_ml=False)
        logger.info(f"BatchProcessor initialized with {self.config.max_workers} workers")

    def process_directory(self, directory: Path) -> BatchResult:
        """
        Process all files in a directory.

        Args:
            directory: Directory to analyze

        Returns:
            BatchResult with analysis results and statistics
        """
        directory = Path(directory)
        if not directory.is_dir():
            raise ValueError(f"Not a directory: {directory}")

        # Collect files
        files = self._collect_files(directory)

        logger.info(f"Processing {len(files)} files from {directory}")

        # Process files
        start_time = time.time()
        results, errors = self._process_files(files)
        duration = time.time() - start_time

        # Calculate statistics
        analyzed = len(results)
        failed = len(errors)
        skipped = len(files) - analyzed - failed
        fps = analyzed / duration if duration > 0 else 0

        return BatchResult(
            total_files=len(files),
            analyzed_files=analyzed,
            failed_files=failed,
            skipped_files=skipped,
            results=results,
            errors=errors,
            duration=duration,
            files_per_second=fps,
        )

    def _collect_files(self, directory: Path) -> List[Path]:
        """Collect files matching criteria."""
        files = []

        if self.config.recursive:
            pattern = "**/*"
        else:
            pattern = "*"

        for path in directory.glob(pattern):
            # Skip directories
            if path.is_dir():
                continue

            # Check symlinks
            if path.is_symlink() and not self.config.follow_symlinks:
                continue

            # Check size
            try:
                if path.stat().st_size > self.config.max_file_size:
                    logger.debug(f"Skipping {path}: too large")
                    continue
            except OSError:
                continue

            # Check exclude patterns
            if self._matches_patterns(path, self.config.exclude_patterns):
                logger.debug(f"Skipping {path}: matches exclude pattern")
                continue

            # Check include patterns (if specified)
            if self.config.include_patterns:
                if not self._matches_patterns(path, self.config.include_patterns):
                    continue

            files.append(path)

        return sorted(files)

    def _matches_patterns(self, path: Path, patterns: List[str]) -> bool:
        """Check if path matches any pattern."""
        from fnmatch import fnmatch

        path_str = str(path)
        for pattern in patterns:
            if fnmatch(path_str, pattern) or fnmatch(path.name, pattern):
                return True
        return False

    def _process_files(
        self, files: List[Path]
    ) -> tuple[List[tuple[Path, AnalysisResult]], List[tuple[Path, Exception]]]:
        """Process files in parallel."""
        results = []
        errors = []
        completed = 0

        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            # Submit all tasks
            future_to_path = {executor.submit(self._analyze_file, path): path for path in files}

            # Process completed tasks
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                completed += 1

                # Progress callback
                if self.config.progress_callback:
                    self.config.progress_callback(completed, len(files))

                try:
                    result = future.result()
                    if result:
                        results.append((path, result))
                except Exception as e:
                    logger.error(f"Error analyzing {path}: {e}")
                    errors.append((path, e))

        return results, errors

    def _analyze_file(self, path: Path) -> Optional[AnalysisResult]:
        """Analyze a single file."""
        try:
            with open(path, "rb") as f:
                data = f.read()

            result = self.analyzer.analyze(data)
            return result
        except Exception as e:
            logger.error(f"Failed to analyze {path}: {e}")
            raise


def analyze_directory(
    directory: Path,
    recursive: bool = True,
    max_workers: int = 4,
    max_file_size: int = 100 * 1024 * 1024,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> BatchResult:
    """
    Convenience function for batch directory analysis.

    Args:
        directory: Directory to analyze
        recursive: Recursively process subdirectories
        max_workers: Number of parallel workers
        max_file_size: Maximum file size to process
        progress_callback: Optional progress callback(completed, total)

    Returns:
        BatchResult with analysis results
    """
    config = BatchConfig(
        max_workers=max_workers,
        max_file_size=max_file_size,
        recursive=recursive,
        progress_callback=progress_callback,
    )

    processor = BatchProcessor(config)
    return processor.process_directory(directory)
