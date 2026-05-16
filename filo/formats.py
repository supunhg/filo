import logging
from pathlib import Path
from typing import Optional

import yaml

from filo.models import FormatSpec

logger = logging.getLogger(__name__)


class FormatDatabase:
    """
    Machine-readable database of file format specifications.

    Loads and queries format specifications from YAML files.
    """

    def __init__(self, formats_dir: Optional[Path] = None) -> None:
        """
        Initialize format database.

        Args:
            formats_dir: Directory containing format YAML files.
                        Defaults to bundled formats.
        """
        if formats_dir is None:
            # Use bundled formats directory
            formats_dir = Path(__file__).parent / "formats"

        self.formats_dir = Path(formats_dir)
        self._formats: dict[str, FormatSpec] = {}
        self._load_formats()

    def _load_formats(self) -> None:
        """Load all format specifications from YAML files."""
        if not self.formats_dir.exists():
            logger.warning(f"Formats directory not found: {self.formats_dir}")
            return

        yaml_files = list(self.formats_dir.glob("*.yaml")) + list(self.formats_dir.glob("*.yml"))

        for yaml_file in yaml_files:
            try:
                with open(yaml_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    spec = FormatSpec(**data)
                    self._formats[spec.format] = spec
                    logger.debug(f"Loaded format: {spec.format}")
            except Exception as e:
                logger.error(f"Failed to load format from {yaml_file}: {e}")

    def get_format(self, format_name: str) -> Optional[FormatSpec]:
        """
        Get format specification by name.

        Args:
            format_name: Format identifier (e.g., 'png')

        Returns:
            FormatSpec if found, None otherwise
        """
        return self._formats.get(format_name)

    def list_formats(self) -> list[str]:
        """
        List all available format identifiers.

        Returns:
            Sorted list of format names
        """
        return sorted(self._formats.keys())

    def get_formats_by_category(self, category: str) -> list[FormatSpec]:
        """
        Get all formats in a category.

        Args:
            category: Category name (e.g., 'raster_image')

        Returns:
            List of matching format specifications
        """
        return [spec for spec in self._formats.values() if spec.category == category]

    def get_formats_by_extension(self, extension: str) -> list[FormatSpec]:
        """
        Get formats that use a file extension.

        Args:
            extension: File extension (with or without leading dot)

        Returns:
            List of matching format specifications
        """
        ext = extension.lstrip(".")
        return [spec for spec in self._formats.values() if ext in spec.extensions]

    def count(self) -> int:
        """Return number of loaded formats."""
        return len(self._formats)

    def __contains__(self, format_name: str) -> bool:
        """Check if format exists in database."""
        return format_name in self._formats

    def __len__(self) -> int:
        """Return number of loaded formats."""
        return len(self._formats)
