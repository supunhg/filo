"""
Hash Lineage Tracking for Chain-of-Custody

Tracks cryptographic hashes across file transformations to maintain
forensic chain-of-custody. Critical for court evidence and investigations.
"""

import hashlib
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field, asdict
from enum import Enum


class OperationType(str, Enum):
    """Types of operations that create lineage records"""

    REPAIR = "repair"
    CARVE = "carve"
    EXTRACT = "extract"
    EXPORT = "export"
    TEACH = "teach"
    ANALYZE = "analyze"


@dataclass
class FileLineage:
    """
    Single lineage record tracking a file transformation.

    Attributes:
        original_hash: SHA-256 hash of source file
        result_hash: SHA-256 hash of resulting file
        operation: Type of transformation performed
        timestamp: ISO 8601 timestamp of operation
        original_path: Path to original file (optional)
        result_path: Path to result file (optional)
        metadata: Operation-specific details (repair strategy, offset, etc.)
    """

    original_hash: str
    result_hash: str
    operation: OperationType
    timestamp: str
    original_path: Optional[str] = None
    result_path: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON export"""
        data = asdict(self)
        data["operation"] = self.operation.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FileLineage":
        """Create from dictionary"""
        data["operation"] = OperationType(data["operation"])
        return cls(**data)


class LineageTracker:
    """
    Tracks and queries file transformation lineage using SQLite.

    Maintains chain-of-custody for forensic investigations by recording
    cryptographic hashes across all file transformations.
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        """
        Initialize lineage tracker.

        Args:
            db_path: Path to SQLite database (default: ~/.filo/lineage.db)
        """
        if db_path is None:
            db_path = Path.home() / ".filo" / "lineage.db"

        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._init_database()

    def _init_database(self) -> None:
        """Initialize SQLite database schema"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS lineage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    original_hash TEXT NOT NULL,
                    result_hash TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    original_path TEXT,
                    result_path TEXT,
                    metadata TEXT,
                    UNIQUE(original_hash, result_hash, operation, timestamp)
                )
            """)

            # Indexes for efficient queries
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_original_hash 
                ON lineage(original_hash)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_result_hash 
                ON lineage(result_hash)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_operation 
                ON lineage(operation)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp 
                ON lineage(timestamp)
            """)

    def record(
        self,
        original_data: bytes,
        result_data: bytes,
        operation: OperationType,
        original_path: Optional[str] = None,
        result_path: Optional[str] = None,
        **metadata: Any,
    ) -> FileLineage:
        """
        Record a file transformation.

        Args:
            original_data: Original file bytes
            result_data: Resulting file bytes
            operation: Type of operation performed
            original_path: Path to original file
            result_path: Path to result file
            **metadata: Additional operation details

        Returns:
            FileLineage record
        """
        original_hash = hashlib.sha256(original_data).hexdigest()
        result_hash = hashlib.sha256(result_data).hexdigest()
        timestamp = datetime.utcnow().isoformat() + "Z"

        lineage = FileLineage(
            original_hash=original_hash,
            result_hash=result_hash,
            operation=operation,
            timestamp=timestamp,
            original_path=original_path,
            result_path=result_path,
            metadata=metadata,
        )

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO lineage 
                (original_hash, result_hash, operation, timestamp, 
                 original_path, result_path, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    original_hash,
                    result_hash,
                    operation.value,
                    timestamp,
                    original_path,
                    result_path,
                    json.dumps(metadata),
                ),
            )

        return lineage

    def record_from_files(
        self, original_path: Path, result_path: Path, operation: OperationType, **metadata: Any
    ) -> FileLineage:
        """
        Record transformation using file paths.

        Args:
            original_path: Path to original file
            result_path: Path to result file
            operation: Type of operation
            **metadata: Additional details

        Returns:
            FileLineage record
        """
        original_data = original_path.read_bytes()
        result_data = result_path.read_bytes()

        return self.record(
            original_data=original_data,
            result_data=result_data,
            operation=operation,
            original_path=str(original_path),
            result_path=str(result_path),
            **metadata,
        )

    def get_descendants(self, file_hash: str) -> List[FileLineage]:
        """
        Get all files derived from this hash (forward lineage).

        Args:
            file_hash: SHA-256 hash to query

        Returns:
            List of lineage records where this is the original
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """
                SELECT * FROM lineage 
                WHERE original_hash = ? 
                ORDER BY timestamp ASC
                """,
                (file_hash,),
            )

            records = []
            for row in cursor:
                records.append(
                    FileLineage(
                        original_hash=row["original_hash"],
                        result_hash=row["result_hash"],
                        operation=OperationType(row["operation"]),
                        timestamp=row["timestamp"],
                        original_path=row["original_path"],
                        result_path=row["result_path"],
                        metadata=json.loads(row["metadata"]) if row["metadata"] else {},
                    )
                )

            return records

    def get_ancestors(self, file_hash: str) -> List[FileLineage]:
        """
        Get all files this was derived from (backward lineage).

        Args:
            file_hash: SHA-256 hash to query

        Returns:
            List of lineage records where this is the result
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """
                SELECT * FROM lineage 
                WHERE result_hash = ? 
                ORDER BY timestamp DESC
                """,
                (file_hash,),
            )

            records = []
            for row in cursor:
                records.append(
                    FileLineage(
                        original_hash=row["original_hash"],
                        result_hash=row["result_hash"],
                        operation=OperationType(row["operation"]),
                        timestamp=row["timestamp"],
                        original_path=row["original_path"],
                        result_path=row["result_path"],
                        metadata=json.loads(row["metadata"]) if row["metadata"] else {},
                    )
                )

            return records

    def get_full_chain(self, file_hash: str) -> Dict[str, Any]:
        """
        Get complete lineage chain (ancestors + descendants).

        Args:
            file_hash: SHA-256 hash to query

        Returns:
            Dictionary with ancestors, hash, and descendants
        """
        # Recursively walk backward to find root
        ancestors: list[FileLineage] = []
        current = file_hash
        visited = {current}

        while True:
            parents = self.get_ancestors(current)
            if not parents:
                break

            # Take most recent parent
            parent = parents[0]
            if parent.original_hash in visited:
                break  # Circular reference

            ancestors.insert(0, parent)
            visited.add(parent.original_hash)
            current = parent.original_hash

        # Recursively walk forward to find all descendants
        descendants = []
        to_visit = [file_hash]
        visited = {file_hash}

        while to_visit:
            current = to_visit.pop(0)
            children = self.get_descendants(current)

            for child in children:
                if child.result_hash not in visited:
                    descendants.append(child)
                    visited.add(child.result_hash)
                    to_visit.append(child.result_hash)

        return {
            "root_hash": ancestors[0].original_hash if ancestors else file_hash,
            "query_hash": file_hash,
            "ancestors": [a.to_dict() for a in ancestors],
            "descendants": [d.to_dict() for d in descendants],
            "chain_length": len(ancestors) + len(descendants) + 1,
        }

    def get_by_operation(self, operation: OperationType) -> List[FileLineage]:
        """
        Get all lineage records for a specific operation type.

        Args:
            operation: Operation type to filter by

        Returns:
            List of matching lineage records
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """
                SELECT * FROM lineage 
                WHERE operation = ? 
                ORDER BY timestamp DESC
                """,
                (operation.value,),
            )

            records = []
            for row in cursor:
                records.append(
                    FileLineage(
                        original_hash=row["original_hash"],
                        result_hash=row["result_hash"],
                        operation=OperationType(row["operation"]),
                        timestamp=row["timestamp"],
                        original_path=row["original_path"],
                        result_path=row["result_path"],
                        metadata=json.loads(row["metadata"]) if row["metadata"] else {},
                    )
                )

            return records

    def export_chain_json(self, file_hash: str) -> str:
        """
        Export lineage chain as JSON for court documentation.

        Args:
            file_hash: Hash to generate chain for

        Returns:
            JSON string with complete chain-of-custody
        """
        chain = self.get_full_chain(file_hash)

        # Add forensic metadata
        export = {
            "lineage_export": {
                "version": "1.0",
                "export_timestamp": datetime.utcnow().isoformat() + "Z",
                "query_hash": file_hash,
                "chain": chain,
            }
        }

        return json.dumps(export, indent=2)

    def export_chain_report(self, file_hash: str) -> str:
        """
        Export human-readable chain-of-custody report.

        Args:
            file_hash: Hash to generate report for

        Returns:
            Formatted report suitable for court documentation
        """
        chain = self.get_full_chain(file_hash)

        lines = [
            "=" * 70,
            "FORENSIC CHAIN-OF-CUSTODY REPORT",
            "=" * 70,
            "",
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Query Hash: {file_hash}",
            f"Root Hash:  {chain['root_hash']}",
            f"Chain Length: {chain['chain_length']} transformations",
            "",
            "=" * 70,
            "LINEAGE CHAIN",
            "=" * 70,
            "",
        ]

        # Show ancestors (backward chain)
        if chain["ancestors"]:
            lines.append("BACKWARD CHAIN (Origins):")
            lines.append("-" * 70)
            for i, record in enumerate(chain["ancestors"], 1):
                lines.append(f"\n{i}. {record['operation'].upper()}")
                lines.append(f"   Timestamp:     {record['timestamp']}")
                lines.append(f"   Original Hash: {record['original_hash']}")
                lines.append(f"   Result Hash:   {record['result_hash']}")
                if record["original_path"]:
                    lines.append(f"   Original Path: {record['original_path']}")
                if record["result_path"]:
                    lines.append(f"   Result Path:   {record['result_path']}")
                if record["metadata"]:
                    lines.append(f"   Metadata:      {json.dumps(record['metadata'])}")
            lines.append("")

        # Current file
        lines.append("=" * 70)
        lines.append(f"CURRENT FILE: {file_hash}")
        lines.append("=" * 70)
        lines.append("")

        # Show descendants (forward chain)
        if chain["descendants"]:
            lines.append("FORWARD CHAIN (Derived Files):")
            lines.append("-" * 70)
            for i, record in enumerate(chain["descendants"], 1):
                lines.append(f"\n{i}. {record['operation'].upper()}")
                lines.append(f"   Timestamp:     {record['timestamp']}")
                lines.append(f"   Original Hash: {record['original_hash']}")
                lines.append(f"   Result Hash:   {record['result_hash']}")
                if record["original_path"]:
                    lines.append(f"   Original Path: {record['original_path']}")
                if record["result_path"]:
                    lines.append(f"   Result Path:   {record['result_path']}")
                if record["metadata"]:
                    lines.append(f"   Metadata:      {json.dumps(record['metadata'])}")
            lines.append("")

        lines.extend(["=" * 70, "END OF CHAIN-OF-CUSTODY REPORT", "=" * 70])

        return "\n".join(lines)

    def clear_all(self) -> None:
        """Clear all lineage records (use with caution)"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM lineage")

    def get_stats(self) -> Dict[str, Any]:
        """Get lineage database statistics"""
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM lineage").fetchone()[0]

            by_operation = {}
            for op in OperationType:
                count = conn.execute(
                    "SELECT COUNT(*) FROM lineage WHERE operation = ?", (op.value,)
                ).fetchone()[0]
                by_operation[op.value] = count

            oldest = conn.execute(
                "SELECT timestamp FROM lineage ORDER BY timestamp ASC LIMIT 1"
            ).fetchone()

            newest = conn.execute(
                "SELECT timestamp FROM lineage ORDER BY timestamp DESC LIMIT 1"
            ).fetchone()

            return {
                "total_records": total,
                "by_operation": by_operation,
                "oldest_record": oldest[0] if oldest else None,
                "newest_record": newest[0] if newest else None,
                "database_path": str(self.db_path),
            }
