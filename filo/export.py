"""
Export functionality for JSON and SARIF reports.
"""

import json
import logging
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from filo.models import AnalysisResult
from filo.repair import RepairReport

logger = logging.getLogger(__name__)


class JSONExporter:
    """Export analysis results to JSON format."""
    
    @staticmethod
    def export_result(result: AnalysisResult, pretty: bool = True) -> str:
        """
        Export single analysis result to JSON.
        
        Args:
            result: Analysis result to export
            pretty: Pretty-print JSON output
            
        Returns:
            JSON string
        """
        data = {
            "format": result.primary_format,
            "confidence": result.confidence,
            "file_size": result.file_size,
            "alternative_formats": [
                {"format": fmt, "confidence": conf}
                for fmt, conf in result.alternative_formats
            ],
            "evidence_chain": result.evidence_chain,
            "entropy": result.entropy,
            "crypto_analysis": result.crypto_analysis,
            "checksum": result.checksum_sha256
        }
        
        indent = 2 if pretty else None
        return json.dumps(data, indent=indent)
    
    @staticmethod
    def export_batch(results: List[tuple[Path, AnalysisResult]], pretty: bool = True) -> str:
        """
        Export batch results to JSON.
        
        Args:
            results: List of (path, result) tuples
            pretty: Pretty-print JSON output
            
        Returns:
            JSON string
        """
        from datetime import datetime, timezone
        
        data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_files": len(results),
            "files": []
        }
        
        for path, result in results:
            file_data = {
                "path": str(path),
                "format": result.primary_format,
                "confidence": result.confidence,
                "file_size": result.file_size,
                "alternative_formats": [
                    {"format": fmt, "confidence": conf}
                    for fmt, conf in result.alternative_formats
                ]
            }
            data["files"].append(file_data)
        
        indent = 2 if pretty else None
        return json.dumps(data, indent=indent)
    
    @staticmethod
    def export_repair(repair_report: RepairReport, pretty: bool = True) -> str:
        """
        Export repair report to JSON.
        
        Args:
            repair_report: Repair report to export
            pretty: Pretty-print JSON output
            
        Returns:
            JSON string
        """
        data = asdict(repair_report)
        indent = 2 if pretty else None
        return json.dumps(data, indent=indent)


class SARIFExporter:
    """
    Export analysis results to SARIF (Static Analysis Results Interchange Format).
    
    SARIF is used by GitHub Advanced Security, VS Code, and other tools.
    Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
    """
    
    TOOL_NAME = "Filo"
    TOOL_VERSION = "1.0.0"
    
    @staticmethod
    def export_result(
        result: AnalysisResult,
        file_path: Optional[Path] = None,
        pretty: bool = True
    ) -> str:
        """
        Export single analysis result to SARIF format.
        
        Args:
            result: Analysis result to export
            file_path: Optional file path for location info
            pretty: Pretty-print JSON output
            
        Returns:
            SARIF JSON string
        """
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": SARIFExporter.TOOL_NAME,
                            "version": SARIFExporter.TOOL_VERSION,
                            "informationUri": "https://github.com/example/filo"
                        }
                    },
                    "results": SARIFExporter._result_to_sarif_results(result, file_path)
                }
            ]
        }
        
        indent = 2 if pretty else None
        return json.dumps(sarif, indent=indent)
    
    @staticmethod
    def export_batch(
        results: List[tuple[Path, AnalysisResult]],
        pretty: bool = True
    ) -> str:
        """
        Export batch results to SARIF format.
        
        Args:
            results: List of (path, result) tuples
            pretty: Pretty-print JSON output
            
        Returns:
            SARIF JSON string
        """
        all_results = []
        
        for path, result in results:
            sarif_results = SARIFExporter._result_to_sarif_results(result, path)
            all_results.extend(sarif_results)
        
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": SARIFExporter.TOOL_NAME,
                            "version": SARIFExporter.TOOL_VERSION,
                            "informationUri": "https://github.com/example/filo"
                        }
                    },
                    "results": all_results
                }
            ]
        }
        
        indent = 2 if pretty else None
        return json.dumps(sarif, indent=indent)
    
    @staticmethod
    def _result_to_sarif_results(
        result: AnalysisResult,
        file_path: Optional[Path] = None
    ) -> List[Dict[str, Any]]:
        """Convert AnalysisResult to SARIF results."""
        sarif_results = []
        
        # Main result
        level = "note"
        if result.confidence < 0.5:
            level = "warning"
        
        message = f"File identified as {result.primary_format} with {result.confidence:.1%} confidence"
        
        sarif_result = {
            "ruleId": "FILE-001",
            "level": level,
            "message": {
                "text": message
            },
            "properties": {
                "format": result.primary_format,
                "confidence": result.confidence,
                "fileSize": result.file_size,
                "alternativeFormats": [
                    {"format": fmt, "confidence": conf}
                    for fmt, conf in result.alternative_formats
                ],
                "entropy": result.entropy,
                "checksum": result.checksum_sha256
            }
        }
        
        if file_path:
            sarif_result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": str(file_path)
                        }
                    }
                }
            ]
        
        sarif_results.append(sarif_result)
        
        return sarif_results


def export_to_file(
    data: str,
    output_path: Path,
    overwrite: bool = False
) -> None:
    """
    Write exported data to file.
    
    Args:
        data: Exported data string
        output_path: Output file path
        overwrite: Allow overwriting existing files
        
    Raises:
        FileExistsError: If file exists and overwrite=False
    """
    output_path = Path(output_path)
    
    if output_path.exists() and not overwrite:
        raise FileExistsError(f"Output file already exists: {output_path}")
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        f.write(data)
    
    logger.info(f"Exported to {output_path}")
