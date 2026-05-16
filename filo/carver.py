import logging
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass

from .formats import FormatDatabase
from .analyzer import Analyzer
from .models import AnalysisResult
from .lineage import LineageTracker, OperationType

logger = logging.getLogger(__name__)


@dataclass
class CarvedFile:
    offset: int
    size: int
    format: str
    confidence: float
    data: bytes
    metadata: Dict[str, any] = None
    
    def save(self, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(self.data)


class CarverEngine:
    def __init__(self, format_db: Optional[FormatDatabase] = None, lineage_tracker: Optional[LineageTracker] = None):
        self.format_db = format_db or FormatDatabase()
        self.analyzer = Analyzer(database=self.format_db, use_ml=False)
        self.lineage_tracker = lineage_tracker
        
        self.signatures = self._build_signature_index()
    
    def _build_signature_index(self) -> Dict[bytes, List[str]]:
        """Build index of signatures to format names for fast scanning."""
        sig_index = {}
        
        for format_name in self.format_db.list_formats():
            spec = self.format_db.get_format(format_name)
            if not spec:
                continue
                
            for sig in spec.signatures:
                if sig.offset == 0:
                    sig_bytes = bytes.fromhex(sig.hex.replace(" ", ""))
                    if sig_bytes not in sig_index:
                        sig_index[sig_bytes] = []
                    sig_index[sig_bytes].append(format_name)
        
        return sig_index
    
    def carve_file(self, file_path: Path, min_size: int = 512, max_size: Optional[int] = None) -> List[CarvedFile]:
        """Carve embedded files from a file."""
        with open(file_path, "rb") as f:
            data = f.read()
        
        return self.carve_data(data, min_size=min_size, max_size=max_size)
    
    def carve_data(self, data: bytes, min_size: int = 512, max_size: Optional[int] = None) -> List[CarvedFile]:
        """Carve embedded files from binary data."""
        carved_files = []
        data_len = len(data)
        
        if max_size is None:
            max_size = data_len
        
        logger.info(f"Carving {data_len} bytes, min_size={min_size}, max_size={max_size}")
        
        for signature, format_names in self.signatures.items():
            sig_len = len(signature)
            offset = 0
            
            while offset < data_len - sig_len:
                idx = data.find(signature, offset)
                if idx == -1:
                    break
                
                logger.debug(f"Found signature for {format_names} at offset {idx}")
                
                chunk = data[idx:min(idx + max_size, data_len)]
                if len(chunk) < min_size:
                    offset = idx + 1
                    continue
                
                result = self.analyzer.analyze(chunk)
                
                if result.primary_format and result.confidence > 0.5:
                    file_size = self._estimate_file_size(chunk, result)
                    
                    if file_size >= min_size:
                        carved_data = data[idx:idx + file_size]
                        
                        carved = CarvedFile(
                            offset=idx,
                            size=file_size,
                            format=result.primary_format,
                            confidence=result.confidence,
                            data=carved_data,
                            metadata={
                                "alternative_formats": result.alternative_formats,
                                "evidence": result.evidence_chain
                            }
                        )
                        
                        # Record lineage if tracker available
                        if self.lineage_tracker:
                            self.lineage_tracker.record(
                                original_data=data,
                                result_data=carved_data,
                                operation=OperationType.CARVE,
                                offset=idx,
                                size=file_size,
                                format=result.primary_format,
                                confidence=result.confidence
                            )
                        
                        carved_files.append(carved)
                        logger.info(f"Carved {result.primary_format} at offset {idx}, size {file_size}")
                        
                        offset = idx + file_size
                    else:
                        offset = idx + 1
                else:
                    offset = idx + 1
        
        carved_files.sort(key=lambda x: x.offset)
        return carved_files
    
    def _estimate_file_size(self, data: bytes, result: AnalysisResult) -> int:
        """Estimate actual file size based on format and structure."""
        format_name = result.primary_format
        spec = self.format_db.get_format(format_name)
        
        if not spec or not spec.structure:
            return self._estimate_by_footer(data, format_name)
        
        # Use footer detection as the primary size estimation method
        return self._estimate_by_footer(data, format_name)
    
    def _read_size_field(self, data: bytes, offset: int, size: int, endian: str) -> int:
        """Read size value from specific offset."""
        if offset + size > len(data):
            return 0
        
        size_bytes = data[offset:offset + size]
        
        if endian == "little":
            return int.from_bytes(size_bytes, byteorder="little")
        else:
            return int.from_bytes(size_bytes, byteorder="big")
    
    def _estimate_by_footer(self, data: bytes, format_name: str) -> int:
        """Estimate size by looking for known footer/EOF markers."""
        footers = {
            "png": b"IEND\xae\x42\x60\x82",
            "jpeg": b"\xff\xd9",
            "gif": b"\x00\x3b",
            "zip": b"PK\x05\x06",
            "rar": b"Rar!\x1a\x07\x01\x00",
            "pdf": b"%%EOF",
        }
        
        footer = footers.get(format_name.lower())
        if footer:
            idx = data.find(footer)
            if idx != -1:
                return idx + len(footer)
        
        return min(len(data), 10 * 1024 * 1024)
    
    def carve_directory(self, dir_path: Path, output_dir: Path, 
                       recursive: bool = False, 
                       min_size: int = 512,
                       max_size: Optional[int] = None) -> Dict[str, List[CarvedFile]]:
        """Carve files from all files in a directory."""
        results = {}
        
        pattern = "**/*" if recursive else "*"
        
        for file_path in dir_path.glob(pattern):
            if file_path.is_file():
                try:
                    carved = self.carve_file(file_path, min_size=min_size, max_size=max_size)
                    
                    if carved:
                        results[str(file_path)] = carved
                        
                        for i, carved_file in enumerate(carved):
                            out_name = f"{file_path.stem}_carved_{i:04d}_{carved_file.format}.bin"
                            out_path = output_dir / out_name
                            carved_file.save(out_path)
                            logger.info(f"Saved carved file to {out_path}")
                
                except Exception as e:
                    logger.error(f"Error carving {file_path}: {e}")
        
        return results


class StreamCarver:
    """Carve files from streaming data (network captures, device streams)."""
    
    def __init__(self, buffer_size: int = 1024 * 1024):
        self.buffer_size = buffer_size
        self.carver = CarverEngine()
        self.buffer = bytearray()
    
    def feed(self, data: bytes) -> List[CarvedFile]:
        """Feed data into the carver and return completed files."""
        self.buffer.extend(data)
        
        carved = self.carver.carve_data(bytes(self.buffer))
        
        if carved:
            last_offset = carved[-1].offset + carved[-1].size
            self.buffer = self.buffer[last_offset:]
        
        if len(self.buffer) > self.buffer_size * 2:
            self.buffer = self.buffer[-self.buffer_size:]
        
        return carved
    
    def finalize(self) -> List[CarvedFile]:
        """Process remaining buffer."""
        if self.buffer:
            return self.carver.carve_data(bytes(self.buffer))
        return []
