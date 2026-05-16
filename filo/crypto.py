"""
Cryptographic and encoding detection for forensic analysis.

Detects encrypted data, encoding patterns, and cipher characteristics.
"""

from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
import logging

logger = logging.getLogger(__name__)


class CryptoAnalysis(BaseModel):
    """Results of cryptographic analysis"""
    is_likely_encrypted: bool = Field(description="File likely contains encrypted data")
    encryption_indicators: List[str] = Field(default_factory=list, description="Evidence of encryption")
    cipher_hints: List[str] = Field(default_factory=list, description="Possible cipher types")
    block_alignment: Optional[Dict[str, Any]] = Field(default=None, description="Block cipher alignment info")
    entropy_interpretation: str = Field(description="Human-readable entropy interpretation")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in crypto detection")


class CryptoDetector:
    """Detects encrypted/encoded data patterns"""
    
    @staticmethod
    def interpret_entropy(entropy: float) -> str:
        """
        Interpret entropy value for human understanding.
        
        Args:
            entropy: Shannon entropy in bits/byte (0.0 - 8.0)
            
        Returns:
            Human-readable interpretation
        """
        if entropy < 1.0:
            return "Very low - highly repetitive data or sparse file"
        elif entropy < 4.0:
            return "Low - likely text, structured data, or simple encoding"
        elif entropy < 7.0:
            return "Medium - compressed data, weak encryption, or obfuscation"
        elif entropy < 7.9:
            return "High - strong compression or encryption likely"
        else:
            return "Very high - strong encryption or cryptographically random data"
    
    @staticmethod
    def analyze_block_alignment(data: bytes) -> Dict[str, Any]:
        """
        Analyze if file size suggests block cipher usage.
        
        Args:
            data: File data to analyze
            
        Returns:
            Dictionary with block alignment information
        """
        size = len(data)
        
        result = {
            "file_size": size,
            "aes_aligned": size % 16 == 0,
            "aes_block_count": size // 16 if size % 16 == 0 else None,
            "des_aligned": size % 8 == 0,
            "des_block_count": size // 8 if size % 8 == 0 else None,
            "blowfish_aligned": size % 8 == 0,  # Same as DES
        }
        
        # Check for padding (extra block at end)
        if size % 16 == 0 and size > 16:
            result["pkcs7_padding_possible"] = True
        
        return result
    
    @staticmethod
    def detect_ecb_mode(data: bytes, block_size: int = 16) -> bool:
        """
        Detect ECB mode by finding repeating blocks.
        
        ECB mode encrypts identical plaintext blocks to identical ciphertext,
        making it cryptographically weak and detectable.
        
        Args:
            data: Ciphertext to analyze
            block_size: Block size in bytes (16 for AES, 8 for DES)
            
        Returns:
            True if repeating blocks detected (ECB mode likely)
        """
        if len(data) < block_size * 2:
            return False
        
        if len(data) % block_size != 0:
            return False
        
        # Split into blocks
        blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
        
        # Check for duplicates
        unique_blocks = set(blocks)
        has_duplicates = len(blocks) != len(unique_blocks)
        
        return has_duplicates
    
    @staticmethod
    def detect_openssl_format(data: bytes) -> bool:
        """Detect OpenSSL command-line encrypted files"""
        return data.startswith(b"Salted__")
    
    @staticmethod
    def detect_pgp_format(data: bytes) -> bool:
        """Detect PGP/GPG encrypted files"""
        return (data.startswith(b"-----BEGIN PGP") or 
                data.startswith(b"\x85\x01") or  # PGP binary
                data.startswith(b"\x84"))  # Old PGP format
    
    @staticmethod
    def detect_pkcs7_padding(data: bytes) -> Optional[int]:
        """
        Detect PKCS#7 padding at end of data.
        
        Returns:
            Padding length if detected, None otherwise
        """
        if len(data) < 16:
            return None
        
        last_byte = data[-1]
        
        # PKCS#7: padding value = number of padding bytes (1-16)
        if not (1 <= last_byte <= 16):
            return None
        
        # Check if all padding bytes are the same
        padding_bytes = data[-last_byte:]
        if all(b == last_byte for b in padding_bytes):
            return last_byte
        
        return None
    
    @classmethod
    def analyze(cls, data: bytes, entropy: float) -> CryptoAnalysis:
        """
        Perform comprehensive cryptographic analysis.
        
        Args:
            data: File data to analyze
            entropy: Pre-calculated Shannon entropy
            
        Returns:
            CryptoAnalysis with detection results
        """
        indicators = []
        cipher_hints = []
        is_encrypted = False
        confidence = 0.0
        
        # Interpret entropy
        entropy_desc = cls.interpret_entropy(entropy)
        
        # High entropy suggests encryption/compression
        if entropy > 7.5:
            indicators.append(f"Very high entropy ({entropy:.2f} bits/byte)")
            is_encrypted = True
            confidence = 0.9
        elif entropy > 7.0:
            indicators.append(f"High entropy ({entropy:.2f} bits/byte)")
            is_encrypted = True
            confidence = 0.7
        elif entropy > 6.5:
            indicators.append(f"Moderately high entropy ({entropy:.2f} bits/byte)")
            confidence = 0.5
        
        # Block alignment analysis
        block_info = cls.analyze_block_alignment(data)
        
        if block_info["aes_aligned"]:
            indicators.append(f"File size is AES-aligned ({block_info['aes_block_count']} blocks)")
            cipher_hints.append("AES (block size: 16 bytes)")
            confidence += 0.1
        
        if block_info["des_aligned"] and not block_info["aes_aligned"]:
            indicators.append(f"File size is DES/Blowfish-aligned ({block_info['des_block_count']} blocks)")
            cipher_hints.append("DES or Blowfish (block size: 8 bytes)")
            confidence += 0.1
        
        # ECB mode detection (security vulnerability)
        if block_info["aes_aligned"] and len(data) >= 32:
            if cls.detect_ecb_mode(data, 16):
                indicators.append("⚠️  Repeating blocks detected - ECB mode (INSECURE)")
                cipher_hints.append("AES-ECB (Electronic Codebook - deprecated)")
                confidence += 0.2
        
        if block_info["des_aligned"] and len(data) >= 16:
            if cls.detect_ecb_mode(data, 8):
                indicators.append("⚠️  Repeating blocks detected - ECB mode (INSECURE)")
                cipher_hints.append("DES-ECB or 3DES-ECB (deprecated)")
                confidence += 0.2
        
        # PKCS#7 padding detection
        padding_len = cls.detect_pkcs7_padding(data)
        if padding_len:
            indicators.append(f"PKCS#7 padding detected ({padding_len} bytes)")
            confidence += 0.1
        
        # Known encrypted formats
        if cls.detect_openssl_format(data):
            indicators.append("OpenSSL command-line encryption format")
            cipher_hints.append("OpenSSL enc (likely AES-256-CBC)")
            is_encrypted = True
            confidence = 0.95
        
        if cls.detect_pgp_format(data):
            indicators.append("PGP/GPG encrypted format")
            cipher_hints.append("PGP/GPG asymmetric encryption")
            is_encrypted = True
            confidence = 0.95
        
        # Cap confidence at 1.0
        confidence = min(confidence, 1.0)
        
        return CryptoAnalysis(
            is_likely_encrypted=is_encrypted,
            encryption_indicators=indicators,
            cipher_hints=cipher_hints,
            block_alignment=block_info if (block_info["aes_aligned"] or block_info["des_aligned"]) else None,
            entropy_interpretation=entropy_desc,
            confidence=confidence
        )
