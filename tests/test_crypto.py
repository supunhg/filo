"""
Tests for cryptographic detection functionality
"""

import pytest
from filo.crypto import CryptoDetector, CryptoAnalysis


class TestEntropyInterpretation:
    """Test entropy interpretation"""
    
    def test_very_low_entropy(self):
        result = CryptoDetector.interpret_entropy(0.5)
        assert "very low" in result.lower()
        assert "repetitive" in result.lower()
    
    def test_low_entropy(self):
        result = CryptoDetector.interpret_entropy(3.0)
        assert "low" in result.lower()
        assert "text" in result.lower()
    
    def test_medium_entropy(self):
        result = CryptoDetector.interpret_entropy(5.5)
        assert "medium" in result.lower()
        assert "compressed" in result.lower() or "encryption" in result.lower()
    
    def test_high_entropy(self):
        result = CryptoDetector.interpret_entropy(7.5)
        assert "high" in result.lower()
        assert "encrypt" in result.lower()
    
    def test_very_high_entropy(self):
        result = CryptoDetector.interpret_entropy(7.95)
        assert "very high" in result.lower()
        assert "strong" in result.lower()


class TestBlockAlignment:
    """Test block cipher alignment detection"""
    
    def test_aes_aligned(self):
        data = b"A" * 48  # 3 AES blocks
        result = CryptoDetector.analyze_block_alignment(data)
        
        assert result["aes_aligned"] is True
        assert result["aes_block_count"] == 3
        assert result["pkcs7_padding_possible"] is True
    
    def test_des_aligned(self):
        data = b"A" * 24  # 3 DES blocks
        result = CryptoDetector.analyze_block_alignment(data)
        
        assert result["des_aligned"] is True
        assert result["des_block_count"] == 3
    
    def test_not_aligned(self):
        data = b"A" * 50  # Not aligned to any block size
        result = CryptoDetector.analyze_block_alignment(data)
        
        assert result["aes_aligned"] is False
        assert result["des_aligned"] is False


class TestECBDetection:
    """Test ECB mode detection"""
    
    def test_ecb_repeating_blocks(self):
        # Create data with repeating 16-byte blocks (ECB pattern)
        block = b"AAAAAAAAAAAAAAAA"  # 16 bytes
        data = block + block + b"B" * 16  # First two blocks identical
        
        result = CryptoDetector.detect_ecb_mode(data, block_size=16)
        assert result is True
    
    def test_no_ecb_unique_blocks(self):
        # Create data with unique blocks (not ECB)
        data = b"A" * 16 + b"B" * 16 + b"C" * 16
        
        result = CryptoDetector.detect_ecb_mode(data, block_size=16)
        assert result is False
    
    def test_ecb_too_small(self):
        # Not enough data for ECB detection
        data = b"AAAAAAAAAAAAAAAA"  # Only 1 block
        
        result = CryptoDetector.detect_ecb_mode(data, block_size=16)
        assert result is False
    
    def test_ecb_not_aligned(self):
        # Data not aligned to block size
        data = b"A" * 50
        
        result = CryptoDetector.detect_ecb_mode(data, block_size=16)
        assert result is False


class TestOpenSSLDetection:
    """Test OpenSSL format detection"""
    
    def test_openssl_salted(self):
        data = b"Salted__" + b"\x00" * 40
        assert CryptoDetector.detect_openssl_format(data) is True
    
    def test_not_openssl(self):
        data = b"NotSalted" + b"\x00" * 40
        assert CryptoDetector.detect_openssl_format(data) is False


class TestPGPDetection:
    """Test PGP/GPG format detection"""
    
    def test_pgp_ascii_armor(self):
        data = b"-----BEGIN PGP MESSAGE-----\n" + b"\x00" * 50
        assert CryptoDetector.detect_pgp_format(data) is True
    
    def test_pgp_binary(self):
        data = b"\x85\x01" + b"\x00" * 50
        assert CryptoDetector.detect_pgp_format(data) is True
    
    def test_not_pgp(self):
        data = b"NotPGP" + b"\x00" * 50
        assert CryptoDetector.detect_pgp_format(data) is False


class TestPKCS7Padding:
    """Test PKCS#7 padding detection"""
    
    def test_valid_padding(self):
        # Valid PKCS#7: last 5 bytes are all 0x05
        data = b"A" * 27 + b"\x05" * 5  # 32 bytes total
        result = CryptoDetector.detect_pkcs7_padding(data)
        assert result == 5
    
    def test_invalid_padding_value(self):
        # Invalid: padding value too large
        data = b"A" * 15 + b"\x20"  # 0x20 = 32, invalid
        result = CryptoDetector.detect_pkcs7_padding(data)
        assert result is None
    
    def test_invalid_padding_inconsistent(self):
        # Invalid: inconsistent padding bytes
        data = b"A" * 28 + b"\x04\x04\x04\x05"
        result = CryptoDetector.detect_pkcs7_padding(data)
        assert result is None


class TestCryptoAnalysis:
    """Test full crypto analysis"""
    
    def test_high_entropy_encrypted(self):
        # Simulate encrypted data (high entropy, AES-aligned)
        data = bytes(range(256)) * 3  # 768 bytes, high entropy
        entropy = 7.8
        
        result = CryptoDetector.analyze(data, entropy)
        
        assert result.is_likely_encrypted is True
        assert result.confidence > 0.7
        assert "high" in result.entropy_interpretation.lower()
        assert "encrypt" in result.entropy_interpretation.lower()
        assert len(result.encryption_indicators) > 0
    
    def test_medium_entropy_maybe_encrypted(self):
        # Simulate compressed data (medium entropy)
        data = b"A" * 48  # AES-aligned but low entropy
        entropy = 5.5
        
        result = CryptoDetector.analyze(data, entropy)
        
        assert "medium" in result.entropy_interpretation.lower()
    
    def test_openssl_format(self):
        # OpenSSL encrypted file
        data = b"Salted__" + b"\x00" * 40
        entropy = 7.9
        
        result = CryptoDetector.analyze(data, entropy)
        
        assert result.is_likely_encrypted is True
        assert result.confidence >= 0.95
        assert any("OpenSSL" in ind for ind in result.encryption_indicators)
        assert any("AES" in hint for hint in result.cipher_hints)
    
    def test_ecb_mode_detection(self):
        # ECB mode with repeating blocks
        block = b"AAAAAAAAAAAAAAAA"
        data = block * 3  # 48 bytes, aligned
        entropy = 3.0  # Low because it's repeating
        
        result = CryptoDetector.analyze(data, entropy)
        
        # Should detect block alignment
        assert result.block_alignment is not None
        assert result.block_alignment["aes_aligned"] is True
        
        # Should detect ECB mode
        assert any("ECB" in ind for ind in result.encryption_indicators)
        assert any("ECB" in hint for hint in result.cipher_hints)
    
    def test_low_entropy_plaintext(self):
        # Regular text file
        data = b"This is a normal text file. " * 10
        entropy = 3.5  # Actually in low range
        
        result = CryptoDetector.analyze(data, entropy)
        
        assert result.is_likely_encrypted is False
        assert "low" in result.entropy_interpretation.lower()
        assert "text" in result.entropy_interpretation.lower()
    
    def test_ctf_challenge_file(self):
        # Simulate the CTF challenge: 48 bytes, medium-high entropy
        data = bytes.fromhex("6afc705dd11147acddb3ae1027773c12c7d9729fbe12b71dd4f821f51629926fcf485b3460e638095596e5ed1215f665")
        entropy = 5.49  # Actual entropy from the challenge
        
        result = CryptoDetector.analyze(data, entropy)
        
        # Should detect AES alignment
        assert result.block_alignment is not None
        assert result.block_alignment["aes_aligned"] is True
        assert result.block_alignment["aes_block_count"] == 3
        
        # Should interpret as compressed/weak encryption
        assert "medium" in result.entropy_interpretation.lower()
        assert "AES" in " ".join(result.cipher_hints)
