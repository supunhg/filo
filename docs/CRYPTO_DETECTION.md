# Crypto Detection - Filo v0.3.0

**Cryptographic Analysis & Encryption Detection**

Filo's crypto detection automatically identifies encrypted data, analyzes block cipher patterns, and provides actionable intelligence for CTF challenges, malware analysis, and forensic investigations.

## Features

### 🔐 Encryption Detection
- Automatically detects likely encrypted data based on entropy and structural patterns
- Confidence scoring (0-100%) for encryption likelihood
- Identifies multiple encryption indicators

### 📊 Entropy Interpretation
Human-readable Shannon entropy explanation:
- **Very Low (< 1.0)**: Highly repetitive data or sparse files
- **Low (1.0 - 4.0)**: Text, structured data, simple encoding
- **Medium (4.0 - 7.0)**: Compressed data, weak encryption, obfuscation
- **High (7.0 - 7.9)**: Strong compression or encryption
- **Very High (≥ 7.9)**: Strong encryption or cryptographically random data

### 🔢 Block Cipher Analysis
Detects block alignment patterns:
- **AES**: 16-byte block alignment
- **DES/3DES**: 8-byte block alignment
- **Blowfish**: 8-byte block alignment
- **Block counts**: Number of cipher blocks in file
- **PKCS#7 padding**: Detects standard block cipher padding

### ⚠️ ECB Mode Detection
Identifies the insecure ECB (Electronic Codebook) mode:
- Finds repeating ciphertext blocks (security vulnerability)
- Indicates poor encryption practices
- Critical for CTF challenges and security audits

### 🎯 Format Recognition
Identifies known encrypted file formats:
- **OpenSSL**: Command-line encrypted files (`Salted__` header)
- **PGP/GPG**: ASCII armor and binary PGP formats
- Generic block cipher patterns

## Usage

### Basic Analysis

```bash
# Analyze any file for encryption
filo analyze suspicious.bin

# Show all crypto details
filo analyze cipher.bin -a

# JSON output for automation
filo analyze encrypted.dat --json > report.json
```

### Example Output

**Encrypted File (OpenSSL):**
```
File Size: 48 bytes
Entropy: 7.85 bits/byte
  (High - strong compression or encryption likely)

🔐 Encryption Detected: 95% confidence
  • OpenSSL command-line encryption format
  • File size is AES-aligned (3 blocks)

Possible Cipher Types:
  • AES (block size: 16 bytes)
  • OpenSSL enc (likely AES-256-CBC)

Block Analysis:
  • AES blocks: 3
  • PKCS#7 padding possible
```

**ECB Mode Detection (Security Vulnerability):**
```
Entropy: 5.20 bits/byte
  (Medium - compressed data, weak encryption, or obfuscation)

🔐 Encryption Detected: 85% confidence
  • ⚠️  Repeating blocks detected - ECB mode (INSECURE)
  • File size is AES-aligned (8 blocks)

Possible Cipher Types:
  • AES-ECB (Electronic Codebook - deprecated)
```

**Plaintext File:**
```
Entropy: 4.30 bits/byte
  (Low - likely text, structured data, or simple encoding)

No encryption detected.
```

## CTF Challenge Example

**Scenario:** You receive an unknown binary file in a CTF challenge called "Old Habits"

```bash
filo analyze cipher.bin
```

**Output:**
```
Detected Format: unknown
Confidence: 0.0%

File Size: 48 bytes
Entropy: 5.49 bits/byte
  (Medium - compressed data, weak encryption, or obfuscation)
  Crypto indicators: File size is AES-aligned (3 blocks)
```

**Analysis:**
1. ✅ **48 bytes = exactly 3 AES blocks** → Block cipher
2. ✅ **Medium entropy (5.49)** → Weak cipher or ECB mode
3. ✅ **Challenge name "Old Habits"** → Deprecated ECB mode hint
4. 🎯 **Solution**: Try AES-ECB brute force with wordlist

This is exactly how the real "Old Habits" CTF challenge was solved!

## JSON Output

Full crypto analysis available in JSON format:

```json
{
  "crypto_analysis": {
    "is_likely_encrypted": true,
    "encryption_indicators": [
      "Very high entropy (7.85 bits/byte)",
      "File size is AES-aligned (3 blocks)",
      "OpenSSL command-line encryption format"
    ],
    "cipher_hints": [
      "AES (block size: 16 bytes)",
      "OpenSSL enc (likely AES-256-CBC)"
    ],
    "block_alignment": {
      "file_size": 48,
      "aes_aligned": true,
      "aes_block_count": 3,
      "des_aligned": true,
      "des_block_count": 6,
      "blowfish_aligned": true,
      "pkcs7_padding_possible": true
    },
    "entropy_interpretation": "High - strong compression or encryption likely",
    "confidence": 0.95
  }
}
```

## Programmatic Usage

```python
from filo.crypto import CryptoDetector

# Analyze binary data
with open("cipher.bin", "rb") as f:
    data = f.read()

# Calculate entropy (using Filo's StatisticalAnalyzer)
from filo.analyzer import StatisticalAnalyzer
entropy = StatisticalAnalyzer.calculate_entropy(data)

# Perform crypto analysis
crypto_result = CryptoDetector.analyze(data, entropy)

# Check results
if crypto_result.is_likely_encrypted:
    print(f"Encryption detected: {crypto_result.confidence:.0%} confidence")
    print(f"Cipher hints: {crypto_result.cipher_hints}")
    
    # Check for ECB mode
    if any("ECB" in indicator for indicator in crypto_result.encryption_indicators):
        print("⚠️  WARNING: Insecure ECB mode detected!")
    
    # Get block alignment info
    if crypto_result.block_alignment:
        block_info = crypto_result.block_alignment
        if block_info["aes_aligned"]:
            print(f"AES-aligned: {block_info['aes_block_count']} blocks")
```

## Detection Methods

### 1. Entropy Analysis
```python
def interpret_entropy(entropy: float) -> str:
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
```

### 2. Block Alignment Detection
```python
def analyze_block_alignment(data: bytes) -> Dict[str, Any]:
    size = len(data)
    return {
        "aes_aligned": size % 16 == 0,
        "aes_block_count": size // 16 if size % 16 == 0 else None,
        "des_aligned": size % 8 == 0,
        "pkcs7_padding_possible": size % 16 == 0 and size > 16
    }
```

### 3. ECB Mode Detection
```python
def detect_ecb_mode(data: bytes, block_size: int = 16) -> bool:
    """Detect repeating blocks (ECB mode indicator)"""
    if len(data) % block_size != 0:
        return False
    
    blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
    unique_blocks = set(blocks)
    
    return len(blocks) != len(unique_blocks)  # Duplicates = ECB
```

### 4. Format Recognition
```python
def detect_openssl_format(data: bytes) -> bool:
    """Detect OpenSSL command-line encrypted files"""
    return data.startswith(b"Salted__")

def detect_pgp_format(data: bytes) -> bool:
    """Detect PGP/GPG encrypted files"""
    return (data.startswith(b"-----BEGIN PGP") or 
            data.startswith(b"\x85\x01") or  # PGP binary
            data.startswith(b"\x84"))  # Old PGP format
```

## Use Cases

### 1. CTF Challenges
Perfect for:
- Identifying encryption algorithms
- Detecting weak cipher modes (ECB)
- Finding cipher hints from entropy patterns
- Determining if brute-force is viable

### 2. Malware Analysis
Detect:
- Encrypted payloads in executables
- Obfuscated configuration files
- Encrypted command & control (C2) traffic captures
- Packed/crypted malware samples

### 3. Forensic Investigation
Analyze:
- Encrypted user data
- Disk encryption artifacts
- Secure deletion evidence (high entropy in free space)
- Encrypted container files

### 4. Security Audits
Identify:
- Weak encryption practices (ECB mode)
- Insecure cipher choices
- Missing or incorrect padding
- Deprecated crypto formats

## Technical Details

### Entropy Calculation
Uses Shannon entropy formula:
```
H(X) = -Σ P(xi) * log2(P(xi))
```
Where P(xi) is the probability of byte value i (0-255).

### Confidence Scoring
Crypto detection confidence is calculated by combining:
- **Entropy level** (+0.5 to +0.9 based on value)
- **Block alignment** (+0.1 per aligned cipher)
- **ECB detection** (+0.2 if repeating blocks found)
- **Format recognition** (+0.95 for known formats like OpenSSL/PGP)

Maximum confidence capped at 1.0 (100%).

### Block Cipher Indicators

**AES (Advanced Encryption Standard):**
- Block size: 16 bytes
- File size must be multiple of 16
- Common in: OpenSSL, modern encrypted archives

**DES/3DES (Data Encryption Standard):**
- Block size: 8 bytes
- File size must be multiple of 8
- Legacy cipher, still found in older systems

**Blowfish:**
- Block size: 8 bytes (same as DES)
- Variable key size (32-448 bits)
- Common in: bcrypt, older encryption tools

## Limitations

1. **Compressed Files**: High compression can appear as encryption (high entropy)
2. **Small Files**: Statistical analysis less reliable for files < 32 bytes
3. **Encryption + Compression**: May show medium entropy despite strong encryption
4. **Custom Ciphers**: Unknown cipher types won't be identified by name
5. **Stream Ciphers**: Don't have block alignment patterns (harder to detect)

## Best Practices

### For CTF Players
1. Always check entropy interpretation first
2. Look for block alignment hints
3. ECB mode = potential cryptanalysis opportunity
4. Cross-reference challenge name/description with crypto hints
5. Use `--json` for automated crypto parameter extraction

### For Malware Analysts
1. Use `-a` flag to see full block analysis
2. High entropy in unexpected files = suspicious
3. ECB mode in malware = poor operational security
4. Combine with `--explain` for detailed evidence chain
5. Export to JSON for threat intelligence feeds

### For Forensic Investigators
1. Document entropy values in reports (court-ready evidence)
2. Use `--json` output for reproducible analysis
3. Check for PKCS#7 padding to estimate original plaintext size
4. ECB patterns can leak information about plaintext structure
5. Cross-reference with known file formats before concluding encryption

## Testing

Run crypto detection tests:

```bash
# All crypto tests
pytest tests/test_crypto.py -v

# Specific test categories
pytest tests/test_crypto.py::TestEntropyInterpretation -v
pytest tests/test_crypto.py::TestECBDetection -v
pytest tests/test_crypto.py::TestCryptoAnalysis -v

# With coverage
pytest tests/test_crypto.py --cov=filo.crypto --cov-report=html
```

**Test Coverage:**
- ✅ Entropy interpretation (5 tests)
- ✅ Block alignment detection (3 tests)
- ✅ ECB mode detection (4 tests)
- ✅ OpenSSL/PGP format detection (4 tests)
- ✅ PKCS#7 padding detection (3 tests)
- ✅ Full crypto analysis (7 tests including real CTF data)

## Related Features

- **Entropy Calculation**: [analyzer.py](../filo/analyzer.py) - `StatisticalAnalyzer.calculate_entropy()`
- **Steganography Detection**: [STEGANOGRAPHY_DETECTION.md](STEGANOGRAPHY_DETECTION.md) - Distinguishes crypto from stego
- **PCAP Analysis**: [pcap.py](../filo/pcap.py) - Analyze encrypted network traffic
- **Contradiction Detection**: [CONTRADICTION_DETECTION.md](CONTRADICTION_DETECTION.md) - Detect crypto format mismatches

## References

**Cryptographic Standards:**
- [NIST FIPS 197](https://csrc.nist.gov/publications/detail/fips/197/final) - AES Specification
- [RFC 4880](https://datatracker.ietf.org/doc/html/rfc4880) - OpenPGP Message Format
- [PKCS #7](https://datatracker.ietf.org/doc/html/rfc2315) - Padding Standard

**Security Advisories:**
- [ECB Mode Weakness](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)) - Why ECB is insecure
- [Padding Oracle Attacks](https://en.wikipedia.org/wiki/Padding_oracle_attack) - PKCS#7 vulnerabilities

**CTF Resources:**
- [CryptoPals Challenges](https://cryptopals.com/) - Learn crypto attacks
- [CTF Field Guide](https://trailofbits.github.io/ctf/) - Crypto challenge patterns

---

**Release Date**: February 13, 2026  
**Filo Version**: 0.3.0  
**Module**: [filo/crypto.py](../filo/crypto.py)
