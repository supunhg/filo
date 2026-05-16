"""Tests for CPU architecture detection."""

from filo.architecture import ArchitectureDetector


class TestELFArchitecture:
    """Test ELF architecture detection."""

    def test_elf_x86_64(self):
        """Test x86-64 ELF detection."""
        # ELF 64-bit x86-64 little-endian header
        data = bytes.fromhex(
            "7F454C46"  # ELF magic
            "02"  # 64-bit
            "01"  # Little-endian
            "01"  # Version
            + "00" * 9  # Padding
            + "0200"  # e_type (executable)
            + "3E00"  # e_machine (0x3E = x86-64)
        )

        detector = ArchitectureDetector()
        result = detector.detect_elf_architecture(data)

        assert result is not None
        assert result["architecture"] == "AMD x86-64"
        assert result["bits"] == "64-bit"
        assert result["endian"] == "Little-endian"
        assert result["machine_code"] == 0x3E
        assert result["format"] == "ELF"

    def test_elf_x86_32(self):
        """Test x86 32-bit ELF detection."""
        data = bytes.fromhex(
            "7F454C46"  # ELF magic
            "01"  # 32-bit
            "01"  # Little-endian
            "01"  # Version
            + "00" * 9  # Padding
            + "0200"  # e_type
            + "0300"  # e_machine (0x03 = x86)
        )

        detector = ArchitectureDetector()
        result = detector.detect_elf_architecture(data)

        assert result is not None
        assert result["architecture"] == "x86"
        assert result["bits"] == "32-bit"
        assert result["machine_code"] == 0x03

    def test_elf_arm64(self):
        """Test ARM64/Aarch64 ELF detection."""
        data = bytes.fromhex(
            "7F454C46"  # ELF magic
            "02"  # 64-bit
            "01"  # Little-endian
            "01"  # Version
            + "00" * 9  # Padding
            + "0200"  # e_type
            + "B700"  # e_machine (0xB7 = ARM64)
        )

        detector = ArchitectureDetector()
        result = detector.detect_elf_architecture(data)

        assert result is not None
        assert result["architecture"] == "ARM 64-bits (ARMv8/Aarch64)"
        assert result["bits"] == "64-bit"
        assert result["machine_code"] == 0xB7

    def test_elf_arm32(self):
        """Test ARM 32-bit ELF detection."""
        data = bytes.fromhex(
            "7F454C46"  # ELF magic
            "01"  # 32-bit
            "01"  # Little-endian
            "01"  # Version
            + "00" * 9  # Padding
            + "0200"  # e_type
            + "2800"  # e_machine (0x28 = ARM)
        )

        detector = ArchitectureDetector()
        result = detector.detect_elf_architecture(data)

        assert result is not None
        assert result["architecture"] == "ARM (up to ARMv7/Aarch32)"
        assert result["bits"] == "32-bit"
        assert result["machine_code"] == 0x28

    def test_elf_riscv(self):
        """Test RISC-V ELF detection."""
        data = bytes.fromhex(
            "7F454C46"  # ELF magic
            "02"  # 64-bit
            "01"  # Little-endian
            "01"  # Version
            + "00" * 9  # Padding
            + "0200"  # e_type
            + "F300"  # e_machine (0xF3 = RISC-V)
        )

        detector = ArchitectureDetector()
        result = detector.detect_elf_architecture(data)

        assert result is not None
        assert result["architecture"] == "RISC-V"
        assert result["bits"] == "64-bit"
        assert result["machine_code"] == 0xF3

    def test_elf_mips(self):
        """Test MIPS ELF detection."""
        data = bytes.fromhex(
            "7F454C46"  # ELF magic
            "01"  # 32-bit
            "02"  # Big-endian
            "01"  # Version
            + "00" * 9  # Padding
            + "0002"  # e_type (big-endian)
            + "0008"  # e_machine (0x08 = MIPS, big-endian)
        )

        detector = ArchitectureDetector()
        result = detector.detect_elf_architecture(data)

        assert result is not None
        assert result["architecture"] == "MIPS"
        assert result["bits"] == "32-bit"
        assert result["endian"] == "Big-endian"
        assert result["machine_code"] == 0x08

    def test_elf_xtensa(self):
        """Test Tensilica Xtensa ELF detection (CTF challenge)."""
        data = bytes.fromhex(
            "7F454C46"  # ELF magic
            "01"  # 32-bit
            "01"  # Little-endian
            "01"  # Version
            + "00" * 9  # Padding
            + "0200"  # e_type
            + "5E00"  # e_machine (0x5E = Xtensa)
        )

        detector = ArchitectureDetector()
        result = detector.detect_elf_architecture(data)

        assert result is not None
        assert result["architecture"] == "Tensilica Xtensa Architecture"
        assert result["bits"] == "32-bit"
        assert result["endian"] == "Little-endian"
        assert result["machine_code"] == 0x5E

    def test_elf_powerpc(self):
        """Test PowerPC ELF detection."""
        data = bytes.fromhex(
            "7F454C46"  # ELF magic
            "01"  # 32-bit
            "02"  # Big-endian
            "01"  # Version
            + "00" * 9  # Padding
            + "0002"  # e_type (big-endian)
            + "0014"  # e_machine (0x14 = PowerPC, big-endian)
        )

        detector = ArchitectureDetector()
        result = detector.detect_elf_architecture(data)

        assert result is not None
        assert result["architecture"] == "PowerPC"
        assert result["bits"] == "32-bit"
        assert result["endian"] == "Big-endian"
        assert result["machine_code"] == 0x14

    def test_elf_sparc(self):
        """Test SPARC ELF detection."""
        data = bytes.fromhex(
            "7F454C46"  # ELF magic
            "01"  # 32-bit
            "02"  # Big-endian
            "01"  # Version
            + "00" * 9  # Padding
            + "0002"  # e_type (big-endian)
            + "0002"  # e_machine (0x02 = SPARC, big-endian)
        )

        detector = ArchitectureDetector()
        result = detector.detect_elf_architecture(data)

        assert result is not None
        assert result["architecture"] == "SPARC"
        assert result["bits"] == "32-bit"
        assert result["endian"] == "Big-endian"
        assert result["machine_code"] == 0x02

    def test_elf_unknown_architecture(self):
        """Test unknown architecture code handling."""
        data = bytes.fromhex(
            "7F454C46"  # ELF magic
            "01"  # 32-bit
            "01"  # Little-endian
            "01"  # Version
            + "00" * 9  # Padding
            + "0200"  # e_type
            + "FF99"  # e_machine (unknown: 0x99FF)
        )

        detector = ArchitectureDetector()
        result = detector.detect_elf_architecture(data)

        assert result is not None
        assert "Unknown" in result["architecture"]
        assert "0x99FF" in result["architecture"]

    def test_not_elf(self):
        """Test non-ELF file returns None."""
        data = b"Not an ELF file"

        detector = ArchitectureDetector()
        result = detector.detect_elf_architecture(data)

        assert result is None

    def test_elf_too_short(self):
        """Test truncated ELF returns None."""
        data = bytes.fromhex("7F454C46010100")  # Only 7 bytes

        detector = ArchitectureDetector()
        result = detector.detect_elf_architecture(data)

        assert result is None


class TestPEArchitecture:
    """Test PE/COFF architecture detection."""

    def test_pe_x86(self):
        """Test x86 PE detection."""
        # Create minimal DOS header + PE header
        data = bytearray(128)
        data[0:2] = b"MZ"  # DOS signature
        data[0x3C:0x40] = (0x40).to_bytes(4, "little")  # PE offset at 0x40
        data[0x40:0x44] = b"PE\x00\x00"  # PE signature
        data[0x44:0x46] = (0x014C).to_bytes(2, "little")  # Machine: I386

        detector = ArchitectureDetector()
        result = detector.detect_pe_architecture(bytes(data))

        assert result is not None
        assert result["architecture"] == "x86 (I386)"
        assert result["bits"] == "32-bit"
        assert result["endian"] == "Little-endian"
        assert result["machine_code"] == 0x014C
        assert result["format"] == "PE"

    def test_pe_x64(self):
        """Test x64 PE detection."""
        data = bytearray(128)
        data[0:2] = b"MZ"
        data[0x3C:0x40] = (0x40).to_bytes(4, "little")
        data[0x40:0x44] = b"PE\x00\x00"
        data[0x44:0x46] = (0x8664).to_bytes(2, "little")  # Machine: AMD64

        detector = ArchitectureDetector()
        result = detector.detect_pe_architecture(bytes(data))

        assert result is not None
        assert result["architecture"] == "x64 (AMD64/Intel 64)"
        assert result["bits"] == "64-bit"
        assert result["machine_code"] == 0x8664

    def test_pe_arm64(self):
        """Test ARM64 PE detection."""
        data = bytearray(128)
        data[0:2] = b"MZ"
        data[0x3C:0x40] = (0x40).to_bytes(4, "little")
        data[0x40:0x44] = b"PE\x00\x00"
        data[0x44:0x46] = (0xAA64).to_bytes(2, "little")  # Machine: ARM64

        detector = ArchitectureDetector()
        result = detector.detect_pe_architecture(bytes(data))

        assert result is not None
        assert result["architecture"] == "ARM64 little endian (Aarch64)"
        assert result["bits"] == "64-bit"
        assert result["machine_code"] == 0xAA64

    def test_not_pe(self):
        """Test non-PE file returns None."""
        data = b"Not a PE file"

        detector = ArchitectureDetector()
        result = detector.detect_pe_architecture(data)

        assert result is None


class TestMachOArchitecture:
    """Test Mach-O architecture detection."""

    def test_macho_x86_64(self):
        """Test x86-64 Mach-O detection."""
        data = bytearray(32)
        data[0:4] = (0xFEEDFACF).to_bytes(4, "little")  # 64-bit magic
        data[4:8] = (0x01000007).to_bytes(4, "little")  # CPU type: x86_64

        detector = ArchitectureDetector()
        result = detector.detect_macho_architecture(bytes(data))

        assert result is not None
        assert result["architecture"] == "x86_64"
        assert result["bits"] == "64-bit"
        assert result["endian"] == "Little-endian"
        assert result["format"] == "Mach-O"

    def test_macho_arm64(self):
        """Test ARM64 Mach-O detection."""
        data = bytearray(32)
        data[0:4] = (0xFEEDFACF).to_bytes(4, "little")  # 64-bit magic
        data[4:8] = (0x0100000C).to_bytes(4, "little")  # CPU type: ARM64

        detector = ArchitectureDetector()
        result = detector.detect_macho_architecture(bytes(data))

        assert result is not None
        assert result["architecture"] == "ARM64 (Aarch64)"
        assert result["bits"] == "64-bit"

    def test_macho_i386(self):
        """Test i386 Mach-O detection."""
        data = bytearray(32)
        data[0:4] = (0xFEEDFACE).to_bytes(4, "little")  # 32-bit magic
        data[4:8] = (7).to_bytes(4, "little")  # CPU type: x86

        detector = ArchitectureDetector()
        result = detector.detect_macho_architecture(bytes(data))

        assert result is not None
        assert result["architecture"] == "x86 (I386)"
        assert result["bits"] == "32-bit"

    def test_not_macho(self):
        """Test non-Mach-O file returns None."""
        data = b"Not a Mach-O file"

        detector = ArchitectureDetector()
        result = detector.detect_macho_architecture(data)

        assert result is None


class TestAutoDetect:
    """Test automatic format detection."""

    def test_auto_detect_elf(self):
        """Test auto-detect identifies ELF."""
        data = bytes.fromhex("7F454C46020101000000000000000000" "02003E00")

        detector = ArchitectureDetector()
        result = detector.detect(data)

        assert result is not None
        assert result["format"] == "ELF"
        assert result["architecture"] == "AMD x86-64"

    def test_auto_detect_pe(self):
        """Test auto-detect identifies PE."""
        data = bytearray(128)
        data[0:2] = b"MZ"
        data[0x3C:0x40] = (0x40).to_bytes(4, "little")
        data[0x40:0x44] = b"PE\x00\x00"
        data[0x44:0x46] = (0x8664).to_bytes(2, "little")

        detector = ArchitectureDetector()
        result = detector.detect(bytes(data))

        assert result is not None
        assert result["format"] == "PE"
        assert result["architecture"] == "x64 (AMD64/Intel 64)"

    def test_auto_detect_macho(self):
        """Test auto-detect identifies Mach-O."""
        data = bytearray(32)
        data[0:4] = (0xFEEDFACF).to_bytes(4, "little")
        data[4:8] = (0x01000007).to_bytes(4, "little")

        detector = ArchitectureDetector()
        result = detector.detect(bytes(data))

        assert result is not None
        assert result["format"] == "Mach-O"
        assert result["architecture"] == "x86_64"

    def test_auto_detect_unknown(self):
        """Test auto-detect returns None for unknown format."""
        data = b"Unknown binary format"

        detector = ArchitectureDetector()
        result = detector.detect(data)

        assert result is None
