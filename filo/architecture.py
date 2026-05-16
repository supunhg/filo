"""CPU Architecture Detection for Executable Files.

This module provides architecture detection for ELF, PE, and Mach-O executables.
"""

import logging
import struct
from typing import Optional

logger = logging.getLogger(__name__)


class ArchitectureDetector:
    """Detect CPU architecture from executable file headers."""

    # ELF e_machine values (from ELF specification)
    # Reference: https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html
    ELF_MACHINES = {
        0x00: "No specific instruction set",
        0x01: "AT&T WE 32100",
        0x02: "SPARC",
        0x03: "x86",
        0x04: "Motorola 68000 (M68k)",
        0x05: "Motorola 88000 (M88k)",
        0x06: "Intel MCU",
        0x07: "Intel 80860",
        0x08: "MIPS",
        0x09: "IBM System/370",
        0x0A: "MIPS RS3000 Little-endian",
        0x0B: "Reserved",
        0x0C: "Reserved",
        0x0D: "Reserved",
        0x0E: "Hewlett-Packard PA-RISC",
        0x0F: "Reserved",
        0x13: "Intel 80960",
        0x14: "PowerPC",
        0x15: "PowerPC (64-bit)",
        0x16: "S390, including S390x",
        0x17: "IBM SPU/SPC",
        0x24: "NEC V800",
        0x25: "Fujitsu FR20",
        0x26: "TRW RH-32",
        0x27: "Motorola RCE",
        0x28: "ARM (up to ARMv7/Aarch32)",
        0x29: "Digital Alpha",
        0x2A: "SuperH",
        0x2B: "SPARC Version 9",
        0x2C: "Siemens TriCore embedded processor",
        0x2D: "Argonaut RISC Core",
        0x2E: "Hitachi H8/300",
        0x2F: "Hitachi H8/300H",
        0x30: "Hitachi H8S",
        0x31: "Hitachi H8/500",
        0x32: "IA-64",
        0x33: "Stanford MIPS-X",
        0x34: "Motorola ColdFire",
        0x35: "Motorola M68HC12",
        0x36: "Fujitsu MMA Multimedia Accelerator",
        0x37: "Siemens PCP",
        0x38: "Sony nCPU embedded RISC processor",
        0x39: "Denso NDR1 microprocessor",
        0x3A: "Motorola Star*Core processor",
        0x3B: "Toyota ME16 processor",
        0x3C: "STMicroelectronics ST100 processor",
        0x3D: "Advanced Logic Corp. TinyJ embedded processor family",
        0x3E: "AMD x86-64",
        0x3F: "Sony DSP Processor",
        0x40: "Digital Equipment Corp. PDP-10",
        0x41: "Digital Equipment Corp. PDP-11",
        0x42: "Siemens FX66 microcontroller",
        0x43: "STMicroelectronics ST9+ 8/16 bit microcontroller",
        0x44: "STMicroelectronics ST7 8-bit microcontroller",
        0x45: "Motorola MC68HC16 Microcontroller",
        0x46: "Motorola MC68HC11 Microcontroller",
        0x47: "Motorola MC68HC08 Microcontroller",
        0x48: "Motorola MC68HC05 Microcontroller",
        0x49: "Silicon Graphics SVx",
        0x4A: "STMicroelectronics ST19 8-bit microcontroller",
        0x4B: "Digital VAX",
        0x4C: "Axis Communications 32-bit embedded processor",
        0x4D: "Infineon Technologies 32-bit embedded processor",
        0x4E: "Element 14 64-bit DSP Processor",
        0x4F: "LSI Logic 16-bit DSP Processor",
        0x50: "Donald Knuth's educational 64-bit processor",
        0x51: "Harvard University machine-independent object files",
        0x52: "SiTera Prism",
        0x53: "Atmel AVR 8-bit microcontroller",
        0x54: "Fujitsu FR30",
        0x55: "Mitsubishi D10V",
        0x56: "Mitsubishi D30V",
        0x57: "NEC v850",
        0x58: "Mitsubishi M32R",
        0x59: "Matsushita MN10300",
        0x5A: "Matsushita MN10200",
        0x5B: "picoJava",
        0x5C: "OpenRISC 32-bit embedded processor",
        0x5D: "ARC International ARCompact processor",
        0x5E: "Tensilica Xtensa Architecture",
        0x5F: "Alphamosaic VideoCore processor",
        0x60: "Thompson Multimedia General Purpose Processor",
        0x61: "National Semiconductor 32000 series",
        0x62: "Tenor Network TPC processor",
        0x63: "Trebia SNP 1000 processor",
        0x64: "STMicroelectronics ST200 microcontroller",
        0x8C: "TMS320C6000 Family",
        0xAF: "MCST Elbrus e2k",
        0xB7: "ARM 64-bits (ARMv8/Aarch64)",
        0xDC: "Zilog Z80",
        0xF3: "RISC-V",
        0xF7: "Berkeley Packet Filter",
        0x101: "WDC 65C816",
    }

    # PE Machine types (from PE/COFF specification)
    # Reference: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
    PE_MACHINES = {
        0x0000: "Unknown",
        0x014C: "x86 (I386)",
        0x0162: "MIPS R3000",
        0x0166: "MIPS little endian (R4000)",
        0x0168: "MIPS R10000",
        0x0169: "MIPS little endian WCI v2",
        0x0183: "old Alpha AXP",
        0x0184: "Alpha AXP",
        0x01A2: "Hitachi SH3",
        0x01A3: "Hitachi SH3 DSP",
        0x01A6: "Hitachi SH4",
        0x01A8: "Hitachi SH5",
        0x01C0: "ARM little endian",
        0x01C2: "Thumb",
        0x01C4: "ARMv7 (or higher) Thumb mode only",
        0x01D3: "Matsushita AM33",
        0x01F0: "PowerPC little endian",
        0x01F1: "PowerPC with floating point support",
        0x0200: "Intel IA64",
        0x0266: "MIPS16",
        0x0268: "Motorola 68000 series",
        0x0284: "Alpha AXP 64-bit",
        0x0366: "MIPS with FPU",
        0x0466: "MIPS16 with FPU",
        0x0520: "Infineon TriCore",
        0x0CEF: "CEF",
        0x0EBC: "EFI Byte Code",
        0x5032: "RISC-V 32-bit address space",
        0x5064: "RISC-V 64-bit address space",
        0x5128: "RISC-V 128-bit address space",
        0x8664: "x64 (AMD64/Intel 64)",
        0x9041: "Mitsubishi M32R little endian",
        0xAA64: "ARM64 little endian (Aarch64)",
        0xC0EE: "clr pure MSIL",
    }

    # Mach-O CPU types (from mach-o/loader.h)
    # Reference: https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/machine.h
    MACHO_CPUTYPES = {
        -1: "ANY",
        1: "VAX",
        6: "MC680x0",
        7: "x86 (I386)",
        0x01000007: "x86_64",
        10: "MC98000",
        11: "HPPA",
        12: "ARM",
        0x0100000C: "ARM64 (Aarch64)",
        13: "MC88000",
        14: "SPARC",
        15: "I860",
        18: "PowerPC",
        0x01000012: "PowerPC 64",
    }

    def __init__(self):
        """Initialize the architecture detector."""
        pass

    def detect_elf_architecture(self, data: bytes) -> Optional[dict]:
        """
        Detect CPU architecture from ELF header.

        Args:
            data: First 20+ bytes of ELF file

        Returns:
            Dict with architecture info or None if not ELF
        """
        if len(data) < 20:
            return None

        # Check ELF magic
        if data[0:4] != b"\x7fELF":
            return None

        # Extract ELF class (32-bit or 64-bit)
        ei_class = data[4]
        class_name = "32-bit" if ei_class == 1 else "64-bit" if ei_class == 2 else "Unknown"

        # Extract endianness
        ei_data = data[5]
        is_little_endian = ei_data == 1
        endian_name = (
            "Little-endian" if is_little_endian else "Big-endian" if ei_data == 2 else "Unknown"
        )

        # Extract e_machine (at offset 0x12 for both 32/64-bit, 2 bytes)
        if is_little_endian:
            e_machine = struct.unpack("<H", data[0x12:0x14])[0]
        else:
            e_machine = struct.unpack(">H", data[0x12:0x14])[0]

        # Get architecture name
        arch_name = self.ELF_MACHINES.get(e_machine, f"Unknown (0x{e_machine:04X})")

        return {
            "architecture": arch_name,
            "bits": class_name,
            "endian": endian_name,
            "machine_code": e_machine,
            "format": "ELF",
        }

    def detect_pe_architecture(self, data: bytes) -> Optional[dict]:
        """
        Detect CPU architecture from PE header.

        Args:
            data: First 128+ bytes of PE file

        Returns:
            Dict with architecture info or None if not PE
        """
        if len(data) < 128:
            return None

        # Check DOS header
        if data[0:2] != b"MZ":
            return None

        # Get PE header offset (at 0x3C)
        pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]

        if pe_offset + 6 > len(data):
            return None

        # Check PE signature
        if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            return None

        # Extract Machine type (2 bytes after PE signature)
        machine = struct.unpack("<H", data[pe_offset + 4 : pe_offset + 6])[0]

        # Get architecture name
        arch_name = self.PE_MACHINES.get(machine, f"Unknown (0x{machine:04X})")

        # Determine bits
        bits = "32-bit"
        if machine in [0x8664, 0xAA64, 0x0200, 0x5064, 0x5128]:
            bits = "64-bit"

        return {
            "architecture": arch_name,
            "bits": bits,
            "endian": "Little-endian",  # PE is always little-endian
            "machine_code": machine,
            "format": "PE",
        }

    def detect_macho_architecture(self, data: bytes) -> Optional[dict]:
        """
        Detect CPU architecture from Mach-O header.

        Args:
            data: First 32+ bytes of Mach-O file

        Returns:
            Dict with architecture info or None if not Mach-O
        """
        if len(data) < 32:
            return None

        # Check magic numbers
        magic = struct.unpack("<I", data[0:4])[0]

        is_little_endian = None
        bits = None

        if magic == 0xFEEDFACE:  # 32-bit little-endian
            is_little_endian = True
            bits = "32-bit"
        elif magic == 0xCEFAEDFE:  # 32-bit big-endian
            is_little_endian = False
            bits = "32-bit"
        elif magic == 0xFEEDFACF:  # 64-bit little-endian
            is_little_endian = True
            bits = "64-bit"
        elif magic == 0xCFFAEDFE:  # 64-bit big-endian
            is_little_endian = False
            bits = "64-bit"
        else:
            return None

        # Extract CPU type (4 bytes at offset 4)
        if is_little_endian:
            cputype = struct.unpack("<i", data[4:8])[0]
        else:
            cputype = struct.unpack(">i", data[4:8])[0]

        # Get architecture name
        arch_name = self.MACHO_CPUTYPES.get(cputype, f"Unknown (0x{cputype:08X})")

        endian_name = "Little-endian" if is_little_endian else "Big-endian"

        return {
            "architecture": arch_name,
            "bits": bits,
            "endian": endian_name,
            "machine_code": cputype,
            "format": "Mach-O",
        }

    def detect(self, data: bytes) -> Optional[dict]:
        """
        Auto-detect architecture from any executable format.

        Args:
            data: First 128+ bytes of file

        Returns:
            Dict with architecture info or None if not recognized
        """
        # Try ELF first
        result = self.detect_elf_architecture(data)
        if result:
            return result

        # Try PE
        result = self.detect_pe_architecture(data)
        if result:
            return result

        # Try Mach-O
        result = self.detect_macho_architecture(data)
        if result:
            return result

        return None
