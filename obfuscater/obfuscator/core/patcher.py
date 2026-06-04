"""ELF binary patcher: write modified sections back to a raw ELF image."""

from __future__ import annotations

import struct
from typing import Optional

from .elf_parser import ELFInfo, SectionInfo


# ---------------------------------------------------------------------------
# Low-level struct helpers
# ---------------------------------------------------------------------------

def _u16(raw: bytes, off: int) -> int:
    return struct.unpack_from("<H", raw, off)[0]


def _u32(raw: bytes, off: int) -> int:
    return struct.unpack_from("<I", raw, off)[0]


def _u64(raw: bytes, off: int) -> int:
    return struct.unpack_from("<Q", raw, off)[0]


def _p16(raw: bytearray, off: int, v: int) -> None:
    struct.pack_into("<H", raw, off, v)


def _p32(raw: bytearray, off: int, v: int) -> None:
    struct.pack_into("<I", raw, off, v)


def _p64(raw: bytearray, off: int, v: int) -> None:
    struct.pack_into("<Q", raw, off, v)


# ---------------------------------------------------------------------------
# ELF header field offsets (64-bit)
# ---------------------------------------------------------------------------
_ELF64_SHOFF   = 0x28   # e_shoff  (u64)
_ELF64_SHNUM   = 0x3C   # e_shnum  (u16)
_ELF64_SHENTSIZE = 0x3A # e_shentsize (u16)

# Elf64_Shdr field offsets
_SH_NAME    = 0
_SH_TYPE    = 4
_SH_FLAGS   = 8
_SH_ADDR    = 16
_SH_OFFSET  = 24
_SH_SIZE    = 32
_SH_LINK    = 40
_SH_INFO    = 44
_SH_ALIGN   = 48
_SH_ENTSIZE = 56
_SH_ENTRY   = 64   # total size of one Elf64_Shdr


def _shdr_offset(raw: bytes, idx: int) -> int:
    e_shoff = _u64(raw, _ELF64_SHOFF)
    e_shentsize = _u16(raw, _ELF64_SHENTSIZE)
    return e_shoff + idx * e_shentsize


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def replace_section_data(
    raw: bytearray,
    sec: SectionInfo,
    new_data: bytes,
) -> bytearray:
    """
    Replace section content in-place (data must fit within original size).
    Pads with zeros if new_data is shorter.
    """
    if len(new_data) > sec.size:
        raise ValueError(
            f"Section '{sec.name}': new data ({len(new_data)} B) "
            f"exceeds original size ({sec.size} B). Use append_section_data."
        )
    raw[sec.offset: sec.offset + sec.size] = new_data.ljust(sec.size, b"\x00")
    return raw


def patch_section_in_place(
    raw: bytearray,
    sec: SectionInfo,
    new_data: bytes,
) -> bytearray:
    """Overwrite section bytes; updates sh_size in the section header too."""
    # Overwrite file region
    end = sec.offset + sec.size
    raw[sec.offset:end] = new_data[:sec.size].ljust(sec.size, b"\x00")

    # Update sh_size if it changed
    off = _shdr_offset(bytes(raw), sec.index)
    _p64(raw, off + _SH_SIZE, min(len(new_data), sec.size))
    return raw


def append_to_section(
    raw: bytearray,
    sec: SectionInfo,
    extra: bytes,
) -> tuple[bytearray, int]:
    """
    Append extra bytes immediately after the section's current content.

    The section must sit at the end of the file (or the caller must know
    what they are doing).  The section header sh_size is updated.

    Returns (new_raw, file_offset_of_extra).
    """
    insert_at = sec.offset + sec.size
    new_raw = raw[:insert_at] + bytearray(extra) + raw[insert_at:]

    # Fix sh_size
    off = _shdr_offset(bytes(new_raw), sec.index)
    _p64(new_raw, off + _SH_SIZE, sec.size + len(extra))

    # Shift all section headers that come after the insertion point
    e_shnum = _u16(bytes(new_raw), _ELF64_SHNUM)
    e_shentsize = _u16(bytes(new_raw), _ELF64_SHENTSIZE)
    e_shoff = _u64(bytes(new_raw), _ELF64_SHOFF)

    for i in range(e_shnum):
        sh_off = e_shoff + i * e_shentsize
        sh_file_offset = _u64(bytes(new_raw), sh_off + _SH_OFFSET)
        if i != sec.index and sh_file_offset >= insert_at:
            _p64(new_raw, sh_off + _SH_OFFSET, sh_file_offset + len(extra))

    # If section header table itself comes after, shift it too
    if e_shoff >= insert_at:
        _p64(new_raw, _ELF64_SHOFF, e_shoff + len(extra))

    return new_raw, insert_at


def patch_init_array(
    raw: bytearray,
    info: ELFInfo,
    fn_vaddr: int,
) -> bytearray:
    """
    Prepend fn_vaddr to .init_array so the stub runs before main().
    Works whether .init_array already exists or needs to be created
    (creation not implemented here — raises if section missing).
    """
    sec = info.section(".init_array")
    if sec is None:
        raise RuntimeError(".init_array section not found")

    entry = struct.pack("<Q", fn_vaddr)
    # Insert at the beginning of the section
    insert_at = sec.offset
    new_raw = raw[:insert_at] + bytearray(entry) + raw[insert_at:]

    # Update sh_size of .init_array
    off = _shdr_offset(bytes(new_raw), sec.index)
    _p64(new_raw, off + _SH_SIZE, sec.size + 8)

    # Shift other sections / section header table
    e_shnum = _u16(bytes(new_raw), _ELF64_SHNUM)
    e_shentsize = _u16(bytes(new_raw), _ELF64_SHENTSIZE)
    e_shoff = _u64(bytes(new_raw), _ELF64_SHOFF)

    for i in range(e_shnum):
        sh_off = e_shoff + i * e_shentsize
        sh_file_offset = _u64(bytes(new_raw), sh_off + _SH_OFFSET)
        if i != sec.index and sh_file_offset >= insert_at:
            _p64(new_raw, sh_off + _SH_OFFSET, sh_file_offset + 8)

    if e_shoff >= insert_at:
        _p64(new_raw, _ELF64_SHOFF, e_shoff + 8)

    # Also update sh_addr to keep virtual mapping consistent (best-effort)
    # (In a real linker we would fix program headers too; omitted here.)

    return new_raw


def patch_bytes_at(raw: bytearray, file_offset: int, data: bytes) -> bytearray:
    """Patch arbitrary bytes at a known file offset."""
    raw[file_offset: file_offset + len(data)] = data
    return raw
