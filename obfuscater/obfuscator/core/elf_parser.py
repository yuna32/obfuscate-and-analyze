"""ELF parsing utilities using pyelftools."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section


@dataclass
class SectionInfo:
    name: str
    offset: int       # file offset
    addr: int         # virtual address
    size: int
    data: bytes
    flags: int = 0
    align: int = 1
    index: int = 0    # section index in ELF


@dataclass
class ELFInfo:
    entry: int
    sections: dict[str, SectionInfo] = field(default_factory=dict)
    raw: bytes = b""
    is_64bit: bool = True
    little_endian: bool = True

    def section(self, name: str) -> Optional[SectionInfo]:
        return self.sections.get(name)


def parse_elf(path: str) -> ELFInfo:
    with open(path, "rb") as f:
        raw = f.read()

    with open(path, "rb") as f:
        elf = ELFFile(f)
        assert elf.get_machine_arch() == "x64", "Only x86-64 ELF supported"

        info = ELFInfo(
            entry=elf.header.e_entry,
            raw=bytearray(raw),
            is_64bit=True,
            little_endian=(elf.little_endian),
        )

        for idx, sec in enumerate(elf.iter_sections()):
            sec_data = sec.data()
            info.sections[sec.name] = SectionInfo(
                name=sec.name,
                offset=sec["sh_offset"],
                addr=sec["sh_addr"],
                size=sec["sh_size"],
                data=sec_data,
                flags=sec["sh_flags"],
                align=sec["sh_addralign"],
                index=idx,
            )

    return info


def get_section_data(raw: bytes, sec: SectionInfo) -> bytes:
    return raw[sec.offset: sec.offset + sec.size]


def patch_section_data(raw: bytearray, sec: SectionInfo, new_data: bytes) -> bytearray:
    """Overwrite section bytes in raw ELF image (must be same size or smaller)."""
    assert len(new_data) <= sec.size, (
        f"New data ({len(new_data)}) exceeds section size ({sec.size})"
    )
    raw[sec.offset: sec.offset + len(new_data)] = new_data
    return raw


def find_section_header_offset(raw: bytes, section_index: int) -> int:
    """Return file offset of a section header entry."""
    e_shoff = struct.unpack_from("<Q", raw, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", raw, 0x3A)[0]
    return e_shoff + section_index * e_shentsize


def update_section_size(raw: bytearray, section_index: int, new_size: int) -> bytearray:
    """Patch sh_size field of a section header."""
    hdr_off = find_section_header_offset(bytes(raw), section_index)
    # sh_size is at offset 32 within the section header (Elf64_Shdr)
    struct.pack_into("<Q", raw, hdr_off + 32, new_size)
    return raw


def update_section_offset(raw: bytearray, section_index: int, new_offset: int) -> bytearray:
    hdr_off = find_section_header_offset(bytes(raw), section_index)
    # sh_offset is at offset 24 within Elf64_Shdr
    struct.pack_into("<Q", raw, hdr_off + 24, new_offset)
    return raw
