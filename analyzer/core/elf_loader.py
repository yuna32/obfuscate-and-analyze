from __future__ import annotations
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


@dataclass
class FunctionInfo:
    name: str
    address: int
    size: int
    data: bytes = field(default_factory=bytes)


HEURISTIC_PATTERNS = [
    bytes([0xF3, 0x0F, 0x1E, 0xFA]),  # ENDBR64
    bytes([0x55]),                      # PUSH RBP (single byte, checked with context)
]


def _looks_like_function_start(data: bytes, offset: int) -> bool:
    if offset + 4 <= len(data) and data[offset:offset + 4] == HEURISTIC_PATTERNS[0]:
        return True
    # PUSH RBP followed by MOV RBP,RSP (55 48 89 E5)
    if offset + 4 <= len(data):
        if data[offset] == 0x55 and data[offset + 1:offset + 4] == bytes([0x48, 0x89, 0xE5]):
            return True
    return False


class ELFLoader:
    def __init__(self, binary_path: str) -> None:
        self.path = Path(binary_path)
        if not self.path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")
        self.raw = self.path.read_bytes()
        self._elf = ELFFile(open(binary_path, "rb"))
        self.functions: list[FunctionInfo] = []
        self._load()

    def _load(self) -> None:
        if self._try_symtab():
            return
        self._heuristic_scan()

    def _try_symtab(self) -> bool:
        for section in self._elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            found = []
            for sym in section.iter_symbols():
                if sym["st_info"]["type"] == "STT_FUNC" and sym["st_size"] > 0:
                    addr = sym["st_value"]
                    size = sym["st_size"]
                    name = sym.name or f"sub_{addr:x}"
                    data = self._read_vaddr(addr, size)
                    found.append(FunctionInfo(name=name, address=addr, size=size, data=data))
            if found:
                self.functions = sorted(found, key=lambda f: f.address)
                return True
        return False

    def _heuristic_scan(self) -> None:
        text = self._elf.get_section_by_name(".text")
        if text is None:
            return
        section_data: bytes = text.data()
        base_vaddr: int = text["sh_addr"]
        candidates: list[int] = []

        for i in range(len(section_data) - 4):
            if _looks_like_function_start(section_data, i):
                candidates.append(i)

        for idx, start in enumerate(candidates):
            end = candidates[idx + 1] if idx + 1 < len(candidates) else len(section_data)
            size = end - start
            addr = base_vaddr + start
            data = section_data[start:end]
            self.functions.append(
                FunctionInfo(name=f"sub_{addr:x}", address=addr, size=size, data=data)
            )

    def _read_vaddr(self, vaddr: int, size: int) -> bytes:
        for segment in self._elf.iter_segments():
            seg_start = segment["p_vaddr"]
            seg_end = seg_start + segment["p_filesz"]
            if seg_start <= vaddr < seg_end:
                offset = segment["p_offset"] + (vaddr - seg_start)
                return self.raw[offset: offset + size]
        return b""

    @property
    def binary_name(self) -> str:
        return self.path.name
