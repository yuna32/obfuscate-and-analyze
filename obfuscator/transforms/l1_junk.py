"""L1: Junk instruction insertion.

Strategy: find NOP sequences at basic-block boundaries (the alignment
padding that gcc inserts after RET/JMP) and replace them in-place with
semantically equivalent but visually confusing junk instructions.

No section growth, no branch-offset fixups — the substitution occupies
exactly the same bytes as the original NOPs.
"""

from __future__ import annotations

import logging
import random
from typing import List, Tuple

from core.disasm import Instruction, disassemble, find_basic_blocks
from core.elf_parser import ELFInfo
from transforms.base import Transform

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Inert byte sequences (all semantically equivalent to NOP on x86-64)
# ---------------------------------------------------------------------------
_JUNK: List[bytes] = [
    b"\x90",                    # NOP                   (1 byte)
    b"\x66\x90",                # NOP word              (2 bytes)
    b"\x48\x89\xC0",            # MOV rax, rax          (3 bytes)
    b"\x48\x89\xD2",            # MOV rdx, rdx          (3 bytes)
    b"\x48\x89\xF6",            # MOV rsi, rsi          (3 bytes)
    b"\x48\x87\xC0",            # XCHG rax, rax         (3 bytes)
    b"\x48\x8D\x40\x00",        # LEA rax, [rax+0]      (4 bytes)
    b"\x48\x8D\x52\x00",        # LEA rdx, [rdx+0]      (4 bytes)
    b"\x4D\x89\xC0",            # MOV r8, r8            (3 bytes)
]


def _fill_junk(n: int) -> tuple[bytes, int]:
    """Return (exactly n bytes of random inert junk, number of sequences inserted)."""
    if n <= 0:
        return b"", 0
    result = bytearray()
    count = 0
    candidates = sorted(_JUNK, key=len, reverse=True)
    while len(result) < n:
        remaining = n - len(result)
        fits = [j for j in candidates if len(j) <= remaining]
        if fits:
            result.extend(random.choice(fits))
        else:
            result.append(0x90)  # single-byte NOP fallback
        count += 1
    return bytes(result[:n]), count


# ---------------------------------------------------------------------------
# NOP-sequence detection
# ---------------------------------------------------------------------------

def _is_nop_insn(insn: Instruction) -> bool:
    """True if capstone classified the instruction as a NOP variant."""
    return insn.mnemonic == "nop"


def _find_nop_runs(
    instructions: List[Instruction],
    base_addr: int,
) -> List[Tuple[int, int]]:
    """
    Return (offset_in_section, byte_length) for each contiguous run of
    NOP instructions that immediately follows a block-ending instruction
    (RET / JMP / CALL / Jcc).

    'offset_in_section' is relative to the start of the .text section bytes.
    """
    runs: List[Tuple[int, int]] = []
    n = len(instructions)
    i = 0
    while i < n:
        insn = instructions[i]
        # Only look at NOPs that follow a block-ender
        if _is_nop_insn(insn):
            at_boundary = (i == 0) or instructions[i - 1].is_block_end
            if at_boundary:
                start_off = insn.address - base_addr
                total_bytes = 0
                j = i
                while j < n and _is_nop_insn(instructions[j]):
                    total_bytes += instructions[j].size
                    j += 1
                if total_bytes > 0:
                    runs.append((start_off, total_bytes))
                i = j
                continue
        i += 1
    return runs


# ---------------------------------------------------------------------------
# Core transform
# ---------------------------------------------------------------------------

def insert_junk_into_text(text_bytes: bytes, base_addr: int) -> Tuple[bytes, int]:
    """
    Replace NOP sequences at block boundaries with junk.
    Returns (new_text_bytes, total_junk_instruction_count).
    """
    instructions = disassemble(text_bytes, base_addr)
    if not instructions:
        return text_bytes, 0

    nop_runs = _find_nop_runs(instructions, base_addr)
    if not nop_runs:
        return text_bytes, 0

    result = bytearray(text_bytes)
    total_count = 0

    for off, length in nop_runs:
        junk_bytes, n_insns = _fill_junk(length)
        result[off: off + length] = junk_bytes
        total_count += n_insns
        logger.debug("[L1] Replaced %d-byte NOP at +0x%x with junk (%d insns)",
                     length, off, n_insns)

    return bytes(result), total_count


class L1JunkTransform(Transform):
    name = "L1:junk"

    def _apply(self, raw: bytearray, info: ELFInfo) -> tuple[bytearray, int]:
        text = info.section(".text")
        if text is None:
            logger.warning("[L1] .text section not found, skipping")
            return raw, 0

        logger.info("[L1] Scanning .text @ 0x%x (%d bytes) for NOP sequences",
                    text.addr, text.size)

        text_bytes = bytes(raw[text.offset: text.offset + text.size])
        new_text, total_count = insert_junk_into_text(text_bytes, text.addr)

        if total_count == 0:
            logger.info("[L1] No NOP sequences at block boundaries found — no change")
            return raw, 0

        logger.info("[L1] Inserted %d junk instruction(s)", total_count)
        raw[text.offset: text.offset + text.size] = new_text
        text.data = new_text
        return raw, total_count
