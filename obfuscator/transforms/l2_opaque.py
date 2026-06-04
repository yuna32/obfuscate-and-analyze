"""L2: Opaque predicate insertion.

Uses the same NOP-space strategy as L1: finds NOP sequences at block
boundaries and replaces them with an always-false conditional branch
pattern.  Requires at least MIN_NOP_BYTES of contiguous NOP space.

Pattern (fits in N bytes, N >= MIN_NOP_BYTES):

    XOR rdx, rdx    ; 3 bytes — rdx = 0 (ZF cleared implicitly, flags updated)
    TEST rdx, rdx   ; 3 bytes — ZF = 1 always
    JNZ +junk_len   ; 2 bytes — NEVER taken (ZF=1), but looks scary to analyst
    JMP +junk_len   ; 2 bytes — always taken, skips the fake_target junk
    [junk]          ; junk_len = N - 10 bytes
    <real code>

The JNZ target ("fake_target") is the junk region — dead code that is
never reached.  Both JNZ and JMP end up pointing past the junk, which
from the analyst's view looks like a conditional branch with a live target.

Wait — the JNZ and JMP are NOT pointing at the same place:

    offset 0:  XOR rdx, rdx   (3 bytes)
    offset 3:  TEST rdx, rdx  (3 bytes)
    offset 6:  JNZ  +2        (2 bytes) → lands at offset 10  = junk start
    offset 8:  JMP  +J        (2 bytes) → lands at offset 10+J = real code
    offset 10: [J bytes junk]
    offset 10+J: real code continues...

Since JNZ is NOT taken (ZF=1), execution falls through to JMP at offset 8,
which jumps past the junk to real code.  Correct!
"""

from __future__ import annotations

import logging
import random
from typing import List, Tuple

from core.disasm import Instruction, disassemble
from core.elf_parser import ELFInfo
from transforms.base import Transform
from transforms.l1_junk import _fill_junk, _is_nop_insn

logger = logging.getLogger(__name__)

# Minimum NOP bytes needed for the opaque predicate header (10) + at least 1 junk byte
MIN_NOP_BYTES = 11

# Opaque predicate fixed header (10 bytes):
#   XOR rdx, rdx  = 48 31 D2  (3)
#   TEST rdx, rdx = 48 85 D2  (3)
#   JNZ  rel8     = 75 XX     (2)
#   JMP  rel8     = EB XX     (2)
_XOR_RDX  = b"\x48\x31\xD2"
_TEST_RDX = b"\x48\x85\xD2"
_JNZ_REL8 = 0x75
_JMP_REL8 = 0xEB
_HEADER_SIZE = 10   # 3+3+2+2


def _build_opaque(nop_len: int) -> bytes:
    """Build an opaque-predicate sequence that occupies exactly *nop_len* bytes."""
    assert nop_len >= MIN_NOP_BYTES
    junk_len = nop_len - _HEADER_SIZE

    # JNZ jumps forward 2 bytes (past the JMP instruction) to land at the junk
    jnz_offset = 2             # skip the 2-byte JMP → land at [10] = junk_start
    # JMP jumps forward junk_len bytes to land past the junk at real code
    jmp_offset = junk_len      # skip the junk → land at real code

    assert 0 <= jnz_offset <= 127 and 0 <= jmp_offset <= 127, (
        f"rel8 overflow: jnz={jnz_offset}, jmp={jmp_offset}"
    )

    junk, _ = _fill_junk(junk_len)

    return (
        _XOR_RDX
        + _TEST_RDX
        + bytes([_JNZ_REL8, jnz_offset])
        + bytes([_JMP_REL8, jmp_offset])
        + junk
    )


def _find_large_nop_runs(
    instructions: List[Instruction],
    base_addr: int,
    min_bytes: int,
) -> List[Tuple[int, int]]:
    """Like l1_junk._find_nop_runs, but requires at least min_bytes in the run."""
    runs: List[Tuple[int, int]] = []
    n = len(instructions)
    i = 0
    while i < n:
        insn = instructions[i]
        if _is_nop_insn(insn):
            at_boundary = (i == 0) or instructions[i - 1].is_block_end
            if at_boundary:
                start_off = insn.address - base_addr
                total_bytes = 0
                j = i
                while j < n and _is_nop_insn(instructions[j]):
                    total_bytes += instructions[j].size
                    j += 1
                if total_bytes >= min_bytes:
                    runs.append((start_off, total_bytes))
                i = j
                continue
        i += 1
    return runs


def insert_opaques(text_bytes: bytes, base_addr: int) -> Tuple[bytes, int]:
    """
    Replace large NOP sequences with opaque-predicate patterns.
    Returns (new_text_bytes, number_of_sites_modified).
    """
    instructions = disassemble(text_bytes, base_addr)
    if not instructions:
        return text_bytes, 0

    runs = _find_large_nop_runs(instructions, base_addr, MIN_NOP_BYTES)
    if not runs:
        return text_bytes, 0

    result = bytearray(text_bytes)
    modified = 0

    for off, length in runs:
        # Cap jmp_offset at 127 (rel8 max) — trim the NOP window if needed
        usable = min(length, _HEADER_SIZE + 127)
        if usable < MIN_NOP_BYTES:
            continue

        opaque = _build_opaque(usable)
        # If the original NOP run is larger than usable, pad the remainder with NOPs
        tail, _ = _fill_junk(length - usable) if length > usable else (b"", 0)

        result[off: off + length] = opaque + tail
        modified += 1
        logger.debug("[L2] Inserted opaque predicate (%d bytes) at +0x%x", usable, off)

    return bytes(result), modified


class L2OpaqueTransform(Transform):
    name = "L2:opaque"

    def _apply(self, raw: bytearray, info: ELFInfo) -> tuple[bytearray, int]:
        text = info.section(".text")
        if text is None:
            logger.warning("[L2] .text section not found, skipping")
            return raw, 0

        logger.info("[L2] Scanning .text @ 0x%x (%d bytes) for opaque-predicate sites",
                    text.addr, text.size)

        text_bytes = bytes(raw[text.offset: text.offset + text.size])
        new_text, n_sites = insert_opaques(text_bytes, text.addr)

        if n_sites == 0:
            logger.info("[L2] No NOP sequences >= %d bytes found — no change", MIN_NOP_BYTES)
            return raw, 0

        logger.info("[L2] Inserted %d opaque predicate(s)", n_sites)
        raw[text.offset: text.offset + text.size] = new_text
        text.data = new_text
        return raw, n_sites
