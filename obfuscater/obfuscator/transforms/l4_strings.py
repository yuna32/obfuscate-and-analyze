"""L4: String encryption via single-byte XOR + runtime decryption stub.

Design (no byte-insertion, no section shifting):

  1. Find NULL-terminated strings in .rodata.
  2. XOR-encrypt each string with a random 1-byte key (in-place in file).
  3. Build a 16-byte-per-entry decryption table and write it into the
     zero-padding gap that GCC leaves between the text PT_LOAD segment and
     the next segment (always available in page-aligned ELFs).
  4. Hand-assemble a decryption stub; write it into the same gap.
  5. Extend the text PT_LOAD's p_filesz / p_memsz to cover table + stub.
  6. Patch the .rodata PT_LOAD segment's p_flags to add PF_W so the stub
     can XOR the strings at runtime without triggering SIGSEGV.
  7. Register the stub in .init_array so it runs before main().
"""

from __future__ import annotations

import logging
import random
import struct
from typing import List, Optional, Tuple

from core.elf_parser import ELFInfo, SectionInfo
from transforms.base import Transform

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ELF program-header constants
# ---------------------------------------------------------------------------
_E_PHOFF     = 0x20   # Elf64_Ehdr: e_phoff (8 bytes)
_E_PHENTSIZE = 0x36   # Elf64_Ehdr: e_phentsize (2 bytes)
_E_PHNUM     = 0x38   # Elf64_Ehdr: e_phnum (2 bytes)

_PH_TYPE   = 0        # Elf64_Phdr field offsets
_PH_FLAGS  = 4
_PH_OFFSET = 8
_PH_VADDR  = 16
_PH_FILESZ = 32
_PH_MEMSZ  = 40

PT_LOAD = 1
PF_X = 1
PF_W = 2
PF_R = 4

_MIN_STR_LEN = 4


# ---------------------------------------------------------------------------
# String detection
# ---------------------------------------------------------------------------

def find_null_terminated_strings(
    data: bytes, section_vaddr: int
) -> List[Tuple[int, int, bytes]]:
    """
    Scan *data* for NULL-terminated strings.  Valid characters are printable
    ASCII (0x20–0x7E) plus common whitespace (\\t \\n \\r).

    Returns list of (vaddr, length_without_null, raw_bytes).
    """
    _VALID = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
    results = []
    i = 0
    while i < len(data):
        start = i
        while i < len(data) and data[i] != 0:
            i += 1
        length = i - start
        if length >= _MIN_STR_LEN:
            chunk = data[start:i]
            if all(b in _VALID for b in chunk):
                results.append((section_vaddr + start, length, chunk))
        i += 1
    return results


# ---------------------------------------------------------------------------
# XOR encryption
# ---------------------------------------------------------------------------

def xor_encrypt(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


# ---------------------------------------------------------------------------
# Decryption table
# ---------------------------------------------------------------------------

_ENTRY_SIZE = 16   # 8 (vaddr) + 4 (len) + 1 (key) + 3 (pad)


def build_decrypt_table(
    strings: List[Tuple[int, int, bytes]],
    keys: List[int],
) -> bytes:
    """Build the runtime decryption metadata table."""
    table = bytearray()
    for (vaddr, length, _), key in zip(strings, keys):
        table += struct.pack("<QIBxxx", vaddr, length, key)
    table += b"\x00" * _ENTRY_SIZE   # sentinel (vaddr == 0)
    return bytes(table)


# ---------------------------------------------------------------------------
# Hand-assembled decryption stub
# ---------------------------------------------------------------------------

def build_decrypt_stub(table_vaddr: int, call_orig: int = 0) -> bytes:
    """
    Return x86-64 machine code for the decryption stub.

    If *call_orig* != 0, the stub calls that address first (preserving the
    original .init_array function), then decrypts strings.

    Register layout during decryption loop:
        rbx   = current table entry pointer
        r12   = string virtual address
        r13   = string length
        r14b  = XOR key
        r15   = byte index

    Table entry (16 bytes):
        [0..7]  uint64_t vaddr
        [8..11] uint32_t length
        [12]    uint8_t  key
        [13..15] padding
    """
    buf = bytearray()

    # Prologue
    buf += b"\x53"             # push rbx
    buf += b"\x41\x54"         # push r12
    buf += b"\x41\x55"         # push r13
    buf += b"\x41\x56"         # push r14
    buf += b"\x41\x57"         # push r15

    # Optional: call the original init function first
    if call_orig:
        # mov rax, call_orig  (48 B8 <imm64>)
        buf += b"\x48\xB8" + struct.pack("<Q", call_orig)
        buf += b"\xFF\xD0"     # call rax

    # mov rbx, table_vaddr  (48 BB <imm64>)
    buf += b"\x48\xBB" + struct.pack("<Q", table_vaddr)

    # loop_entry:
    loop_entry = len(buf)
    buf += b"\x4C\x8B\x23"    # mov r12, [rbx]
    buf += b"\x4D\x85\xE4"    # test r12, r12
    jz_off = len(buf)
    buf += b"\x74\x00"         # jz loop_done (patch later)
    # REX.R=1 for r13d/r14d (dst), REX.B=0 for rbx (base; register 3, no high bit)
    buf += b"\x44\x8B\x6B\x08" # mov r13d, [rbx+8]   REX=0x44(R=1,B=0)
    buf += b"\x44\x0F\xB6\x73\x0C"  # movzx r14d, byte [rbx+12]  REX=0x44
    buf += b"\x4D\x31\xFF"     # xor r15, r15

    # byte_loop:
    byte_loop = len(buf)
    # cmp r15, r13: REX=0x4D(W=1,R=1,B=1), ModRM=0xFD(11_111_101)
    buf += b"\x4D\x3B\xFD"    # cmp r15, r13
    jge_off = len(buf)
    buf += b"\x7D\x00"         # jge next_entry (patch later)
    buf += b"\x43\x0F\xB6\x04\x3C"  # movzx eax, byte [r12+r15]
    buf += b"\x41\x33\xC6"    # xor eax, r14d
    buf += b"\x43\x88\x04\x3C" # mov byte [r12+r15], al
    buf += b"\x49\xFF\xC7"    # inc r15
    jmp_byte = len(buf)
    buf += b"\xEB\x00"         # jmp byte_loop (patch later)

    # next_entry:
    next_entry = len(buf)
    buf += b"\x48\x83\xC3\x10" # add rbx, 16
    jmp_loop = len(buf)
    buf += b"\xEB\x00"         # jmp loop_entry (patch later)

    # loop_done:
    loop_done = len(buf)
    buf += b"\x41\x5F"         # pop r15
    buf += b"\x41\x5E"         # pop r14
    buf += b"\x41\x5D"         # pop r13
    buf += b"\x41\x5C"         # pop r12
    buf += b"\x5B"             # pop rbx
    buf += b"\xC3"             # ret

    # Patch relative offsets
    def _r8(from_after: int, to: int) -> int:
        r = to - from_after
        assert -128 <= r <= 127, f"rel8 overflow {r}"
        return r & 0xFF

    buf[jz_off + 1]   = _r8(jz_off + 2,   loop_done)
    buf[jge_off + 1]  = _r8(jge_off + 2,  next_entry)
    buf[jmp_byte + 1] = _r8(jmp_byte + 2, byte_loop)
    buf[jmp_loop + 1] = _r8(jmp_loop + 2, loop_entry)

    return bytes(buf)


# ---------------------------------------------------------------------------
# Program-header helpers
# ---------------------------------------------------------------------------

def _phdr_base(raw: bytes, idx: int) -> int:
    e_phoff     = struct.unpack_from("<Q", raw, _E_PHOFF)[0]
    e_phentsize = struct.unpack_from("<H", raw, _E_PHENTSIZE)[0]
    return e_phoff + idx * e_phentsize


def _find_pt_load(raw: bytes, vaddr: int, need_exec: Optional[bool] = None
                  ) -> Optional[int]:
    """Return program-header index of PT_LOAD covering *vaddr*."""
    e_phnum = struct.unpack_from("<H", raw, _E_PHNUM)[0]
    for i in range(e_phnum):
        base = _phdr_base(raw, i)
        p_type   = struct.unpack_from("<I", raw, base + _PH_TYPE)[0]
        if p_type != PT_LOAD:
            continue
        p_flags  = struct.unpack_from("<I", raw, base + _PH_FLAGS)[0]
        p_vaddr  = struct.unpack_from("<Q", raw, base + _PH_VADDR)[0]
        p_filesz = struct.unpack_from("<Q", raw, base + _PH_FILESZ)[0]
        if p_vaddr <= vaddr < p_vaddr + p_filesz:
            if need_exec is None:
                return i
            is_exec = bool(p_flags & PF_X)
            if is_exec == need_exec:
                return i
    return None


def _update_shdr_size(raw: bytearray, sec: SectionInfo, new_size: int) -> None:
    e_shoff     = struct.unpack_from("<Q", raw, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", raw, 0x3A)[0]
    sh_base = e_shoff + sec.index * e_shentsize
    struct.pack_into("<Q", raw, sh_base + 32, new_size)


# ---------------------------------------------------------------------------
# Transform
# ---------------------------------------------------------------------------

class L4StringTransform(Transform):
    name = "L4:strings"

    def _apply(self, raw: bytearray, info: ELFInfo) -> tuple[bytearray, int]:
        rodata   = info.section(".rodata")
        text     = info.section(".text")
        init_arr = info.section(".init_array")

        if rodata is None:
            logger.warning("[L4] .rodata not found, skipping")
            return raw, 0
        if text is None:
            logger.warning("[L4] .text not found, skipping")
            return raw, 0

        # ---- 1. Find strings ----
        rodata_bytes = bytes(raw[rodata.offset: rodata.offset + rodata.size])
        strings = find_null_terminated_strings(rodata_bytes, rodata.addr)
        if not strings:
            logger.info("[L4] No qualifying strings found in .rodata")
            return raw, 0
        n_strings = len(strings)
        logger.info("[L4] Found %d string(s) in .rodata", n_strings)

        # ---- 2. Generate XOR keys ----
        keys = [random.randint(1, 255) for _ in strings]

        # ---- 3. Encrypt strings in the .rodata file region ----
        rodata_mut = bytearray(rodata_bytes)
        for (vaddr, length, plain), key in zip(strings, keys):
            off = vaddr - rodata.addr
            rodata_mut[off: off + length] = xor_encrypt(plain, key)
        raw[rodata.offset: rodata.offset + rodata.size] = rodata_mut

        # ---- 4. Locate the text PT_LOAD segment ----
        text_phdr_idx = _find_pt_load(bytes(raw), text.addr, need_exec=True)
        rodata_phdr_idx = _find_pt_load(bytes(raw), rodata.addr, need_exec=False)

        if text_phdr_idx is None:
            logger.error("[L4] Cannot find executable PT_LOAD covering .text")
            return raw, 0
        if rodata_phdr_idx is None:
            logger.error("[L4] Cannot find PT_LOAD covering .rodata")
            return raw, 0

        # ---- 5. Compute the slack region after text content ----
        tp = _phdr_base(bytes(raw), text_phdr_idx)
        t_foff   = struct.unpack_from("<Q", raw, tp + _PH_OFFSET)[0]
        t_filesz = struct.unpack_from("<Q", raw, tp + _PH_FILESZ)[0]
        t_memsz  = struct.unpack_from("<Q", raw, tp + _PH_MEMSZ)[0]
        t_vaddr  = struct.unpack_from("<Q", raw, tp + _PH_VADDR)[0]

        slack_foff  = t_foff  + t_filesz
        table_vaddr = t_vaddr + t_filesz

        e_phnum = struct.unpack_from("<H", raw, _E_PHNUM)[0]
        next_foff = len(raw)
        for i in range(e_phnum):
            bp = _phdr_base(bytes(raw), i)
            p_type = struct.unpack_from("<I", raw, bp + _PH_TYPE)[0]
            if p_type != PT_LOAD:
                continue
            pf = struct.unpack_from("<Q", raw, bp + _PH_OFFSET)[0]
            if pf > slack_foff:
                next_foff = min(next_foff, pf)

        # ---- 6. Read the current .init_array[0] to chain into our stub ----
        orig_init = 0
        if init_arr and init_arr.size >= 8:
            orig_init = struct.unpack_from("<Q", raw, init_arr.offset)[0]
            logger.info("[L4] Original .init_array[0] = 0x%x (will chain from stub)", orig_init)

        # ---- Build table & stub ----
        table_bytes = build_decrypt_table(strings, keys)
        stub_vaddr  = table_vaddr + len(table_bytes)
        stub_bytes  = build_decrypt_stub(table_vaddr, call_orig=orig_init)
        total       = len(table_bytes) + len(stub_bytes)

        if slack_foff + total > next_foff:
            logger.error(
                "[L4] Slack space too small: need %d bytes but only %d available",
                total, next_foff - slack_foff,
            )
            return raw, 0

        logger.info("[L4] Table: %d bytes @ vaddr 0x%x (file 0x%x)",
                    len(table_bytes), table_vaddr, slack_foff)
        logger.info("[L4] Stub:  %d bytes @ vaddr 0x%x (file 0x%x)",
                    len(stub_bytes), stub_vaddr, slack_foff + len(table_bytes))

        # ---- 7. Write table and stub into the slack ----
        stub_foff = slack_foff + len(table_bytes)
        raw[slack_foff: slack_foff + len(table_bytes)] = table_bytes
        raw[stub_foff:  stub_foff  + len(stub_bytes)]  = stub_bytes

        # ---- 8. Extend text PT_LOAD to cover table + stub ----
        new_filesz = t_filesz + total
        new_memsz  = max(t_memsz, new_filesz)
        struct.pack_into("<Q", raw, tp + _PH_FILESZ, new_filesz)
        struct.pack_into("<Q", raw, tp + _PH_MEMSZ,  new_memsz)

        # ---- 9. Make .rodata PT_LOAD writable ----
        rp = _phdr_base(bytes(raw), rodata_phdr_idx)
        r_flags = struct.unpack_from("<I", raw, rp + _PH_FLAGS)[0]
        if not (r_flags & PF_W):
            struct.pack_into("<I", raw, rp + _PH_FLAGS, r_flags | PF_W)
            logger.info("[L4] Patched .rodata PT_LOAD flags: 0x%x → 0x%x",
                        r_flags, r_flags | PF_W)

        # ---- 10. Register stub in .init_array ----
        if init_arr is None:
            logger.warning("[L4] .init_array not found — stub will not auto-run!")
            return raw, n_strings

        stub_entry = struct.pack("<Q", stub_vaddr)

        if init_arr.size >= 8:
            raw[init_arr.offset: init_arr.offset + 8] = stub_entry
            logger.info("[L4] Replaced .init_array[0] with stub ptr 0x%x "
                        "(stub will call original 0x%x)", stub_vaddr, orig_init)
            return raw, n_strings

        init_data = bytes(raw[init_arr.offset: init_arr.offset + init_arr.size])
        for off in range(0, len(init_data) - 7, 8):
            if struct.unpack_from("<Q", init_data, off)[0] == 0:
                raw[init_arr.offset + off: init_arr.offset + off + 8] = stub_entry
                logger.info("[L4] Placed stub ptr in null .init_array slot")
                return raw, n_strings

        append_off = init_arr.offset + init_arr.size
        if append_off + 8 <= len(raw) and raw[append_off: append_off + 8] == b"\x00" * 8:
            raw[append_off: append_off + 8] = stub_entry
            _update_shdr_size(raw, init_arr, init_arr.size + 8)
            logger.info("[L4] Appended stub ptr to .init_array")
            return raw, n_strings

        logger.warning("[L4] Unable to register stub — binary will not decrypt at runtime")
        return raw, n_strings
