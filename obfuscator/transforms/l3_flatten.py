"""L3: Control flow flattening.

Strategy (in-place, no section growth):
  For each eligible function in .symtab:
    1. Disassemble (capstone detail mode for RIP-relative detection)
    2. Split into basic blocks; skip if >10 blocks or any CALL present
    3. Copy all blocks to text PT_LOAD slack space at new virtual addresses
       - RIP-relative instructions: recalculate displacement
       - Block terminators (jmp/jcc): replace with state-machine code
       - ret / indirect jmp: keep as-is
    4. Build a dispatcher in slack: load state_var, cmp+jz chain to each block
    5. Patch original function entry with 5-byte JMP trampoline → block_0
    6. Extend text PT_LOAD p_filesz / p_memsz to cover all new bytes

Multiple transforms (L3 + L4) coexist: each reads the current p_filesz to
find the next free slack offset, then extends it.
"""
from __future__ import annotations

import io
import logging
import struct
from typing import Dict, List, Optional, Tuple

import capstone
import capstone.x86
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from core.disasm import BasicBlock, disassemble, find_basic_blocks
from core.elf_parser import ELFInfo
from transforms.base import Transform

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ELF program-header constants (same layout as l4_strings.py)
# ---------------------------------------------------------------------------
_E_PHOFF, _E_PHENTSIZE, _E_PHNUM = 0x20, 0x36, 0x38
_PH_TYPE, _PH_FLAGS, _PH_OFFSET = 0, 4, 8
_PH_VADDR, _PH_FILESZ, _PH_MEMSZ = 16, 32, 40
PT_LOAD, PF_X = 1, 1

MAX_BLOCKS = 10
MIN_BLOCKS = 2

# near-jcc condition codes: mnemonic → second opcode byte (used after 0F prefix)
_JCC_CC: Dict[str, int] = {
    'je': 0x84, 'jz': 0x84, 'jne': 0x85, 'jnz': 0x85,
    'jl': 0x8C, 'jnge': 0x8C, 'jge': 0x8D, 'jnl': 0x8D,
    'jle': 0x8E, 'jng': 0x8E, 'jg': 0x8F, 'jnle': 0x8F,
    'jb': 0x82, 'jnae': 0x82, 'jc': 0x82,
    'jae': 0x83, 'jnb': 0x83, 'jnc': 0x83,
    'jbe': 0x86, 'jna': 0x86, 'ja': 0x87, 'jnbe': 0x87,
    'js': 0x88, 'jns': 0x89, 'jo': 0x80, 'jno': 0x81,
    'jp': 0x8A, 'jpe': 0x8A, 'jnp': 0x8B, 'jpo': 0x8B,
}


# ---------------------------------------------------------------------------
# Public helper kept from stub (used externally)
# ---------------------------------------------------------------------------

def extract_basic_blocks(text_bytes: bytes, base_addr: int) -> List[BasicBlock]:
    insns = disassemble(text_bytes, base_addr)
    return find_basic_blocks(insns)


# ---------------------------------------------------------------------------
# Capstone detail-mode instruction wrapper
# ---------------------------------------------------------------------------

class _Insn:
    """Capstone instruction enriched with RIP-relative info."""
    __slots__ = ('address', 'size', 'mnemonic', 'op_str', 'raw',
                 'rip_rel', 'disp_offset', 'disp_size', 'disp_value')

    def __init__(self, cs: capstone.CsInsn) -> None:
        self.address: int = cs.address
        self.size: int = cs.size
        self.mnemonic: str = cs.mnemonic
        self.op_str: str = cs.op_str
        self.raw: bytes = bytes(cs.bytes)
        self.rip_rel = False
        self.disp_offset = 0
        self.disp_size = 0
        self.disp_value = 0
        for op in cs.operands:
            if (op.type == capstone.x86.X86_OP_MEM
                    and op.mem.base == capstone.x86.X86_REG_RIP):
                self.rip_rel = True
                self.disp_offset = cs.disp_offset
                self.disp_size = cs.disp_size
                self.disp_value = cs.disp
                break

    @property
    def is_ret(self) -> bool:
        return self.mnemonic in {'ret', 'retn', 'retf'}

    @property
    def is_call(self) -> bool:
        return self.mnemonic == 'call'

    @property
    def is_jcc(self) -> bool:
        return self.mnemonic in _JCC_CC

    @property
    def is_direct_jmp(self) -> bool:
        return self.mnemonic == 'jmp' and self.op_str.startswith('0x')

    @property
    def is_indirect_jmp(self) -> bool:
        return self.mnemonic == 'jmp' and not self.op_str.startswith('0x')

    @property
    def jmp_target(self) -> Optional[int]:
        if (self.is_direct_jmp or self.is_jcc) and self.op_str.startswith('0x'):
            try:
                return int(self.op_str, 16)
            except ValueError:
                return None
        return None

    @property
    def is_block_ender(self) -> bool:
        return self.is_ret or self.is_call or self.mnemonic == 'jmp' or self.is_jcc


def _disasm_func(func_bytes: bytes, func_vaddr: int) -> List[_Insn]:
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    return [_Insn(i) for i in md.disasm(func_bytes, func_vaddr)]


def _split_blocks(insns: List[_Insn]) -> List[List[_Insn]]:
    if not insns:
        return []
    targets: set = set()
    for i in insns:
        t = i.jmp_target
        if t is not None:
            targets.add(t)
    blocks: List[List[_Insn]] = []
    cur: List[_Insn] = []
    for i in insns:
        if i.address in targets and cur:
            blocks.append(cur)
            cur = []
        cur.append(i)
        if i.is_block_ender:
            blocks.append(cur)
            cur = []
    if cur:
        blocks.append(cur)
    return [b for b in blocks if b]


# ---------------------------------------------------------------------------
# ELF slack-space helpers
# ---------------------------------------------------------------------------

def _phdr_base(raw: bytes, idx: int) -> int:
    phoff = struct.unpack_from('<Q', raw, _E_PHOFF)[0]
    phentsize = struct.unpack_from('<H', raw, _E_PHENTSIZE)[0]
    return phoff + idx * phentsize


def _find_exec_ptload(raw: bytes, text_addr: int) -> Optional[int]:
    n = struct.unpack_from('<H', raw, _E_PHNUM)[0]
    for i in range(n):
        b = _phdr_base(raw, i)
        if struct.unpack_from('<I', raw, b + _PH_TYPE)[0] != PT_LOAD:
            continue
        if not (struct.unpack_from('<I', raw, b + _PH_FLAGS)[0] & PF_X):
            continue
        va = struct.unpack_from('<Q', raw, b + _PH_VADDR)[0]
        fs = struct.unpack_from('<Q', raw, b + _PH_FILESZ)[0]
        if va <= text_addr < va + fs:
            return i
    return None


def _get_slack(raw: bytes, text_addr: int) -> Tuple[int, int, int, int]:
    """Return (phdr_idx, slack_file_offset, slack_vaddr, slack_available_bytes)."""
    idx = _find_exec_ptload(raw, text_addr)
    if idx is None:
        raise RuntimeError("executable PT_LOAD not found")
    b = _phdr_base(raw, idx)
    t_foff   = struct.unpack_from('<Q', raw, b + _PH_OFFSET)[0]
    t_filesz = struct.unpack_from('<Q', raw, b + _PH_FILESZ)[0]
    t_vaddr  = struct.unpack_from('<Q', raw, b + _PH_VADDR)[0]
    slack_foff  = t_foff + t_filesz
    slack_vaddr = t_vaddr + t_filesz
    n = struct.unpack_from('<H', raw, _E_PHNUM)[0]
    next_foff = len(raw)
    for i in range(n):
        bp = _phdr_base(raw, i)
        if struct.unpack_from('<I', raw, bp + _PH_TYPE)[0] != PT_LOAD:
            continue
        pf = struct.unpack_from('<Q', raw, bp + _PH_OFFSET)[0]
        if pf > slack_foff:
            next_foff = min(next_foff, pf)
    return idx, slack_foff, slack_vaddr, next_foff - slack_foff


def _extend_ptload(raw: bytearray, idx: int, extra: int) -> None:
    b = _phdr_base(bytes(raw), idx)
    fs = struct.unpack_from('<Q', raw, b + _PH_FILESZ)[0]
    ms = struct.unpack_from('<Q', raw, b + _PH_MEMSZ)[0]
    struct.pack_into('<Q', raw, b + _PH_FILESZ, fs + extra)
    struct.pack_into('<Q', raw, b + _PH_MEMSZ, max(ms, fs + extra))


PF_W = 2

def _make_ptload_writable(raw: bytearray, idx: int) -> None:
    """Add PF_W to the PT_LOAD at phdr index idx (needed so state_var can be written)."""
    b = _phdr_base(bytes(raw), idx)
    flags = struct.unpack_from('<I', raw, b + _PH_FLAGS)[0]
    if not (flags & PF_W):
        struct.pack_into('<I', raw, b + _PH_FLAGS, flags | PF_W)
        logger.info("[L3] Patched text PT_LOAD flags: 0x%x → 0x%x", flags, flags | PF_W)


# ---------------------------------------------------------------------------
# Symbol table enumeration
# ---------------------------------------------------------------------------

def _get_functions(raw: bytes, text_addr: int, text_end: int) -> List[Tuple[str, int, int]]:
    """Return (name, vaddr, size) for STT_FUNC symbols in .text.

    Many GCC CRT functions have st_size=0; their sizes are inferred from the
    address of the next symbol (sorted by address).
    """
    elf = ELFFile(io.BytesIO(raw))
    symtab = elf.get_section_by_name('.symtab')
    if not isinstance(symtab, SymbolTableSection):
        return []

    # Collect all in-text STT_FUNC symbols (addr > 0, inside .text)
    raw_list: List[Tuple[str, int, int]] = []
    for sym in symtab.iter_symbols():
        if sym.entry.st_info.type != 'STT_FUNC':
            continue
        addr = sym.entry.st_value
        if addr == 0 or not (text_addr <= addr < text_end):
            continue
        raw_list.append((sym.name, addr, sym.entry.st_size))

    if not raw_list:
        return []

    # Sort by address so we can infer sizes of zero-size symbols
    raw_list.sort(key=lambda x: x[1])

    results = []
    for i, (name, addr, size) in enumerate(raw_list):
        if size == 0:
            # Infer from next symbol or text_end
            next_addr = raw_list[i + 1][1] if i + 1 < len(raw_list) else text_end
            size = next_addr - addr
        if size >= 5:
            results.append((name, addr, size))
    return results


# ---------------------------------------------------------------------------
# Byte-level encoding helpers
# ---------------------------------------------------------------------------

def _rel32_bytes(from_end_vaddr: int, to_vaddr: int) -> bytes:
    r = to_vaddr - from_end_vaddr
    if not (-0x80000000 <= r <= 0x7FFFFFFF):
        raise OverflowError(f"rel32 overflow: {r:#x}")
    return struct.pack('<i', r)


def _mov_eax_imm32(n: int) -> bytes:
    return b'\xB8' + struct.pack('<I', n)               # B8 imm32 (5 bytes)


def _store_eax_rip(from_vaddr: int, target_vaddr: int) -> bytes:
    # mov [rip+rel32], eax  →  89 05 rel32  (6 bytes)
    # from_vaddr = start of this instruction; end = from_vaddr+6
    return b'\x89\x05' + _rel32_bytes(from_vaddr + 6, target_vaddr)


def _load_eax_rip(from_vaddr: int, target_vaddr: int) -> bytes:
    # mov eax, [rip+rel32]  →  8B 05 rel32  (6 bytes)
    return b'\x8B\x05' + _rel32_bytes(from_vaddr + 6, target_vaddr)


def _jmp_near(from_vaddr: int, to_vaddr: int) -> bytes:
    # E9 rel32 (5 bytes)
    return b'\xE9' + _rel32_bytes(from_vaddr + 5, to_vaddr)


def _jcc_near(cc: int, from_vaddr: int, to_vaddr: int) -> bytes:
    # 0F 8X rel32 (6 bytes)
    return bytes([0x0F, cc]) + _rel32_bytes(from_vaddr + 6, to_vaddr)


def _fix_rip_rel_insn(insn: _Insn, new_vaddr: int) -> bytes:
    """Recalculate a RIP-relative displacement for a moved instruction."""
    old_disp = struct.unpack_from('<i', insn.raw, insn.disp_offset)[0]
    abs_target = insn.address + insn.size + old_disp
    new_disp = abs_target - (new_vaddr + insn.size)
    if not (-0x80000000 <= new_disp <= 0x7FFFFFFF):
        raise OverflowError(f"RIP-rel fixup overflow for insn @ 0x{insn.address:x}")
    b = bytearray(insn.raw)
    struct.pack_into('<i', b, insn.disp_offset, new_disp)
    return bytes(b)


def _fix_direct_branch(insn: _Insn, new_vaddr: int, abs_target: int) -> bytes:
    """Fix a direct jmp/jcc when moved to new_vaddr, expanding short→near if needed."""
    op = insn.raw[0]
    if op == 0xE9:                          # near jmp (E9 rel32)
        return b'\xE9' + _rel32_bytes(new_vaddr + 5, abs_target)
    if op == 0xEB:                          # short jmp (EB rel8) → expand to near
        return b'\xE9' + _rel32_bytes(new_vaddr + 5, abs_target)
    if 0x70 <= op <= 0x7F:                  # short jcc (7X rel8) → expand near
        cc = 0x80 | (op & 0x0F)
        return bytes([0x0F, cc]) + _rel32_bytes(new_vaddr + 6, abs_target)
    if op == 0x0F and len(insn.raw) >= 2:   # near jcc (0F 8X rel32)
        return bytes([0x0F, insn.raw[1]]) + _rel32_bytes(new_vaddr + 6, abs_target)
    raise ValueError(f"Unknown branch opcode {op:#04x} @ 0x{insn.address:x}")


# ---------------------------------------------------------------------------
# Terminator size calculation (must match _emit_terminator exactly)
# ---------------------------------------------------------------------------

def _term_size(term: _Insn, func_start: int, func_end: int) -> int:
    if term.is_ret or term.is_indirect_jmp:
        return term.size  # kept verbatim

    if term.is_direct_jmp:
        tgt = term.jmp_target
        if tgt is None or not (func_start <= tgt < func_end):
            # external direct jmp: keep encoding but expanded to near (5 bytes)
            return 5
        # internal jmp → state machine: mov eax(5) + store(6) + jmp(5) = 16
        return 16

    if term.is_jcc:
        tgt = term.jmp_target
        if tgt is None or not (func_start <= tgt < func_end):
            # external jcc: expand to near = 6 bytes
            return 6
        # internal jcc → state machine: near_jcc(6) + false_path(16) + true_path(16) = 38
        return 38

    return term.size  # fallback: keep


def _emit_terminator(
    term: _Insn,
    term_new_vaddr: int,
    state_ids: Dict[int, int],
    state_var_vaddr: int,
    disp_vaddr: int,
    func_start: int,
    func_end: int,
) -> bytes:
    if term.is_ret or term.is_indirect_jmp:
        return term.raw

    if term.is_direct_jmp:
        tgt = term.jmp_target
        if tgt is None or not (func_start <= tgt < func_end):
            return _fix_direct_branch(term, term_new_vaddr, tgt or 0)
        # Internal jmp: set state → jmp dispatcher
        ns = state_ids[tgt]
        out  = _mov_eax_imm32(ns)                               # 5B @ v+0
        out += _store_eax_rip(term_new_vaddr + 5, state_var_vaddr)  # 6B @ v+5
        out += _jmp_near(term_new_vaddr + 11, disp_vaddr)           # 5B @ v+11
        assert len(out) == 16
        return out

    if term.is_jcc:
        tgt = term.jmp_target
        if tgt is None or not (func_start <= tgt < func_end):
            return _fix_direct_branch(term, term_new_vaddr, tgt or 0)
        # Internal jcc: near_jcc→true_label + false_path + true_path
        cc = _JCC_CC[term.mnemonic]
        fall_addr = term.address + term.size
        false_state = state_ids.get(fall_addr)
        if false_state is None:
            raise KeyError(f"fall-through 0x{fall_addr:x} not a block start")
        true_state = state_ids[tgt]

        false_v = term_new_vaddr + 6       # false path starts after near_jcc
        true_v  = term_new_vaddr + 6 + 16  # true path starts after false path

        out  = _jcc_near(cc, term_new_vaddr, true_v)       # 6B: jump to true path
        # false path (fall-through state)
        out += _mov_eax_imm32(false_state)                  # 5B @ false_v+0
        out += _store_eax_rip(false_v + 5, state_var_vaddr) # 6B @ false_v+5
        out += _jmp_near(false_v + 11, disp_vaddr)           # 5B @ false_v+11
        # true path (branch taken state)
        out += _mov_eax_imm32(true_state)                   # 5B @ true_v+0
        out += _store_eax_rip(true_v + 5, state_var_vaddr)  # 6B @ true_v+5
        out += _jmp_near(true_v + 11, disp_vaddr)            # 5B @ true_v+11
        assert len(out) == 38
        return out

    return term.raw  # fallback


# ---------------------------------------------------------------------------
# Block body emission
# ---------------------------------------------------------------------------

def _calc_block_size(block: List[_Insn], func_start: int, func_end: int) -> int:
    body = sum(i.size for i in block[:-1])   # non-terminator: size doesn't change
    return body + _term_size(block[-1], func_start, func_end)


def _emit_block(
    block: List[_Insn],
    block_new_vaddr: int,
    state_ids: Dict[int, int],
    state_var_vaddr: int,
    disp_vaddr: int,
    func_start: int,
    func_end: int,
) -> bytes:
    out = bytearray()
    cur_v = block_new_vaddr
    for idx, insn in enumerate(block):
        is_term = (idx == len(block) - 1)
        if is_term:
            out += _emit_terminator(insn, cur_v, state_ids,
                                    state_var_vaddr, disp_vaddr,
                                    func_start, func_end)
        else:
            if insn.rip_rel and insn.disp_size == 4:
                out += _fix_rip_rel_insn(insn, cur_v)
            else:
                out += insn.raw
            cur_v += insn.size
    return bytes(out)


# ---------------------------------------------------------------------------
# Dispatcher assembly
# ---------------------------------------------------------------------------

def _assemble_dispatcher(
    block_vaddrs: List[int],
    state_var_vaddr: int,
    disp_vaddr: int,
) -> bytes:
    """
    mov eax, [rip+rel]      ; load state (6 bytes)
    cmp eax, i              ; 3 bytes each
    jz  block_i_vaddr       ; 6 bytes each
    ...
    ud2                      ; 2 bytes (unreachable)
    """
    out = bytearray()
    out += _load_eax_rip(disp_vaddr, state_var_vaddr)      # 6 bytes
    for i, bva in enumerate(block_vaddrs):
        assert 0 <= i <= 127
        out += bytes([0x83, 0xF8, i])                       # cmp eax, i  (3B)
        jz_from_end = disp_vaddr + len(out) + 6
        out += b'\x0F\x84' + _rel32_bytes(jz_from_end, bva)  # jz block_i (6B)
    out += b'\x0F\x0B'                                      # ud2 (2B)
    return bytes(out)


def _dispatcher_size(n_blocks: int) -> int:
    return 6 + n_blocks * 9 + 2


# ---------------------------------------------------------------------------
# Per-function flattening
# ---------------------------------------------------------------------------

def _flatten_one(
    raw: bytearray,
    name: str,
    func_vaddr: int,
    func_size: int,
    text_foff: int,
    text_vaddr: int,
) -> tuple[int, int]:
    """
    Flatten one function.
    Returns (bytes_consumed_in_slack, n_blocks_relocated).
    Raises on any constraint violation.
    """
    func_foff = text_foff + (func_vaddr - text_vaddr)
    func_end  = func_vaddr + func_size
    func_bytes = bytes(raw[func_foff: func_foff + func_size])

    insns = _disasm_func(func_bytes, func_vaddr)
    if not insns:
        raise ValueError("no instructions decoded")

    blocks = _split_blocks(insns)
    n = len(blocks)
    if n < MIN_BLOCKS:
        raise ValueError(f"only {n} block(s) — too few")
    if n > MAX_BLOCKS:
        raise ValueError(f"{n} blocks — exceeds limit")
    if any(any(i.is_call for i in b) for b in blocks):
        raise ValueError("contains CALL")

    # Assign state IDs: original block start vaddr → state index
    state_ids: Dict[int, int] = {b[0].address: i for i, b in enumerate(blocks)}

    # Validate all terminator targets
    for b in blocks:
        term = b[-1]
        if term.is_jcc:
            tgt = term.jmp_target
            if tgt is not None and func_vaddr <= tgt < func_end:
                if tgt not in state_ids:
                    raise ValueError(f"jcc target 0x{tgt:x} not a block start")
                fall = term.address + term.size
                if func_vaddr <= fall < func_end and fall not in state_ids:
                    raise ValueError(f"jcc fall-through 0x{fall:x} not a block start")
        elif term.is_direct_jmp:
            tgt = term.jmp_target
            if tgt is not None and func_vaddr <= tgt < func_end:
                if tgt not in state_ids:
                    raise ValueError(f"jmp target 0x{tgt:x} not a block start")

    # --- Layout calculation ---
    disp_sz = _dispatcher_size(n)
    blk_szs = [_calc_block_size(b, func_vaddr, func_end) for b in blocks]
    total   = 4 + disp_sz + sum(blk_szs)   # 4 = state_var slot

    # Re-read slack to get current free region (may have grown from prior functions)
    idx, slack_foff, slack_vaddr, slack_avail = _get_slack(bytes(raw), text_vaddr)
    if total > slack_avail:
        raise ValueError(f"slack too small ({total} > {slack_avail})")

    state_var_vaddr = slack_vaddr
    disp_vaddr      = slack_vaddr + 4
    block_vaddrs: List[int] = []
    cur_v = disp_vaddr + disp_sz
    for sz in blk_szs:
        block_vaddrs.append(cur_v)
        cur_v += sz

    # --- Assemble ---
    disp_bytes = _assemble_dispatcher(block_vaddrs, state_var_vaddr, disp_vaddr)
    assert len(disp_bytes) == disp_sz, \
        f"dispatcher size mismatch: {len(disp_bytes)} vs {disp_sz}"

    blk_bytes_list = []
    for i, (b, bva, bsz) in enumerate(zip(blocks, block_vaddrs, blk_szs)):
        bb = _emit_block(b, bva, state_ids, state_var_vaddr, disp_vaddr,
                         func_vaddr, func_end)
        if len(bb) != bsz:
            raise AssertionError(
                f"block {i} size mismatch: emitted {len(bb)} vs expected {bsz}"
            )
        blk_bytes_list.append(bb)

    # --- Write to slack ---
    w = slack_foff
    raw[w: w + 4] = b'\x00\x00\x00\x00'           # state_var = 0
    w += 4
    raw[w: w + disp_sz] = disp_bytes
    w += disp_sz
    for bb in blk_bytes_list:
        raw[w: w + len(bb)] = bb
        w += len(bb)

    # --- Trampoline at original function entry ---
    trampoline = b'\xE9' + _rel32_bytes(func_vaddr + 5, block_vaddrs[0])
    raw[func_foff: func_foff + 5] = trampoline

    # --- Extend text PT_LOAD ---
    _extend_ptload(raw, idx, total)

    logger.info("[L3] Flattened '%s' @ 0x%x: %d blocks, %d bytes used in slack",
                name, func_vaddr, n, total)
    return total, n


# ---------------------------------------------------------------------------
# Transform
# ---------------------------------------------------------------------------

class L3FlattenTransform(Transform):
    name = "L3:flatten"

    def _apply(self, raw: bytearray, info: ELFInfo) -> tuple[bytearray, int]:
        text = info.section(".text")
        if text is None:
            logger.warning("[L3] .text section not found, skipping")
            return raw, 0

        text_bytes = bytes(raw[text.offset: text.offset + text.size])
        all_blocks = extract_basic_blocks(text_bytes, text.addr)
        logger.info("[L3] .text has %d basic blocks total", len(all_blocks))

        funcs = _get_functions(bytes(raw), text.addr, text.addr + text.size)
        if not funcs:
            logger.warning("[L3] No STT_FUNC symbols in .text "
                           "(strip binary or missing .symtab — skipping)")
            return raw, 0

        logger.info("[L3] Attempting to flatten %d candidate function(s)", len(funcs))
        n_ok = 0
        total_blocks = 0
        made_writable = False
        for fname, fva, fsz in sorted(funcs, key=lambda x: x[1]):
            try:
                _, n_blocks = _flatten_one(raw, fname, fva, fsz, text.offset, text.addr)
                if not made_writable:
                    idx, _, _, _ = _get_slack(bytes(raw), text.addr)
                    _make_ptload_writable(raw, idx)
                    made_writable = True
                n_ok += 1
                total_blocks += n_blocks
            except Exception as exc:
                logger.debug("[L3] Skip '%s' @ 0x%x: %s", fname, fva, exc)

        if n_ok == 0:
            logger.warning("[L3] No functions flattened — all skipped (see --verbose)")
        else:
            logger.info("[L3] Successfully flattened %d function(s), %d blocks relocated",
                        n_ok, total_blocks)

        return raw, total_blocks
