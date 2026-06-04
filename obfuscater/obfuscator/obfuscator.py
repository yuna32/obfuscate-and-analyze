#!/usr/bin/env python3
"""
x86-64 ELF Binary Obfuscator
Usage: python obfuscator.py --input <elf> --output <elf> --levels L1,L2,L4
"""

from __future__ import annotations

import argparse
import csv
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)-8s %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Imports (defer so that import errors surface cleanly)
# ---------------------------------------------------------------------------
def _import_core():
    from core.elf_parser import parse_elf
    from transforms import REGISTRY
    return parse_elf, REGISTRY


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="x86-64 ELF binary obfuscator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python obfuscator.py --input target --output target_obf --levels L1,L2
  python obfuscator.py --input target --output target_obf --levels L1,L2,L4 --verify
  python obfuscator.py --input target --output target_obf --levels L1 --dry-run
""",
    )
    p.add_argument("--input",  "-i", required=True, help="Input ELF binary")
    p.add_argument("--output", "-o", required=True, help="Output ELF binary")
    p.add_argument(
        "--levels", "-l",
        required=True,
        help="Comma-separated transform levels, e.g. L1,L2,L4",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print transform summary without writing the output file",
    )
    p.add_argument(
        "--verify",
        action="store_true",
        help="Run original and obfuscated binary and compare stdout/stderr",
    )
    p.add_argument(
        "--verify-args",
        default="World",
        help="Arguments to pass to the binary when --verify is used (default: 'World')",
    )
    p.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for reproducible obfuscation",
    )
    p.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug logging",
    )
    p.add_argument(
        "--stats-out",
        metavar="CSV_PATH",
        default=None,
        help="Append a stats row to this CSV file after obfuscation",
    )
    p.add_argument(
        "--stats-target",
        metavar="NAME",
        default=None,
        help="Target name written to the 'target' column in stats CSV",
    )
    return p


# ---------------------------------------------------------------------------
# Verification helper
# ---------------------------------------------------------------------------

def _run_binary(path: str, args: list[str], timeout: int = 10
                ) -> tuple[int, bytes, bytes]:
    """
    Run a binary and return (returncode, stdout, stderr).

    If the binary is not executable (e.g. on an NTFS/WSL mount),
    copy it to a temp file in /tmp, chmod +x, and run from there.
    """
    abs_path = os.path.abspath(path)

    def _try_run(p: str) -> tuple[int, bytes, bytes]:
        try:
            result = subprocess.run(
                [p] + args,
                capture_output=True,
                timeout=timeout,
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            logger.error("Binary %s timed out after %ds", p, timeout)
            return -1, b"", b"TIMEOUT"
        except OSError as e:
            raise

    # First attempt
    try:
        return _try_run(abs_path)
    except OSError as e:
        if e.errno != 13:  # not EACCES
            logger.error("Failed to run %s: %s", path, e)
            return -1, b"", str(e).encode()

    # EACCES: copy to /tmp and retry
    tmp_fd, tmp_path = tempfile.mkstemp(prefix="obf_verify_", dir="/tmp")
    try:
        with open(abs_path, "rb") as src, os.fdopen(tmp_fd, "wb") as dst:
            dst.write(src.read())
        os.chmod(tmp_path, 0o755)
        logger.debug("Copied to %s for execution (NTFS exec workaround)", tmp_path)
        try:
            return _try_run(tmp_path)
        except OSError as e2:
            logger.error("Failed to run %s: %s", path, e2)
            return -1, b"", str(e2).encode()
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def verify_binaries(
    original: str,
    obfuscated: str,
    verify_args: list[str],
) -> bool:
    """
    Execute both binaries with the same arguments and compare output.
    Returns True if outputs match.
    """
    logger.info("Running original:    %s %s", original, " ".join(verify_args))
    rc_orig, out_orig, err_orig = _run_binary(original, verify_args)

    logger.info("Running obfuscated:  %s %s", obfuscated, " ".join(verify_args))
    rc_obf, out_obf, err_obf = _run_binary(obfuscated, verify_args)

    ok = True
    if rc_orig != rc_obf:
        logger.error("Return code mismatch: original=%d obfuscated=%d", rc_orig, rc_obf)
        ok = False
    if out_orig != out_obf:
        logger.error("stdout mismatch:\n  original:   %r\n  obfuscated: %r",
                     out_orig, out_obf)
        ok = False
    if err_orig != err_obf:
        logger.warning("stderr mismatch (may be expected):\n  original:   %r\n  obfuscated: %r",
                       err_orig, err_obf)

    if ok:
        logger.info("[VERIFY] PASS — outputs match")
    else:
        logger.error("[VERIFY] FAIL — outputs differ")
    return ok


# ---------------------------------------------------------------------------
# Stats helpers
# ---------------------------------------------------------------------------

def _get_pt_load_filesz(path: str) -> int:
    """Return the maximum p_filesz among executable PT_LOAD segments."""
    try:
        from elftools.elf.elffile import ELFFile
        PF_X = 0x1
        with open(path, "rb") as f:
            elf = ELFFile(f)
            max_sz = 0
            for seg in elf.iter_segments():
                if seg.header.p_type == "PT_LOAD" and (seg.header.p_flags & PF_X):
                    max_sz = max(max_sz, seg.header.p_filesz)
        return max_sz
    except Exception as e:
        logger.debug("Could not read PT_LOAD filesz from %s: %s", path, e)
        return 0


_STATS_HEADER = ["target", "level", "file_size_bytes", "pt_load_filesz", "injected_count"]


def _write_stats_row(
    csv_path: str,
    target: str,
    level: str,
    file_size: int,
    pt_load_sz: int,
    injected_count: int,
) -> None:
    """Append one row to csv_path, writing the header first if the file is new."""
    needs_header = not os.path.isfile(csv_path) or os.path.getsize(csv_path) == 0
    with open(csv_path, "a", newline="") as f:
        writer = csv.writer(f)
        if needs_header:
            writer.writerow(_STATS_HEADER)
        writer.writerow([target, level, file_size, pt_load_sz, injected_count])
    logger.debug("Stats written to %s", csv_path)


# ---------------------------------------------------------------------------
# Main obfuscation pipeline
# ---------------------------------------------------------------------------

def obfuscate(
    input_path: str,
    output_path: str,
    levels: list[str],
    dry_run: bool = False,
    verify: bool = False,
    verify_args: list[str] | None = None,
    stats_out: str | None = None,
    stats_target: str | None = None,
    stats_level: str | None = None,
) -> bool:
    parse_elf, REGISTRY = _import_core()

    # Validate levels
    unknown = [l for l in levels if l not in REGISTRY]
    if unknown:
        logger.error("Unknown levels: %s.  Available: %s",
                     ", ".join(unknown), ", ".join(REGISTRY))
        return False

    logger.info("Input:  %s", input_path)
    logger.info("Output: %s", output_path)
    logger.info("Levels: %s", " → ".join(levels))

    # Parse ELF
    info = parse_elf(input_path)
    with open(input_path, "rb") as f:
        raw = bytearray(f.read())

    original_size = len(raw)
    injected_count = 0

    # Apply transforms
    for level_name in levels:
        transform_cls = REGISTRY[level_name]
        transform = transform_cls()
        logger.info("--- Applying %s ---", transform.name)
        try:
            raw, count = transform.apply(raw, info)
            injected_count += count
        except NotImplementedError as e:
            logger.warning("Skipping %s (not implemented): %s", level_name, e)
            continue
        except Exception as e:
            logger.error("Transform %s failed: %s", level_name, e)
            raise

    final_size = len(raw)
    logger.info("Size change: %d → %d bytes (%+d)", original_size, final_size,
                final_size - original_size)
    logger.info("Total injected items: %d", injected_count)

    if dry_run:
        logger.info("[dry-run] Not writing output file.")
        return True

    # Write to a temp file first, then rename (preserve original on error)
    out_dir = os.path.dirname(os.path.abspath(output_path)) or "."
    with tempfile.NamedTemporaryFile(dir=out_dir, delete=False) as tmp:
        tmp_path = tmp.name
        tmp.write(raw)

    try:
        # Make executable
        os.chmod(tmp_path, 0o755)
        shutil.move(tmp_path, output_path)
        logger.info("Wrote: %s", output_path)
    except Exception:
        os.unlink(tmp_path)
        raise

    # Write stats row if requested
    if stats_out and not dry_run:
        file_size = os.path.getsize(output_path)
        pt_load_sz = _get_pt_load_filesz(output_path)
        level_label = stats_level or "".join(levels)
        target_label = stats_target or os.path.basename(input_path)
        _write_stats_row(stats_out, target_label, level_label, file_size, pt_load_sz, injected_count)

    if verify:
        args = verify_args or []
        ok = verify_binaries(input_path, output_path, args)
        return ok

    return True


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.seed is not None:
        import random
        random.seed(args.seed)
        logger.info("Random seed: %d", args.seed)

    if not os.path.isfile(args.input):
        logger.error("Input file not found: %s", args.input)
        return 1

    levels = [l.strip().upper() for l in args.levels.split(",") if l.strip()]
    verify_args = args.verify_args.split() if args.verify_args else ["World"]
    # Level label for CSV: join without separator (e.g. "L1L2L3")
    level_label = "".join(levels)

    try:
        ok = obfuscate(
            input_path=args.input,
            output_path=args.output,
            levels=levels,
            dry_run=args.dry_run,
            verify=args.verify,
            verify_args=verify_args,
            stats_out=args.stats_out,
            stats_target=args.stats_target,
            stats_level=level_label,
        )
    except Exception as e:
        logger.error("Fatal error: %s", e)
        if logging.getLogger().level <= logging.DEBUG:
            import traceback
            traceback.print_exc()
        return 1

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
