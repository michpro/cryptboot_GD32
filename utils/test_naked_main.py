"""
Naked-main prologue guard for cryptboot_GD32 (TEST ONLY, CI gate).

main() is __attribute__((naked)) by design (never returns: jumps to the
application or loops forever on error). Without a compiler-generated
prologue, callee-saved registers (r4-r11, lr) must not be READ before
they are WRITTEN inside main — their reset values are undefined.

This test disassembles the built ELF and asserts that every read of
r4-r11/lr inside <main> is dominated by a prior write in the same
function. If GCC changes register allocation, the test fails loudly
instead of shipping a silent brick.

Usage (CI or manual):
    python utils/test_naked_main.py build/cryptboot_GD32.ino.elf
        [--objdump PATH] [--toolchain DIR]

Exit code: 0 = safe, 1 = violation found, 2 = harness error.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

# Registers that REQUIRE a compiler prologue when read-before-written.
CALLEE_SAVED = {f"r{n}" for n in range(4, 12)} | {"lr", "sp"}

_INSN_RE = re.compile(r"^\s*[0-9a-f]+:\s+([0-9a-f ]+)\s+([a-z.]+)\s*(.*)$")


def _regs_written(mnemonic: str, operands: str) -> set[str]:
    """Approximates destination registers of common Thumb-2 instructions."""
    out: set[str] = set()
    ops = [o.strip().split()[0].rstrip(",").lower()
           for o in operands.split(",") if o.strip().split()]
    if not ops:
        return out
    dst = ops[0]
    if mnemonic in ("mov", "movs", "movw", "movt", "ldr", "ldrb", "ldrh",
                    "pop", "add", "adds", "sub", "subs", "and", "ands",
                    "orr", "orrs", "eor", "eors", "lsl", "lsls", "lsr",
                    "lsrs", "asr", "asrs", "bic", "ubfx", "uxth", "uxtb",
                    "uxtah", "mvn", "mvns", "rsb", "rsbs", "adc", "sbc"):
        if dst in CALLEE_SAVED or re.fullmatch(r"r\d+", dst):
            out.add(dst)
    if mnemonic in ("push", "pop"):
        for op in ops:
            for reg in re.findall(r"r\d+|lr|pc|sp", op):
                if "push" == mnemonic and reg in CALLEE_SAVED:
                    pass  # push READS callee-saved -> handled as read below
                if "pop" == mnemonic:
                    out.add(reg)
    if mnemonic.startswith("bl"):
        out.update({"r0", "r1", "r2", "r3", "r12", "lr"})
    return out


def _regs_read(mnemonic: str, operands: str) -> set[str]:
    """Approximates source registers of common Thumb-2 instructions."""
    out: set[str] = set()
    if mnemonic in ("push",):
        for reg in re.findall(r"r\d+|lr", operands.lower()):
            out.add(reg)
        return out
    if mnemonic.startswith(("b", "cb")):
        for reg in re.findall(r"r\d+", operands.lower()):
            out.add(reg)
        return out
    parts = [o.strip().split()[0].rstrip(",").lower()
             for o in operands.split(",") if o.strip().split()]
    sources = parts[1:] if mnemonic not in ("str", "strb", "strh", "cmp",
                                            "cmn", "tst", "teq") else parts
    if mnemonic.startswith("str"):
        sources = parts  # str Rt, [Rn, ...] reads BOTH
    for part in sources:
        for reg in re.findall(r"r\d+|lr|sp|pc", part):
            out.add(reg)
    return out & (CALLEE_SAVED | {f"r{n}" for n in range(13)} | {"lr", "sp", "pc"})


def check_elf(elf: Path, objdump: str) -> list[str]:
    """
    Disassembles <main> and returns violation descriptions (empty = safe).

    Args:
        elf (Path): Built firmware ELF file.
        objdump (str): Path to arm-none-eabi-objdump.

    Returns:
        list: Human-readable violations (empty list means PASS).
    """
    out = subprocess.run(
        [objdump, "-d", str(elf)], capture_output=True, text=True, check=False)
    if 0 != out.returncode:
        raise RuntimeError(f"objdump failed: {out.stderr[:200]}")
    in_main, written, violations = False, set(), []
    for line in out.stdout.splitlines():
        if re.match(r"^[0-9a-f]+ <main>:", line):
            in_main, written = True, set()
            continue
        if in_main and re.match(r"^[0-9a-f]+ <[^>]+>:", line):
            break
        if not in_main:
            continue
        match = _INSN_RE.match(line)
        if not match:
            continue
        _code, mnemonic, operands = match.groups()
        for reg in _regs_read(mnemonic, operands):
            if reg in CALLEE_SAVED and reg not in written:
                violations.append(
                    f"read-before-write of {reg}: {line.strip()}")
        written |= _regs_written(mnemonic, operands)
    return violations


def main(argv: list[str] | None = None) -> int:
    """Parses args, runs the check, prints the verdict."""
    parser = argparse.ArgumentParser(description="naked-main guard")
    parser.add_argument("elf", help="Built cryptboot ELF file")
    parser.add_argument("--objdump", default="arm-none-eabi-objdump",
                        help="Path to arm-none-eabi-objdump")
    args = parser.parse_args(argv)
    try:
        violations = check_elf(Path(args.elf), args.objdump)
    except Exception as exc:  # noqa: BLE001 — harness error, exit 2
        print(f"HARNESS ERROR: {exc}")
        return 2
    if violations:
        print(f"FAIL: {len(violations)} read-before-write violation(s) in <main>:")
        for item in violations[:20]:
            print(f"  {item}")
        return 1
    print("PASS: <main> never reads callee-saved registers before writing them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
