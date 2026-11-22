"""Run cryptboot Renode system tests headless (TEST ONLY, local + CI).

Scenarios (each boots the UNMODIFIED CI .elf, no patching):
  jump  — provisioned NVStorage (SIZE + CRC32 over fake app) -> jump to app.
  error — corrupt app + unformatted NVStorage -> error blink loop.

The jump scenario pins the real APPLICATION_CRC_CHECK path: run_boot.py
computes CRC32/MPEG-2 (poly 0x04C11DB7, init 0xFFFFFFFF, MSB-first — same
as GD32 silicon and the CRC stub in cryptboot.repl) over the fake app
words and provisions matching NVStorage entries, so the bootloader's own
CRC engine must agree for the jump to happen.

Usage:
    python tests/renode/run_boot.py --renode <dir> [--elf <path>]
        [--scenario jump|error|all] [--timeout 300]

Exit: 0 = all pass, 1 = failure, 2 = harness error.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RENODE_DIR = ROOT / "tests" / "renode"

APP_LO, APP_HI = 0x08005000, 0x08040000
BOOT_LO, BOOT_HI = 0x08000000, 0x08005000

# Fake app image (must match boot_jump.resc): vector table + self-loop.
APP_WORDS = (0x2000C000, 0x08005009, 0xE7FEE7FE, 0xE7FEE7FE)
APP_SIZE = 4 * len(APP_WORDS)


def crc32_mpeg2_words(words):
    """GD32 hardware CRC: poly 0x04C11DB7, init 0xFFFFFFFF, MSB-first."""
    crc = 0xFFFFFFFF
    poly = 0x04C11DB7
    for word in words:
        for shift in (24, 16, 8, 0):
            crc ^= ((word >> shift) & 0xFF) << 24
            for _ in range(8):
                if 0 != (crc & 0x80000000):
                    crc = ((crc << 1) ^ poly) & 0xFFFFFFFF
                else:
                    crc = (crc << 1) & 0xFFFFFFFF
    return crc


def find_elf(explicit: str | None) -> Path:
    """Locates the bootloader ELF (explicit path or build/ artifact)."""
    if explicit:
        elf = Path(explicit)
        if not elf.is_file():
            raise SystemExit(f"ELF not found: {elf}")
        return elf
    candidates = sorted((ROOT / "build").rglob("cryptboot_GD32.ino.elf"))
    if not candidates:
        raise SystemExit(
            "no cryptboot_GD32.ino.elf under build/; "
            "compile with arduino-cli first"
        )
    return candidates[0]


def find_renode(renode_dir: str | None) -> Path:
    """Locates the Renode executable (arg, env, PATH, or known path)."""
    if renode_dir:
        base = Path(renode_dir)
        exe = base / ("Renode.exe" if os.name == "nt" else "renode")
        if not exe.is_file():
            raise SystemExit(f"Renode executable not found: {exe}")
        return exe
    for cand in (("Renode.exe", "renode.exe", "renode") if os.name == "nt"
                 else ("renode",)):
        found = shutil.which(cand)
        if found:
            return Path(found)
    for hard in (r"C:\Program Files\Programy\Programowanie\Renode",
                 r"C:\Program Files\Renode"):
        exe = Path(hard) / ("Renode.exe" if os.name == "nt" else "renode")
        if exe.is_file():
            return exe
    raise SystemExit("pass --renode <install dir> or set RENODE_DIR")


def run_one(exe: Path, elf: Path, scenario: str, timeout: int) -> tuple[bool, str]:
    """
    Runs one .resc scenario headless and checks PC samples.

    Args:
        exe: Renode executable.
        elf: Bootloader ELF (staged to a space-free path).
        scenario: 'jump' or 'error'.
        timeout: Seconds for the Renode process.

    Returns:
        (ok, detail) pair.
    """
    stage = Path(tempfile.mkdtemp(prefix="rn_cb_"))
    staged_repl = stage / "cryptboot.repl"
    staged_elf = stage / "fw.elf"
    staged_resc = stage / f"boot_{scenario}.resc"
    shutil.copy(RENODE_DIR / "cryptboot.repl", staged_repl)
    shutil.copy(elf, staged_elf)
    text = (RENODE_DIR / f"boot_{scenario}.resc").read_text(encoding="utf-8")
    if "jump" == scenario:
        # NVStorage entries: [magic][SIZE hdr+data][CRC hdr+data].
        # SIZE entry: header 0x0304 (ID=3, len=4) + LE16 size in one DWORD.
        dw1 = 0x0304 | ((APP_SIZE & 0xFFFF) << 16)
        dw2 = (APP_SIZE >> 16) & 0xFFFF | 0x0404 << 16
        crc = crc32_mpeg2_words(APP_WORDS)
        text = text.replace("@NV_DW1@", f"0x{dw1:08X}")
        text = text.replace("@NV_DW2@", f"0x{dw2:08X}")
        text = text.replace("@NV_CRC@", f"0x{crc:08X}")
    # Rewrite platform/elf references to absolute staged paths (avoids
    # `!`/spaces in the repo path breaking the Renode parser), strip
    # comments (the monitor chokes on `#` inside scripts).
    text = text.replace("@cryptboot.repl", "@" + staged_repl.as_posix())
    text = text.replace("@fw.elf", "@" + staged_elf.as_posix())
    text = "\n".join(line for line in text.splitlines()
                     if line.strip() and not line.lstrip().startswith(("#", "//")))
    staged_resc.write_text(text + "\n", encoding="utf-8")
    cmd = [str(exe), "--disable-xwt", "--console", str(staged_resc)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, cwd=str(stage))
    except subprocess.TimeoutExpired:
        return False, "renode timeout"
    tail = proc.stdout + proc.stderr
    if "RENODE-BOOT-CHECK-DONE" not in tail:
        return False, "missing DONE marker"
    pcs = [int(v, 16) for v in re.findall(r"0x[0-9a-fA-F]+", tail)
           if re.fullmatch(r"0x[0-9a-fA-F]+", v.strip())]
    pcs = [v for v in pcs if 0x08000000 <= v < 0x08100000]
    if 2 > len(pcs):
        return False, f"need 2 PC samples, got {pcs}"
    pc1, pc2 = pcs[-2], pcs[-1]
    if "jump" == scenario:
        ok = (APP_LO <= pc1 < APP_HI) or (APP_LO <= pc2 < APP_HI)
        return ok, f"PC1={pc1:#x} PC2={pc2:#x} (expect app range)"
    ok = (BOOT_LO <= pc1 < BOOT_HI) and (BOOT_LO <= pc2 < BOOT_HI)
    return ok, f"PC1={pc1:#x} PC2={pc2:#x} (expect bootloader range)"


def main(argv=None) -> int:
    """Parses args, runs scenarios, prints the verdict."""
    parser = argparse.ArgumentParser(description="cryptboot Renode tests")
    parser.add_argument("--renode", default=None)
    parser.add_argument("--elf", default=None)
    parser.add_argument("--scenario", default="all",
                        choices=["jump", "error", "all"])
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args(argv)
    try:
        exe = find_renode(args.renode)
        elf = find_elf(args.elf)
    except SystemExit as exc:
        print(f"HARNESS ERROR: {exc}")
        return 2
    scenarios = ["jump", "error"] if "all" == args.scenario else [args.scenario]
    failed = 0
    for name in scenarios:
        ok, detail = run_one(exe, elf, name, args.timeout)
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")
        failed += not ok
    print(f"cryptboot renode: {len(scenarios) - failed}/{len(scenarios)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
