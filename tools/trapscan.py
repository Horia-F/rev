#!/usr/bin/env python3
import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple


@dataclass(frozen=True)
class Pattern:
    name: str
    bytes_: bytes
    default_patch: bytes  # same length as bytes_ (typically NOPs)


def nops(n: int) -> bytes:#!/usr/bin/env python3
import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple


@dataclass(frozen=True)
class Pattern:
    name: str
    bytes_: bytes
    default_patch: bytes  # same length as bytes_ (typically NOPs)


def nops(n: int) -> bytes:
    return b"\x90" * n


# Common “trap / confuse / debug-break” instruction encodings on x86/x86_64
PATTERNS: List[Pattern] = [
    Pattern("UD2", b"\x0f\x0b", nops(2)),          # illegal instruction
    Pattern("INT3", b"\xcc", nops(1)),             # breakpoint
    Pattern("ICEBP", b"\xf1", nops(1)),            # one-byte ICEBP
    Pattern("HLT", b"\xf4", nops(1)),              # halt (will SIGSEGV/SIGILL in usermode)
    Pattern("INT 1", b"\xcd\x01", nops(2)),        # trap-ish
    Pattern("INT 0x2D", b"\xcd\x2d", nops(2)),     # sometimes anti-debug
    # The following are not “anti-decompile” per se, but sometimes useful to spot:
    Pattern("SYSCALL", b"\x0f\x05", b"\x0f\x05"),  # keep unchanged by default
    Pattern("INT 0x80", b"\xcd\x80", b"\xcd\x80"), # keep unchanged by default
]

# Which ones we patch by default (safe-ish for deobfuscation)
DEFAULT_PATCH_SET = {"UD2", "INT3", "ICEBP", "HLT", "INT 1", "INT 0x2D"}


def find_all(data: bytes, needle: bytes) -> List[int]:
    out = []
    start = 0
    while True:
        i = data.find(needle, start)
        if i == -1:
            return out
        out.append(i)
        start = i + 1  # allow overlaps (rarely relevant here)


def scan(data: bytes, patterns: List[Pattern]) -> Dict[str, List[int]]:
    hits: Dict[str, List[int]] = {}
    for p in patterns:
        locs = find_all(data, p.bytes_)
        if locs:
            hits[p.name] = locs
    return hits


def hexdump_slice(data: bytes, off: int, size: int = 16) -> str:
    s = data[off:off + size]
    return " ".join(f"{b:02x}" for b in s)


def apply_patches(
    data: bytearray,
    patterns: List[Pattern],
    hits: Dict[str, List[int]],
    patch_set: set,
) -> Tuple[int, Dict[str, int]]:
    # Build quick lookup
    pat_by_name = {p.name: p for p in patterns}

    total = 0
    by_type: Dict[str, int] = {}

    # To avoid double-patching overlapping areas, patch longer patterns first
    # (UD2 etc. before 1-byte ones if they overlapped—rare but safer)
    order = sorted(
        [p for p in patterns if p.name in hits],
        key=lambda p: len(p.bytes_),
        reverse=True,
    )

    occupied = [False] * len(data)

    for p in order:
        if p.name not in patch_set:
            continue
        patch = p.default_patch
        if len(patch) != len(p.bytes_):
            raise ValueError(f"Patch length mismatch for {p.name}")

        for off in hits[p.name]:
            # Skip if any byte is already patched by a longer pattern
            if any(occupied[off:off + len(p.bytes_)]):
                continue
            # Apply
            data[off:off + len(p.bytes_)] = patch
            for j in range(off, off + len(p.bytes_)):
                occupied[j] = True
            total += 1
            by_type[p.name] = by_type.get(p.name, 0) + 1

    return total, by_type


def main():
    ap = argparse.ArgumentParser(
        description="Scan (and optionally patch) x86/x86_64 trap/obfuscation instruction bytes like UD2."
    )
    ap.add_argument("binary", help="Path to input binary")
    ap.add_argument("-n", "--max-per-type", type=int, default=30,
                    help="Max offsets to print per pattern (default: 30)")
    ap.add_argument("--context", type=int, default=12,
                    help="Bytes of context to show at each hit (default: 12)")
    ap.add_argument("--patch", action="store_true",
                    help="Write a patched copy (replacing common traps with NOPs)")
    ap.add_argument("-o", "--out", default=None,
                    help="Output path for patched binary (default: <input>.patched)")
    ap.add_argument("--patch-all", action="store_true",
                    help="Patch every pattern in the table (including SYSCALL/INT80) — usually NOT recommended")
    ap.add_argument("--only", default=None,
                    help="Comma-separated list of pattern names to patch (e.g. 'UD2,INT3')")
    args = ap.parse_args()

    in_path = Path(args.binary)
    if not in_path.exists():
        raise SystemExit(f"File not found: {in_path}")

    data = in_path.read_bytes()
    hits = scan(data, PATTERNS)

    if not hits:
        print("No known trap patterns found.")
        return

    # Summary
    print(f"[+] Scanned: {in_path} ({len(data)} bytes)\n")
    total_hits = 0
    for name in sorted(hits.keys()):
        c = len(hits[name])
        total_hits += c
        print(f"{name:10s}  count={c}")
    print(f"\nTotal hits across patterns: {total_hits}\n")

    # Details
    for name in sorted(hits.keys()):
        locs = hits[name]
        print(f"== {name} ({len(locs)} hits) ==")
        show = locs[:max(args.max_per_type, 0)]
        for off in show:
            start = max(0, off - args.context)
            end = min(len(data), off + len(next(p.bytes_ for p in PATTERNS if p.name == name)) + args.context)
            blob = data[start:end]
            marker_pos = off - start
            # Simple context line
            print(f"  off=0x{off:08x}  bytes@off={hexdump_slice(data, off, 8)}")
            # Show a tiny marked hexdump
            hexbytes = [f"{b:02x}" for b in blob]
            if 0 <= marker_pos < len(hexbytes):
                hexbytes[marker_pos] = f"[{hexbytes[marker_pos]}]"
            print("   ctx:", " ".join(hexbytes))
        if len(locs) > len(show):
            print(f"  ... ({len(locs) - len(show)} more not shown)")
        print()

    # Patching
    if args.patch:
        out_path = Path(args.out) if args.out else in_path.with_suffix(in_path.suffix + ".patched")

        if args.only:
            patch_set = {x.strip() for x in args.only.split(",") if x.strip()}
        elif args.patch_all:
            patch_set = {p.name for p in PATTERNS}
        else:
            patch_set = set(DEFAULT_PATCH_SET)

        buf = bytearray(data)
        patched_total, patched_by_type = apply_patches(buf, PATTERNS, hits, patch_set)

        out_path.write_bytes(buf)
        out_path.chmod(0o755)

        print(f"[+] Patched file written: {out_path}")
        print(f"    Patch set: {', '.join(sorted(patch_set))}")
        print(f"    Patched occurrences: {patched_total}")
        for k in sorted(patched_by_type):
            print(f"      {k:10s}  patched={patched_by_type[k]}")


if __name__ == "__main__":
    main()

    return b"\x90" * n


# Common “trap / confuse / debug-break” instruction encodings on x86/x86_64
PATTERNS: List[Pattern] = [
    Pattern("UD2", b"\x0f\x0b", nops(2)),          # illegal instruction
    Pattern("INT3", b"\xcc", nops(1)),             # breakpoint
    Pattern("ICEBP", b"\xf1", nops(1)),            # one-byte ICEBP
    Pattern("HLT", b"\xf4", nops(1)),              # halt (will SIGSEGV/SIGILL in usermode)
    Pattern("INT 1", b"\xcd\x01", nops(2)),        # trap-ish
    Pattern("INT 0x2D", b"\xcd\x2d", nops(2)),     # sometimes anti-debug
    # The following are not “anti-decompile” per se, but sometimes useful to spot:
    Pattern("SYSCALL", b"\x0f\x05", b"\x0f\x05"),  # keep unchanged by default
    Pattern("INT 0x80", b"\xcd\x80", b"\xcd\x80"), # keep unchanged by default
]

# Which ones we patch by default (safe-ish for deobfuscation)
DEFAULT_PATCH_SET = {"UD2", "INT3", "ICEBP", "HLT", "INT 1", "INT 0x2D"}


def find_all(data: bytes, needle: bytes) -> List[int]:
    out = []
    start = 0
    while True:
        i = data.find(needle, start)
        if i == -1:
            return out
        out.append(i)
        start = i + 1  # allow overlaps (rarely relevant here)


def scan(data: bytes, patterns: List[Pattern]) -> Dict[str, List[int]]:
    hits: Dict[str, List[int]] = {}
    for p in patterns:
        locs = find_all(data, p.bytes_)
        if locs:
            hits[p.name] = locs
    return hits


def hexdump_slice(data: bytes, off: int, size: int = 16) -> str:
    s = data[off:off + size]
    return " ".join(f"{b:02x}" for b in s)


def apply_patches(
    data: bytearray,
    patterns: List[Pattern],
    hits: Dict[str, List[int]],
    patch_set: set,
) -> Tuple[int, Dict[str, int]]:
    # Build quick lookup
    pat_by_name = {p.name: p for p in patterns}

    total = 0
    by_type: Dict[str, int] = {}

    # To avoid double-patching overlapping areas, patch longer patterns first
    # (UD2 etc. before 1-byte ones if they overlapped—rare but safer)
    order = sorted(
        [p for p in patterns if p.name in hits],
        key=lambda p: len(p.bytes_),
        reverse=True,
    )

    occupied = [False] * len(data)

    for p in order:
        if p.name not in patch_set:
            continue
        patch = p.default_patch
        if len(patch) != len(p.bytes_):
            raise ValueError(f"Patch length mismatch for {p.name}")

        for off in hits[p.name]:
            # Skip if any byte is already patched by a longer pattern
            if any(occupied[off:off + len(p.bytes_)]):
                continue
            # Apply
            data[off:off + len(p.bytes_)] = patch
            for j in range(off, off + len(p.bytes_)):
                occupied[j] = True
            total += 1
            by_type[p.name] = by_type.get(p.name, 0) + 1

    return total, by_type


def main():
    ap = argparse.ArgumentParser(
        description="Scan (and optionally patch) x86/x86_64 trap/obfuscation instruction bytes like UD2."
    )
    ap.add_argument("binary", help="Path to input binary")
    ap.add_argument("-n", "--max-per-type", type=int, default=30,
                    help="Max offsets to print per pattern (default: 30)")
    ap.add_argument("--context", type=int, default=12,
                    help="Bytes of context to show at each hit (default: 12)")
    ap.add_argument("--patch", action="store_true",
                    help="Write a patched copy (replacing common traps with NOPs)")
    ap.add_argument("-o", "--out", default=None,
                    help="Output path for patched binary (default: <input>.patched)")
    ap.add_argument("--patch-all", action="store_true",
                    help="Patch every pattern in the table (including SYSCALL/INT80) — usually NOT recommended")
    ap.add_argument("--only", default=None,
                    help="Comma-separated list of pattern names to patch (e.g. 'UD2,INT3')")
    args = ap.parse_args()

    in_path = Path(args.binary)
    if not in_path.exists():
        raise SystemExit(f"File not found: {in_path}")

    data = in_path.read_bytes()
    hits = scan(data, PATTERNS)

    if not hits:
        print("No known trap patterns found.")
        return

    # Summary
    print(f"[+] Scanned: {in_path} ({len(data)} bytes)\n")
    total_hits = 0
    for name in sorted(hits.keys()):
        c = len(hits[name])
        total_hits += c
        print(f"{name:10s}  count={c}")
    print(f"\nTotal hits across patterns: {total_hits}\n")

    # Details
    for name in sorted(hits.keys()):
        locs = hits[name]
        print(f"== {name} ({len(locs)} hits) ==")
        show = locs[:max(args.max_per_type, 0)]
        for off in show:
            start = max(0, off - args.context)
            end = min(len(data), off + len(next(p.bytes_ for p in PATTERNS if p.name == name)) + args.context)
            blob = data[start:end]
            marker_pos = off - start
            # Simple context line
            print(f"  off=0x{off:08x}  bytes@off={hexdump_slice(data, off, 8)}")
            # Show a tiny marked hexdump
            hexbytes = [f"{b:02x}" for b in blob]
            if 0 <= marker_pos < len(hexbytes):
                hexbytes[marker_pos] = f"[{hexbytes[marker_pos]}]"
            print("   ctx:", " ".join(hexbytes))
        if len(locs) > len(show):
            print(f"  ... ({len(locs) - len(show)} more not shown)")
        print()

    # Patching
    if args.patch:
        out_path = Path(args.out) if args.out else in_path.with_suffix(in_path.suffix + ".patched")

        if args.only:
            patch_set = {x.strip() for x in args.only.split(",") if x.strip()}
        elif args.patch_all:
            patch_set = {p.name for p in PATTERNS}
        else:
            patch_set = set(DEFAULT_PATCH_SET)

        buf = bytearray(data)
        patched_total, patched_by_type = apply_patches(buf, PATTERNS, hits, patch_set)

        out_path.write_bytes(buf)
        out_path.chmod(0o755)

        print(f"[+] Patched file written: {out_path}")
        print(f"    Patch set: {', '.join(sorted(patch_set))}")
        print(f"    Patched occurrences: {patched_total}")
        for k in sorted(patched_by_type):
            print(f"      {k:10s}  patched={patched_by_type[k]}")


if __name__ == "__main__":
    main()
