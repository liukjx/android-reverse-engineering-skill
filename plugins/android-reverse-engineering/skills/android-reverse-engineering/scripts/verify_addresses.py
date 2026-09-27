#!/usr/bin/env python3
"""
Sanity-check Il2CppDumper addresses BEFORE a long Ghidra run (10 seconds).
Samples N addresses from symbols_map.txt, converts VMA->file offset via the
ELF program headers (handles the common RX-segment skew, e.g. +0x4000, which
also breaks binutils objdump on such .so files), and disassembles with capstone.

A real function should start with a prologue (stp/str/sub sp/pacibsp/mov x29).
A first insn of `b <far>` is an IL2CPP tail-call stub — fine, Ghidra follows it.
Anything else (or undecodable bytes) means the address map and the .so disagree.

Usage: python verify_addresses.py <libil2cpp.so> <symbols_map.txt> [sample_count=6]
"""
import sys, struct, random

try:
    import capstone
except ImportError:
    sys.exit("pip install capstone")

SO, MAP = sys.argv[1], sys.argv[2]
N = int(sys.argv[3]) if len(sys.argv) > 3 else 6

data = open(SO, "rb").read()

# parse ELF64 program headers -> (vaddr, filesz, offset, flags) per PT_LOAD
e_phoff, = struct.unpack_from("<Q", data, 0x20)
e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
loads = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type, p_flags = struct.unpack_from("<II", data, off)
    p_offset, p_vaddr, _, p_filesz, _ = struct.unpack_from("<QQQQQ", data, off + 8)[0:5]
    if p_type == 1 and p_filesz > 0:
        loads.append((p_vaddr, p_filesz, p_offset, p_flags))

def v2f(vma):
    for vaddr, filesz, offset, _ in loads:
        if vaddr <= vma < vaddr + filesz:
            return vma - vaddr + offset
    return None

rows = []
for line in open(MAP, encoding="utf-8"):
    line = line.strip()
    if "|" in line:
        a, n = line.split("|", 1)
        rows.append((int(a, 16), n))

random.seed(42)   # deterministic sampling
for vma, name in random.sample(rows, min(N, len(rows))):
    off = v2f(vma)
    print(f"--- {name} @ vma {vma:x} (file offset {off if off is not None else 'NOT MAPPED'}) ---")
    if off is None:
        print("  !! address not inside any PT_LOAD — symbol map and .so do not match")
        continue
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    insns = list(md.disasm(data[off:off + 64], vma))[:8]
    if not insns:
        print("  !! undecodable bytes")
        continue
    for ins in insns:
        print(f"  {ins.address:x}: {ins.mnemonic} {ins.op_str}")
    first = insns[0].mnemonic
    if first in ("b", "br", "bx"):
        print("  [ok] tail-call stub — Ghidra follows it to the real body")
    elif first in ("stp", "str", "sub", "pacibsp", "mov", "stur"):
        print("  [ok] standard prologue")
    else:
        print("  [??] unusual first insn — inspect manually")
