#!/usr/bin/env python3
"""Headless Ghidra decompilation of UE4/UE5 game methods (pyghidra, no GUI).

Unlike the Unity IL2CPP path (decompile_il2cpp_headless.py), UE4 needs NO address
recovery step: when the engine .so is unstripped, .dynsym already supplies an address
per method, so symbols_map.txt (hex-address|Class$$mangled, from extract_ue4_symbols.py)
can be fed straight in.

Usage:
    export GHIDRA_INSTALL_DIR="<ghidra_12.x_PUBLIC>"
    export JAVA_HOME="<JDK-21>"          # Ghidra REQUIRES JDK 21
    # one-time:  pyghidra --install-dir "$GHIDRA_INSTALL_DIR"
    python3 decompile_ue4_headless.py <libUE4.so> <symbols_map.txt> <out-dir> <project-name>

Writes one .c per class into <out-dir>, each containing every decompiled method body.
Verified on a 110 MB libUE4.so / 295k dynsym / 7.7k app methods:
    7114 methods decompiled, 0 failures, 234 class files, ~5 min.

Why the output is better than the Unity path: Ghidra reads the ELF symbol table, so the
bodies already carry demangled UE4 names (_ZN18UTRProgressionData18SetChallengeStatus...).
The annotate_decompiled.py / annotate_fields.py / annotate_metadata.py passes are
unnecessary here.
"""
from __future__ import annotations

import collections
import os
import sys
import time


def main():
    if len(sys.argv) < 5:
        print(__doc__)
        return 1
    so_path, smap_path, out_dir, proj_name = sys.argv[1:5]

    os.environ.setdefault("GHIDRA_INSTALL_DIR", os.environ.get("GHIDRA_INSTALL_DIR", ""))
    import pyghidra
    pyghidra.start()                     # pyghidra 3.x takes NO vm_args parameter

    from ghidra.base.project import GhidraProject
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.model.symbol import SourceType
    from ghidra.util.task import ConsoleTaskMonitor
    from java.io import File

    os.makedirs(out_dir, exist_ok=True)
    proj_dir = os.path.join(out_dir, "_ghidra_proj")
    os.makedirs(proj_dir, exist_ok=True)

    entries = []
    with open(smap_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or "|" not in line:
                continue
            addr, name = line.split("|", 1)
            try:
                entries.append((int(addr, 16), name))
            except ValueError:
                pass
    if not entries:
        print("ERROR: symbols_map.txt is empty", file=sys.stderr)
        return 1
    print("symbols: %d" % len(entries), flush=True)

    proj = GhidraProject.createProject(proj_dir, proj_name, False)
    # NOTE: GhidraProject.importProgram(File) -- the (File, bool) overload does not exist.
    prog = proj.importProgram(File(so_path))
    base = prog.getImageBase().getOffset()
    print("imported: %s  imageBase: 0x%x" % (prog.getName(), base), flush=True)

    fm = prog.getFunctionManager()
    af = prog.getAddressFactory()
    space = af.getDefaultAddressSpace()
    dec = DecompInterface()
    dec.openProgram(prog)
    monitor = ConsoleTaskMonitor()

    ok = fail = created = 0
    by_class = collections.defaultdict(list)
    t0 = time.time()
    for i, (rva, name) in enumerate(entries):
        addr = space.getAddress(base + rva)   # dynsym values are RVAs
        func = fm.getFunctionAt(addr)
        if func is None:
            try:
                func = fm.createFunction(None, addr, None, SourceType.USER_DEFINED)
                if func is not None:
                    created += 1
            except Exception:
                func = None
        if func is None:
            fail += 1
            continue
        try:
            res = dec.decompileFunction(func, 90, monitor)
            if res is not None and res.decompileCompleted():
                cls, _, mangled = name.partition("$")
                body = res.getDecompiledFunction().getC()
                by_class[cls].append("/* " + mangled + " */\n" + body)
                ok += 1
            else:
                fail += 1
        except Exception:
            fail += 1
        if (i + 1) % 200 == 0:
            print("  %d/%d ok=%d fail=%d created=%d elapsed=%.0fs"
                  % (i + 1, len(entries), ok, fail, created, time.time() - t0), flush=True)

    for cls, bodies in by_class.items():
        path = os.path.join(out_dir, cls + ".c")
        with open(path, "w", encoding="utf-8", errors="replace") as fh:
            fh.write("\n\n".join(bodies))

    print("DONE ok=%d fail=%d created=%d classes=%d" % (ok, fail, created, len(by_class)),
          flush=True)
    dec.dispose()
    proj.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())