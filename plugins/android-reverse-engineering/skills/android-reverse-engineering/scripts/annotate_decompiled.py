#!/usr/bin/env python3
"""
把 decompiled/*.c 里的 func_0xADDR 调用目标替换为真实的 Class$$Method 名。
地址换算: Ghidra地址 = imageBase(0x100000) + RVA, script.json 里的 Address 是 RVA。
用法: python annotate_decompiled.py <il2cpp-output/script.json> <decompiled目录>
"""
import os, sys, re, glob

script_json, outdir = sys.argv[1], sys.argv[2]
BASE = 0x100000

import json
data = json.load(open(script_json, encoding="utf-8", errors="ignore"))
name_by_rva = {}
for m in data["ScriptMethod"]:
    name_by_rva.setdefault(int(m["Address"]), m["Name"])
print(f"[+] {len(name_by_rva)} full symbols")

pat = re.compile(r'func_(0x[0-9a-f]{8,16})')
resolved = missed = 0
files = glob.glob(os.path.join(outdir, "*.c"))
for fp in files:
    src = open(fp, encoding="utf-8").read()
    def sub(mo):
        global resolved, missed
        ghidra = int(mo.group(1), 16)
        rva = ghidra - BASE
        nm = name_by_rva.get(rva)
        if nm is None:
            missed += 1
            return mo.group(0)          # keep func_0x... (il2cpp runtime internals etc.)
        resolved += 1
        return nm.replace("/", ".").replace("$$", "__").replace("::", "_")
    out = pat.sub(sub, src)
    if out != src:
        open(fp, "w", encoding="utf-8").write(out)

print(f"[+] resolved {resolved} call sites, left {missed} as func_0x (runtime internals)")
print(f"[+] annotated {len(files)} files")
