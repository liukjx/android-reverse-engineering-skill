#!/usr/bin/env python3
"""
Metadata 槽注解器（第三步，在 annotate_decompiled + annotate_fields 之后运行）。

把伪代码里的 metadata 用法槽还原成可读信息：
  - cRam/bRam/uRam/lRam/iRam/sRam000000000XXXXX、PTR_DAT_xxx、DAT_xxx、UNK_xxx
    -> /*"字符串字面值"*/ 或 /*类_TypeInfo*/ 或 /*&Class$$Method*/
  - guard 块里的裸绝对地址参数 func_0x..(0xfXXXXXX,1) -> 同样注解
数据源: Il2CppDumper script.json 的 ScriptString / ScriptMetadata / ScriptMetadataMethod。
地址换算: Ghidra 地址 = imageBase(默认 0x100000) + RVA（与 dump.cs RVA 同基）。

静态字段存储（.bss 静态区）无静态映射，保持原样——属正常。
用法: python annotate_metadata.py <script.json> <decompiled目录> [--base 0x100000]
"""
import os, sys, re, glob, json

script_json, outdir = sys.argv[1], sys.argv[2]
BASE = 0x100000
if "--base" in sys.argv:
    BASE = int(sys.argv[sys.argv.index("--base") + 1], 16)

data = json.load(open(script_json, encoding="utf-8", errors="ignore"))
meta = {int(e["Address"]) + BASE: e["Name"] for e in data.get("ScriptMetadata", [])}
meth = {int(e["Address"]) + BASE: e["Name"] for e in data.get("ScriptMetadataMethod", [])}
sstr = {int(e["Address"]) + BASE: e["Value"] for e in data.get("ScriptString", [])}
print(f"[+] tables: metadata={len(meta)} method={len(meth)} string={len(sstr)}")

def esc(s):
    return s[:56].replace("\\", "\\\\").replace("*/", "*_/").replace("\n", " ").replace("\r", "")

tok_re = re.compile(r'\b([a-z]{1,2}Ram|PTR_DAT_|DAT_|UNK_|PTR_)([0-9a-f]{6,16})\b(?!/\*)')
bare_re = re.compile(r'\(0x([0-9a-f]{7,16})\b(?!/\*)')   # (0xfXXXXXX 形式的调用参数（绝对地址）

def lookup(addr):
    if addr < 0x1000000:          # 小于 16MB 的视为普通偏移量，不注解
        return None
    if addr in sstr:
        return f'/*"{esc(sstr[addr])}"*/'
    if addr in meth:
        return f'/*&{esc(meth[addr].removeprefix("Method$"))}*/'
    if addr in meta:
        return f'/*{esc(meta[addr])}*/'
    return None

total = files_hit = 0
for fp in sorted(glob.glob(os.path.join(outdir, "*.c"))):
    src = open(fp, encoding="utf-8", errors="ignore").read()
    hits = [0]

    def sub_tok(mo):
        addr = int(mo.group(2), 16)
        c = lookup(addr)
        if c:
            hits[0] += 1
            return mo.group(0) + c
        return mo.group(0)

    def sub_bare(mo):
        addr = int(mo.group(1), 16)          # 0xfXXXXXX 已含 base（Ghidra 绝对地址）
        c = lookup(addr)
        if c:
            hits[0] += 1
            return f"(0x{mo.group(1)}" + c
        return mo.group(0)

    out = tok_re.sub(sub_tok, src)
    out = bare_re.sub(sub_bare, out)
    if hits[0]:
        open(fp, "w", encoding="utf-8").write(out)
        total += hits[0]
        files_hit += 1

print(f"[+] annotated {total} metadata slots across {files_hit} files")
