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

# ---------------- pass 2: .bss 槽归属推断（交叉引用 + 守卫模式） ----------------
# 未被元数据表覆盖的 Ram 槽 = .bss 运行时存储：类初始化标志 / 静态字段 / 运行时全局。
# 元数据无映射，但可通过引用推断：
#   - 单类引用 + 守卫模式（(X & 1) == 0 ... X = 1）  -> /*<类>.init-flag*/
#   - 单类引用 + 其他用法                            -> /*<类>.static*/
#   - 大量文件引用（>20）                            -> /*il2cpp-runtime-global*/
#   - 少量文件引用                                   -> /*shared: <类A|类B>*/
GUARD_RE = re.compile(r'\((?:[a-z]{1,2}Ram|PTR_DAT_)([0-9a-f]{6,16})\s*&\s*1\)\s*==\s*0')
FLG_RE  = re.compile(r'\b[a-z]{1,2}Ram([0-9a-f]{6,16})\s*=\s*(?:1|\'\\x01\'|\'\\0*1\')')
TOK2_RE = re.compile(r'\b([a-z]{1,2}Ram|PTR_DAT_)([0-9a-f]{6,16})\b(?!/\*)')

owner = {}   # addr -> {"files": [类名...], "guard": bool}
for fp in sorted(glob.glob(os.path.join(outdir, "*.c"))):
    cls = os.path.basename(fp)[:-2].rsplit(".", 1)[-1]
    src = open(fp, encoding="utf-8", errors="ignore").read()
    for mo in GUARD_RE.finditer(src):
        owner.setdefault(int(mo.group(1), 16), {"files": [], "guard": False})["guard"] = True
    for mo in FLG_RE.finditer(src):
        owner.setdefault(int(mo.group(1), 16), {"files": [], "guard": False})["guard"] = True
    for mo in TOK2_RE.finditer(src):
        owner.setdefault(int(mo.group(2), 16), {"files": [], "guard": False})["files"].append(cls)

t2 = f2 = 0
for fp in sorted(glob.glob(os.path.join(outdir, "*.c"))):
    cls = os.path.basename(fp)[:-2].rsplit(".", 1)[-1]
    src = open(fp, encoding="utf-8", errors="ignore").read()

    def sub2(mo):
        global t2, f2
        addr = int(mo.group(2), 16)
        info = owner.get(addr)
        if not info:
            return mo.group(0)
        files = sorted(set(info["files"]))
        if len(files) > 20:
            label = "il2cpp-runtime-global"
        elif len(files) == 1:
            label = f"{files[0]}.{'init-flag' if info['guard'] else 'static'}"
        else:
            label = f"shared-{'init-flag' if info['guard'] else 'static'}:{'|'.join(files[:4])}"
        t2 += 1
        return f"{mo.group(0)}/*{label}*/"

    out = TOK2_RE.sub(sub2, src)
    if out != src:
        open(fp, "w", encoding="utf-8").write(out)
        f2 += 1
print(f"[+] pass2: {t2} .bss slots tagged across {f2} files")
