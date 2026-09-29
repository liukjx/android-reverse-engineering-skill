#!/usr/bin/env python3
"""
第四步注解：类型传播 + il2pp 运行时惯用语识别（在 annotate_metadata 之后运行）。

1. 全局助手识别（先扫全库，按调用形状定助手地址，再统一标注）:
   - func_0xX(1,1, V + 0xe0/0xe4)   -> /*il2cpp-class-init*/（类初始化助手）
   - func_0xX(1L << ((ulong)...)    -> /*gc-write-barrier*/（GC 写屏障）
2. 变量类型传播（保守）:
   - param_1 = this（实例方法）；param_2..N 按 dump.cs 方法签名形参类型
   - 变量来自 /*X_TypeInfo*/ 槽读取    -> Il2CppClass 指针（+0xe4 = cctor 标志）
   - 变量来自已注解字段读取 / 已知类方法返回值 -> 字段/返回值声明类型
   - 仅对"单一赋值"局部变量做字段注解；TypeInfo 变量的 0xe4 检查按最后赋值识别
用法: python annotate_types.py <dump.cs> <decompiled目录>
"""
import os, sys, re, glob

DUMP, OUTDIR = sys.argv[1], sys.argv[2]

cls_re   = re.compile(r'^\s*(?:\[[^\]]*\]\s*)*(?:(?:public|private|internal|protected|sealed|abstract|static|new)\s+)*(class|struct|interface|enum)\s+([\w.@<>]+)\s*(?::\s*([\w.@<>]+))?')
field_re = re.compile(r'^\s*.*?;\s*//\s*(?:0x)?([0-9A-Fa-f]+)\s*$')
hdr_re   = re.compile(r'^//====\s+([\w.@<>/]+)\$\$([\w.<>+]+)\s+@\s+([0-9a-f]+)')

classes = {}
cur = None
for line in open(DUMP, encoding="utf-8", errors="ignore"):
    m = cls_re.match(line)
    if m:
        cur = m.group(2)
        classes[cur] = {"base": m.group(3), "fields": {}, "static_methods": set(), "methods": {}}
        continue
    if cur is None:
        continue
    fm = field_re.match(line)
    if fm and "(" not in line and " static " not in f" {line.strip()} " and not line.strip().startswith("const"):
        off = int(fm.group(1), 16)
        if off > 0:
            decl = line.strip().rsplit(";", 1)[0]
            parts = decl.split()
            classes[cur]["fields"].setdefault(off, (parts[-1], " ".join(parts[:-1])))
        continue
    if "(" in line and ")" in line and "; // 0x" not in line:
        is_static = " static " in f" {line} "
        pre = line.split("(", 1)[0]
        mm = re.search(r'([\w.<>]+)\s*$', pre)
        if mm:
            mname = mm.group(1)
            ret = pre[:mm.start()].split()[-1] if mm.start() > 0 else "void"
            args = line[line.find("(")+1:line.rfind(")")]
            depth, out, buf = 0, [], ""
            for ch in args:
                if ch == "<": depth += 1
                if ch == ">": depth -= 1
                if ch == "," and depth == 0:
                    out.append(buf); buf = ""
                else: buf += ch
            if buf.strip(): out.append(buf)
            atypes = []
            for a in out:
                a = a.strip().replace("ref ", "").replace("out ", "").replace("in ", "")
                atypes.append(a.rsplit(" ", 1)[0] if " " in a.strip() else a.strip())
            classes[cur]["methods"].setdefault(mname, []).append((ret, atypes))
            if is_static:
                classes[cur]["static_methods"].add(mname)

by_full = dict(classes)
def resolve_type(t):
    if not t: return None
    t = t.strip()
    if t.endswith("[]") or "<" in t or t in ("string","int","uint","long","ulong","float","double","bool","byte","sbyte","short","ushort","char","object","void"):
        return None
    return t if t in by_full else next((c for c in by_full if c.endswith("." + t)), None)

def field_map_for(name):
    out, seen, chain = {}, set(), [name]
    while chain:
        c = chain.pop(0)
        if c not in by_full or c in seen: continue
        seen.add(c)
        for off, (fn, ft) in by_full[c]["fields"].items():
            out.setdefault(off, (c.split(".")[-1] + "." + fn, ft))
        b = by_full[c]["base"]
        if b: chain.append(b if b in by_full else next((x for x in by_full if x.endswith("." + b)), None))
    return out

files_texts = {fp: open(fp, encoding="utf-8", errors="ignore").read()
               for fp in sorted(glob.glob(os.path.join(OUTDIR, "*.c")))}

# ---- 全局助手地址识别 ----
init_helpers, wb_helpers = set(), set()
for src in files_texts.values():
    init_helpers.update(re.findall(r'func_(0x[0-9a-f]+)\(1,1,\w+ \+ 0xe[04]\)', src))
    wb_helpers.update(re.findall(r'func_(0x[0-9a-f]+)\(1L << \(\(ulong\)', src))
print(f"[+] helpers: class-init={len(init_helpers)} write-barrier={len(wb_helpers)}")

tok_off   = re.compile(r'\((\w+) \+ (0x[0-9a-f]+)\)(?!/\*)')
assign_re = re.compile(r'^\s*(\w+)\s*=\s*(.+?);?$')
call_re   = re.compile(r'([\w.]+)__([\w<>]+)\(')
helper_re = re.compile(r'func_(0x[0-9a-f]+)\((?!/\*)')

total = files_hit = 0
for fp, src in files_texts.items():
    raw = os.path.basename(fp)[:-2]
    cls_name = raw if raw in classes else raw.rsplit(".", 1)[-1]
    if cls_name not in classes:
        continue
    lines = src.split("\n")
    out_lines, hits = [], 0
    cur_m = None
    kinds, asg = {}, {}
    for line in lines:
        hm = hdr_re.match(line)
        if hm:
            cur_m = hm.group(2); kinds, asg = {}, {}
        if cur_m is not None:
            am = assign_re.match(line)
            if am and not line.lstrip().startswith("//"):
                var, rhs = am.group(1), am.group(2)
                if "_TypeInfo*/" in rhs:
                    kinds[var] = "__CLASS__"
                else:
                    cm = call_re.search(rhs)
                    if cm:
                        cn = cm.group(1)
                        cn = cn if cn in by_full else next((x for x in by_full if x.endswith("." + cn)), None)
                        if cn and cn in classes:
                            for ret, _ in classes[cn]["methods"].get(cm.group(2).split("(")[0], []):
                                rt = resolve_type(ret)
                                if rt: kinds[var] = rt
                                break
                    else:
                        src_var = re.search(r'\((\w+) \+ (0x[0-9a-f]+)\)', rhs)
                        if src_var and src_var.group(1) in kinds:
                            t = kinds[src_var.group(1)]
                            if t != "__CLASS__":
                                ent = field_map_for(t).get(int(src_var.group(2), 16))
                                if ent:
                                    rt = resolve_type(ent[1])
                                    if rt: kinds[var] = rt

            def annotate(mo):
                global total, hits
                var, off = mo.group(1), int(mo.group(2), 16)
                t = kinds.get(var)
                if t == "__CLASS__":
                    if off in (0xe0, 0xe4):
                        hits += 1; total += 1
                        return f"{mo.group(0)}/*class-init-flag*/"
                    return mo.group(0)
                if var == "param_1" or asg.get(var, 0) != 1 or not t:
                    return mo.group(0)
                ent = field_map_for(t).get(off)
                if ent:
                    hits += 1; total += 1
                    return f"{mo.group(0)}/*{ent[0]}*/"
                return mo.group(0)

            new = tok_off.sub(annotate, line)

            def tag_helper(mo):
                global total, hits
                a = mo.group(1)
                if a in init_helpers:
                    hits += 1; total += 1
                    return f"func_{a}/*il2cpp-class-init*/("
                if a in wb_helpers:
                    hits += 1; total += 1
                    return f"func_{a}/*gc-write-barrier*/("
                return mo.group(0)
            new = helper_re.sub(tag_helper, new)
            out_lines.append(new)
        else:
            out_lines.append(line)
    src2 = "\n".join(out_lines)
    if src2 != src:
        open(fp, "w", encoding="utf-8").write(src2)
        files_hit += 1

print(f"[+] pass4: {total} type/idiom annotations across {files_hit} files")
