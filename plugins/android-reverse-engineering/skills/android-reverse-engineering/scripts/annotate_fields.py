#!/usr/bin/env python3
"""
把反编译 .c 里的对象字段偏移注解成字段名：*(long*)(param_1 + 0x50) -> /*Cls.field*/
数据源: Il2CppDumper dump.cs（每类字段 // 0xNN 偏移 + class A : B 继承链）。

规则:
- IL2CPP 实例方法第一个参数是 this (param_1)；静态方法没有 this，跳过其块。
- 每个方法块以 "//==== Class$$Method @ addr ====" 分隔。
- 字段映射 = 本类字段 + 沿 base 链上溯的全部实例字段（offset > 0），外加 0x0=klass, 0x8=monitor。
- 只做保守注解：偏移命中才追加 /*Cls.field*/ 注释，绝不改写表达式本身。

用法: python annotate_fields.py <dump.cs> <decompiled目录>
在 annotate_decompiled.py 之后运行。
"""
import os, sys, re, glob

DUMP, OUTDIR = sys.argv[1], sys.argv[2]

cls_re   = re.compile(r'^\s*(?:\[[^\]]*\]\s*)*((?:public|private|internal|protected|sealed|abstract|static|new)\s+)*(class|struct|interface|enum)\s+([\w.@<>]+)\s*(?::\s*([\w.@<>]+))?')
field_re = re.compile(r'^\s*.*?;\s*//\s*(?:0x)?([0-9A-Fa-f]+)\s*$')
meth_re  = re.compile(r'^\s*(?:\[[^\]]*\]\s*)*(?:public|private|protected|internal|static|virtual|override|abstract|sealed|extern|unsafe|new|async|explicit|implicit|operator|\s)*[\w.<>,\[\] ()]*?([\w.@<>]+)\s*\(')

classes = {}   # name -> {'base': str|None, 'fields': {int: name}, 'static_methods': set()}
cur = None
cur_bases = set()

print("[*] parsing dump.cs ...", flush=True)
for line in open(DUMP, encoding="utf-8", errors="ignore"):
    m = cls_re.match(line)
    if m:
        cur = m.group(3)
        cur_bases.add(cur)
        classes[cur] = {"base": m.group(4) if m.group(4) and m.group(4) not in ("object",) else None,
                        "fields": {}, "static_methods": set()}
        continue
    if cur is None:
        continue
    fm = field_re.match(line)
    if fm and "(" not in line and " static " not in f" {line.strip()} " and not line.strip().startswith("const"):
        off = int(fm.group(1), 16)
        if off > 0:
            fname = line.strip().rsplit(";", 1)[0].split()[-1]
            if fname not in ("get", "set"):
                classes[cur]["fields"].setdefault(off, fname)
        continue
    if "(" in line and (" static " in f" {line} " or line.strip().startswith("public static") or line.strip().startswith("private static")
                        or line.strip().startswith("internal static") or line.strip().startswith("protected static")):
        mm = meth_re.match(line)
        if mm:
            classes[cur]["static_methods"].add(mm.group(1))
print(f"[+] {len(classes)} classes parsed", flush=True)

def field_map_for(name):
    """offset -> 'Cls.field'，沿继承链上溯，子类优先。"""
    out, seen = {}, set()
    chain = [name]
    while chain:
        c = chain.pop(0)
        if c in seen or c not in classes:
            continue
        seen.add(c)
        for off, fn in classes[c]["fields"].items():
            out.setdefault(off, f"{c.split('.')[-1]}.{fn}")
        b = classes[c]["base"]
        if b:
            chain.append(b if b in classes else (b.split(".")[-1] if b.split(".")[-1] in classes else b))
    return out

hdr_re   = re.compile(r"^//====\s+([\w.@<>/]+)\$\$([\w.<>+]+)")
acc_re   = re.compile(r"(param_1\s*\+\s*(0x[0-9A-Fa-f]+))\b")
klass_map = {0x0: "Il2CppObject.klass", 0x8: "Il2CppObject.monitor"}

total_files = total_hits = 0
for fp in sorted(glob.glob(os.path.join(OUTDIR, "*.c"))):
    cls_name = os.path.basename(fp)[:-2]
    if cls_name not in classes:
        continue
    fmap = field_map_for(cls_name)
    if not fmap:
        continue
    out_lines, hits = [], 0
    current_method_static = False
    for line in open(fp, encoding="utf-8"):
        hm = hdr_re.match(line)
        if hm:
            current_method_static = hm.group(1).rsplit(".", 1)[-1] in classes.get(cls_name, {}).get("static_methods", set())
        if not current_method_static:
            def sub(mo):
                off = int(mo.group(2), 16)
                label = fmap.get(off) or klass_map.get(off)
                if label:
                    return f"{mo.group(1)} /*this.{label}*/"
                return mo.group(0)
            new = acc_re.sub(sub, line)
            hits += new.count("/*this.")
            out_lines.append(new)
        else:
            out_lines.append(line)
    if hits:
        open(fp, "w", encoding="utf-8").write("".join(out_lines))
        total_files += 1
        total_hits += hits

print(f"[+] annotated {total_hits} field accesses across {total_files} files")
