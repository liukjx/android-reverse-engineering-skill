#!/usr/bin/env python3
"""
从 Il2CppDumper 输出中过滤出 App 自有代码的符号表（给 Ghidra headless 用）。

用法:
  python filter_symbols.py <il2cpp-output目录> <out_prefix> [--assemblies "模式1,模式2"]
  例:
    python filter_symbols.py D:/tmp/dreamspace-re/il2cpp-output D:/tmp/dreamspace-re
    python filter_symbols.py ./il2cpp-output . --assemblies "Assembly-CSharp.dll,ATiStudios.*.dll"

--assemblies 支持 glob 模式（fnmatch），默认 Assembly-CSharp.dll。
App 自有代码可能分布在多个程序集（如 Mondly 的 39 个 ATiStudios.*.dll），
先用 ls DummyDll/ 查看清单再指定。排除名单兜底过滤引擎/SDK 前缀。

读取: <dir>/script.json (Il2CppDumper 产物)
      <dir>/DummyDll/*.dll (按 --assemblies 匹配的 App 自有程序集)
写出: <out_prefix>/symbols_map.txt      hex地址|Class$$Method
      <out_prefix>/game_types.txt       全部自有类型名
      <out_prefix>/game_methods.json    过滤后的方法条目
"""
import os, sys, json, fnmatch

DEFAULT_ASSEMBLIES = ["Assembly-CSharp.dll"]
ENGINE_PREFIXES = ("System", "Mono", "Microsoft", "Unity", "UnityEngine",
                   "TMPro", "Newtonsoft", "I18N", "netstandard", "mscorlib",
                   "Accessibility", "Il2CppDummyDll")

if len(sys.argv) < 3:
    sys.exit(__doc__)
outdir, prefix = sys.argv[1], sys.argv[2]
patterns = DEFAULT_ASSEMBLIES
if "--assemblies" in sys.argv:
    patterns = [p.strip() for p in sys.argv[sys.argv.index("--assemblies") + 1].split(",") if p.strip()]

# 1) game types from matched DummyDll assemblies (dnfile, no .net runtime needed)
import dnfile
dlls = sorted(d for d in os.listdir(os.path.join(outdir, "DummyDll"))
              if d.endswith(".dll")
              and any(fnmatch.fnmatch(d, p) for p in patterns)
              and not d.startswith(ENGINE_PREFIXES))
print(f"[+] matched assemblies ({len(dlls)}): {', '.join(dlls[:8])}{' ...' if len(dlls) > 8 else ''}")
types = set()
for asm in dlls:
    pe = dnfile.dnPE(os.path.join(outdir, "DummyDll", asm))
    for t in pe.net.mdtables.TypeDef:
        name = str(t.TypeName)
        if name == "<Module>":
            continue
        ns = str(t.TypeNamespace)
        types.add(ns + "." + name if ns else name)
print(f"[+] {len(types)} game types")

# 2) filter script.json
data = json.load(open(os.path.join(outdir, "script.json"), encoding="utf-8", errors="ignore"))
game = [m for m in data["ScriptMethod"]
        if m["Name"].split("$$", 1)[0].rsplit("/", 1)[-1] in types
        or m["Name"].split("$$", 1)[0] in types]
print(f"[+] {len(game)} game methods, {len({m['Address'] for m in game})} unique addresses")

os.makedirs(prefix, exist_ok=True) if not os.path.isdir(prefix) else None
with open(os.path.join(prefix, "symbols_map.txt"), "w", encoding="utf-8") as f:
    for m in game:
        f.write(f"{m['Address']:x}|{m['Name']}\n")
json.dump(game, open(os.path.join(prefix, "game_methods.json"), "w"))
open(os.path.join(prefix, "game_types.txt"), "w", encoding="utf-8").write("\n".join(sorted(types)))
print(f"[+] wrote symbols_map.txt / game_methods.json / game_types.txt under {prefix}")
