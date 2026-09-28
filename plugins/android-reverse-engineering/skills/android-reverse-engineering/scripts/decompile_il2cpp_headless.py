#!/usr/bin/env python3
"""
通用的 IL2CPP -> C 伪代码 命令行反编译工具 (Ghidra headless, 无需 GUI)

用法:
  set GHIDRA_INSTALL_DIR=D:/program/ghidra_12.1.3_PUBLIC
  set JAVA_HOME=D:/program/jdk-21.0.12.1
  pip install pyghidra && pyghidra --install-dir <GHIDRA_DIR>   (首次)
  python decompile_il2cpp_headless.py <libil2cpp.so> <symbols_map.txt> <out_dir> [project_name]

  symbols_map.txt 每行: <hex地址>|<Class$$Method名>   (由 filter_symbols.py 从 Il2CppDumper 的
                       script.json 按 App 自有类型过滤生成)

依赖:
  - JDK 21 (Ghidra 12 要求), JAVA_HOME 指向它
  - pyghidra (pip install pyghidra), 首次需 pyghidra --install-dir 指向 Ghidra 安装目录
  - Il2CppDumper (wklin8607 fork, 支持 metadata v39): dotnet Il2CppDumper.dll <so> <dat> <outdir>
"""
import os, sys, json, time, re

# ---- paths from env/args ----
GHIDRA_DIR = os.environ.get("GHIDRA_INSTALL_DIR")
JAVA_HOME  = os.environ.get("JAVA_HOME")
if not GHIDRA_DIR or not JAVA_HOME:
    sys.exit("ERROR: set GHIDRA_INSTALL_DIR and JAVA_HOME (JDK 21) first")
os.environ["GHIDRA_INSTALL_DIR"] = GHIDRA_DIR
os.environ["JAVA_HOME"] = JAVA_HOME

BINARY = sys.argv[1] if len(sys.argv) > 1 else "libil2cpp.so"
MAP    = sys.argv[2] if len(sys.argv) > 2 else "symbols_map.txt"
OUT    = sys.argv[3] if len(sys.argv) > 3 else "decompiled"
PROJ   = sys.argv[4] if len(sys.argv) > 4 else "il2cpp_re"
PROJ_DIR = os.path.join(os.path.dirname(os.path.abspath(OUT)), "ghidra_project")
os.makedirs(OUT, exist_ok=True)

import pyghidra
pyghidra.start()

syms = {}
for line in open(MAP, encoding="utf-8"):
    line = line.strip()
    if not line or "|" not in line:
        continue
    a, n = line.split("|", 1)
    syms.setdefault(int(a, 16), n)
print(f"[+] {len(syms)} target functions", flush=True)

t0 = time.time()
with pyghidra.open_program(os.path.abspath(BINARY), project_location=PROJ_DIR,
                           project_name=PROJ, analyze=False) as api:
    prog = api.getCurrentProgram()
    from ghidra.program.model.symbol import SourceType
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    base = prog.getImageBase()
    fm   = prog.getFunctionManager()
    mon  = ConsoleTaskMonitor()
    print(f"[+] image base = {base}", flush=True)

    # pass 1: create + name functions at Il2CppDumper addresses
    tx = prog.startTransaction("apply-il2cpp-symbols")
    ok = fail = 0
    funcs = {}
    try:
        for a, name in syms.items():
            addr = base.add(a)
            f = fm.getFunctionAt(addr)
            if f is None:
                f = api.createFunction(addr, name)
            if f is None:
                fail += 1
                continue
            try:
                f.setName(name, SourceType.USER_DEFINED)
            except Exception:
                pass
            funcs[a] = f
            ok += 1
    finally:
        prog.endTransaction(tx, True)
    print(f"[+] functions: created={ok} failed={fail} ({time.time()-t0:.0f}s)", flush=True)

    # pass 2: decompile each target, writing each class file as soon as
    # its last method is done (interrupt-safe, progress visible on disk)
    ifc = DecompInterface()
    ifc.openProgram(prog)
    by_class = {}
    remaining = {}
    for a, name in syms.items():
        cls = name.split("/")[0].split("$$")[0].replace("::", "_")
        remaining[cls] = remaining.get(cls, 0) + 1
    badch = re.compile(r'[<>:"/\\|?*]')
    good = bad = 0
    total = len(syms)

    def flush_class(cls):
        items = by_class.pop(cls, [])
        if not items:
            return
        fn = badch.sub("_", cls) or "_global"
        with open(os.path.join(OUT, fn + ".c"), "w", encoding="utf-8") as fh:
            fh.write(f"// class: {cls}\n// {len(items)} methods, Ghidra headless decompilation\n\n")
            for name, ep, code in items:
                fh.write(f"//==== {name} @ {ep} ====\n{code}\n\n")

    for i, (a, name) in enumerate(syms.items()):
        f = funcs.get(a)
        if f is None:
            continue
        cls = name.split("/")[0].split("$$")[0].replace("::", "_")
        try:
            res = ifc.decompileFunction(f, 120, mon)
            if res.decompileCompleted() and res.getDecompiledFunction() is not None:
                code = res.getDecompiledFunction().getC()
                by_class.setdefault(cls, []).append((name, f.getEntryPoint(), code))
                good += 1
            else:
                bad += 1
        except Exception:
            bad += 1
        remaining[cls] -= 1
        if remaining[cls] <= 0:
            flush_class(cls)
        if i % 500 == 0:
            print(f"    [{i}/{total}] ok={good} fail={bad} ({time.time()-t0:.0f}s)", flush=True)

    for cls in list(by_class.keys()):   # classes whose methods all failed
        flush_class(cls)

    print(f"[+] decompiled {good}, failed {bad} ({time.time()-t0:.0f}s)", flush=True)

    json.dump({"targets": total, "functions_created": ok, "decompiled": good,
               "failed": bad, "classes": len(remaining), "seconds": round(time.time()-t0)},
              open(os.path.join(OUT, "_stats.json"), "w"), indent=1)
    print(f"[done] {len(remaining)} classes -> {OUT}", flush=True)
