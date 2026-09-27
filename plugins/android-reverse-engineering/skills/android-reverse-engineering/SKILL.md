---
name: android-reverse-engineering
description: Decompile Android APK, XAPK, JAR, and AAR files using jadx or Fernflower/Vineflower. Reverse engineer Android apps, extract HTTP API endpoints (Retrofit, OkHttp, Volley), and trace call flows from UI to network layer. For Unity IL2CPP games, recover method bodies via Ghidra + Il2CppDumper (NOT Cpp2IL, whose IL-recovery is a known unimplemented stub). Use when the user wants to decompile, analyze, or reverse engineer Android packages, find API endpoints, or follow call flows. 中文触发词：反编译APK、安卓逆向、提取API、分析安卓应用、反编译安卓、逆向工程、追踪调用链、提取接口
trigger: decompile APK|decompile XAPK|reverse engineer Android|extract API|analyze Android|jadx|fernflower|vineflower|follow call flow|decompile JAR|decompile AAR|Android reverse engineering|find API endpoints|unity il2cpp|libil2cpp|reverse unity game|反编译APK|安卓逆向|提取API|分析安卓应用|逆向unity
---

# Android Reverse Engineering

Decompile Android APK/XAPK/JAR/AAR with jadx and Fernflower/Vineflower, trace call flows, and produce structured API documentation. Two decompiler engines: jadx for broad Android coverage and Fernflower for higher-quality Java on complex code. For Unity IL2CPP games, see the dedicated workflow below — this is a different problem and jadx alone is useless there.

## Prerequisites

- JDK 17+ (jadx / Fernflower)
- JDK 21+ (Ghidra — required for Unity IL2CPP body recovery)
- jadx, Ghidra 12+, Python 3 with capstone (pip install capstone)
- Il2CppDumper (auto-downloaded from wklin8607/Il2CppDumper if missing — that fork supports metadata v39)
- Cpp2IL — only used for structure (stub DLLs); it does NOT recover bodies (see warning)

All tool paths are resolved by the scripts via which / env vars, NOT hardcoded. Set JAVA_HOME explicitly per-phase because jadx wants JDK 17 and Ghidra wants JDK 21.

---

## Phase 0: Fingerprint the App

Run BEFORE anything else:

    APK="<path/to/app.apk>"
    SKILL_DIR="$(dirname "$(find ~/.dsh/skills/android-reverse-engineering -name fingerprint.sh | head -1)")"
    bash "$SKILL_DIR/fingerprint.sh" "$APK"

Key decision:
- has libil2cpp.so -> Unity IL2CPP -> jump to Phase U1 (Phases 1-5 below are useless for it)
- has Assembly-CSharp.dll (no libil2cpp) -> Unity Mono -> open with dnSpy / ICSharpCode.Decompiler directly
- neither -> standard Android app -> continue with Phase 1

---

## Standard Android App Workflow (Phases 1-5)

### Phase 1: Dependency check

    export JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$(which java)")")")"   # or point at JDK 17
    SKILL_DIR="$(dirname "$(find ~/.dsh/skills/android-reverse-engineering -name check-deps.sh | head -1)")"
    bash "$SKILL_DIR/check-deps.sh"

### Phase 2: jadx decompile

    SKILL_DIR="$(dirname "$(find ~/.dsh/skills/android-reverse-engineering -name decompile.sh | head -1)")"
    bash "$SKILL_DIR/decompile.sh" --engine jadx -o <output-dir> "$APK"

### Phase 3-5: structural analysis & API extraction
See the original SKILL.md sections (analyze AndroidManifest, BuildConfig, Retrofit annotations, etc.). The find-api-calls.sh script and api-extraction-patterns.md cover this.

---

## Unity IL2CPP Game Workflow (Phases U1-U8)

If Phase 0 finds libil2cpp.so, use this. It integrates the full toolchain and fixes the JAVA_HOME split (jadx=17, Ghidra=21).

### CRITICAL: How to actually get method bodies

There is a widely-repeated but WRONG assumption that Cpp2IL recovers C# bodies for modern Unity. It does not:

- Cpp2IL's --output-as dll_il_recovery is, per the author (SamboyCoding) in issues #223 / #528, an unimplemented stub — it emits throw null / empty bodies for every method. We verified this firsthand on a Unity 6000.4 / arm64 / metadata v39 build: dll_il_recovery, dll_throw_null, and diffable-cs all produced empty or stub bodies.
- Il2CppInspector's free release (2021.1) predates metadata v29+, so it cannot load a v39 binary either.
- Therefore the ONLY reliable route to real method bodies is Ghidra + Il2CppDumper. Everything else (Cpp2IL, Il2CppInspector) only gives you structure (class/field/method signatures, strings) — which is still very useful, just not bodies.

So: Phases U2-U3 give you structure; Phase U6 (Ghidra) gives you bodies. Do not waste time re-running Cpp2IL hoping for bodies.

### Phase U1: Extract key files

    APK="<path/to/app.apk>"
    WORK_DIR="<work-dir>"
    mkdir -p "$WORK_DIR/apk-extracted"
    unzip -o "$APK" "lib/arm64-v8a/libil2cpp.so" -d "$WORK_DIR/apk-extracted"
    unzip -o "$APK" "assets/bin/Data/Managed/Metadata/global-metadata.dat" -d "$WORK_DIR/apk-extracted"
    unzip -o "$APK" "assets/bin/Data/data.unity3d" -d "$WORK_DIR/apk-extracted" 2>/dev/null

### Phase U2: Il2CppDumper (structure: signatures, symbol table, strings)

    IL2CPP_DUMPER="$WORK_DIR/Il2CppDumper-v6.7.48/extracted/Il2CppDumper"
    if [ ! -f "$IL2CPP_DUMPER" ]; then
      gh release download --repo wklin8607/Il2CppDumper --pattern "*net8.0*" -D "$WORK_DIR/Il2CppDumper-v6.7.48"
      unzip -o "$WORK_DIR/Il2CppDumper-v6.7.48/"*net8.0.zip -d "$WORK_DIR/Il2CppDumper-v6.7.48/extracted"
    fi
    dotnet "$WORK_DIR/Il2CppDumper-v6.7.48/extracted/Il2CppDumper.dll"       "$WORK_DIR/apk-extracted/lib/arm64-v8a/libil2cpp.so"       "$WORK_DIR/apk-extracted/assets/bin/Data/Managed/Metadata/global-metadata.dat"       "$WORK_DIR/il2cpp-output"

Key outputs:
- dump.cs: all class/field/method definitions (structure)
- script.json: full symbol table: address -> Class$$Method (huge; pre-filter before use)
- stringliteral.json: all string constants
- il2cpp.h: C struct header (feed to Ghidra)
- DummyDll/: stub DLLs (browse structure in dnSpy/ILSpy)
- ghidra_with_struct.py, il2cpp_header_to_ghidra.py: Ghidra symbol-loading scripts (in the Il2CppDumper folder)

Note: this fork names the binary Il2CppDumper.dll (run via dotnet); Perfare's original ships Il2CppDumper.exe for Windows. Both work; the .dll + dotnet form is cross-platform.

### Phase U3: Pre-filter the symbol table (script.json is huge)

Only keep the app's own code + interesting SDK symbols:

    python3 << 'PYEOF'
    import json
    WORK_DIR = "<work-dir>"
    keywords = ["ATiStudios","Mondly","Chatbot","Grader","Speech","AI","Database",
                "OpenAI","Azure","Gemini","Whisper","Oculus","HandsFree","Vocabulary",
                "Lesson"]   # TUNE to the target app's namespaces/brand
    data = json.loads(open(f"{WORK_DIR}/il2cpp-output/script.json",encoding="utf-8",errors="ignore").read())
    filtered = {
        "ScriptMethod": [m for m in data["ScriptMethod"] if any(k in m["Name"] for k in keywords)],
        "Addresses": data["Addresses"],
    }
    json.dump(filtered, open(f"{WORK_DIR}/il2cpp-output/script_filtered.json","w"))
    with open(f"{WORK_DIR}/symbols_map.txt","w") as f:
        for m in data["ScriptMethod"]:
            f.write(f"{int(m['Address']):x}|{m['Name']}
")
    print("filtered methods:", len(filtered["ScriptMethod"]))
    PYEOF

### Phase U4: Cpp2IL — STRUCTURE ONLY (do not expect bodies)

    CPP2IL="$WORK_DIR/Cpp2IL/Cpp2IL-2022.1.0-pre-release.21"
    if [ ! -f "$CPP2IL" ]; then
      gh release download "2022.1.0-pre-release.21" --repo SamboyCoding/Cpp2IL         --pattern "*OSX-ARM64*" -D "$WORK_DIR/Cpp2IL"   # or *Windows.exe on Windows
    fi
    # On macOS the downloaded Mach-O may be killed by Gatekeeper; self-sign it:
    codesign --force --sign - "$CPP2IL" 2>/dev/null
    "$CPP2IL"       --force-binary-path "$WORK_DIR/apk-extracted/lib/arm64-v8a/libil2cpp.so"       --force-metadata-path "$WORK_DIR/apk-extracted/assets/bin/Data/Managed/Metadata/global-metadata.dat"       --force-unity-version "6000.4.0"       --output-as dll_default       --output-to "$WORK_DIR/cpp2il-output"

Use this only to get a browsable skeleton in your IDE. Bodies will be empty/throw null. If you need bodies, go to Phase U6.

macOS note: the prebuilt Cpp2IL Mach-O is unsigned and Gatekeeper silently kills it (Killed: 9 at ~32 KB RSS before .NET starts). codesign --force --sign - fixes it. Same applies to any downloaded raw Mach-O.

### Phase U5: ARM64 disassembly for specific functions (fast, no Ghidra)

For 3-5 key functions, objdump beats Ghidra startup. Resolve callee names against script.json and follow tail calls (IL2CPP stubs often b to the real body elsewhere):

    SO="$WORK_DIR/apk-extracted/lib/arm64-v8a/libil2cpp.so"
    objdump -d --start-address=0x<ADDR> --stop-address=0x<ADDR+0x300> "$SO"

Gotchas proven on this build:
- The address in dump.cs / script.json may be a tail-call stub (10 insns + b <far>). Disassemble the target to get the real body.
- Callee bl targets inside script.json resolve to real Class$$Method names; targets NOT in it are il2cpp runtime internals — label them as such, do not invent names.
- This gives you control flow you can annotate into pseudo-C# by hand (reliable for simple/medium methods; semantic-level for complex ones).

### Phase U6: Ghidra — the ONLY body-recovery path

Follow the Cpp2IL author's own guide (gist "Decompiling IL2CPP Games with Il2CppDumper and Ghidra"):

    export JAVA_HOME="<path/to/JDK-21>"          # Ghidra REQUIRES JDK 21
    export PATH="$JAVA_HOME/bin:$PATH"
    GHIDRA="$WORK_DIR/ghidra_12.x_PUBLIC"
    # 1. Import the binary (NO auto-analysis — it's slow on a 100MB+ .so)
    "$GHIDRA/support/analyzeHeadless" "$WORK_DIR/ghidra_project" "il2cpp_re"         -import "$WORK_DIR/apk-extracted/lib/arm64-v8a/libil2cpp.so" -noanalysis -overwrite
    # 2. In Ghidra GUI: File -> Parse C Code, load il2cpp_ghidra.h (from il2cpp_header_to_ghidra.py)
    # 3. Script Manager -> add Il2CppDumper folder -> run ghidra_with_struct.py (picks script.json)
    # 4. Let Ghidra analyze; open Functions window, search "ClassName$$Method"

Memory: Ghidra on a 100 MB+ libil2cpp.so wants 16 GB+ RAM. On 8 GB it will likely OOM mid-analysis. Mitigations:
- Set -Xmx high but under physical RAM (e.g. -Xmx6G on 8 GB).
- Decompile only the functions you care about (right-click -> Decompile), not the whole binary.
- Prefer a machine with >=16 GB for full analysis.

Output: real C-level decompilation of each Class$$Method — this is what Cpp2IL cannot give you.

### Phase U7: strings / constants (strongest signal)

    python3 -c "
    import json
    for it in json.load(open('<work-dir>/il2cpp-output/stringliteral.json')):
        v = it.get('value','')
        if 'http' in v or 'api' in v or 'key' in v or 'secret' in v:
            print(v[:200])
    "

### Phase U8: Unity assets (optional)

UnityPy / AssetRipper for textures, models, scenes, and serialized MonoBehaviour data.

---

## Java version cheat-sheet

| step | JAVA_HOME |
|------|-----------|
| jadx / Fernflower | JDK 17 |
| Ghidra import/analyze | JDK 21 |
| Il2CppDumper | none (dotnet) |
| Cpp2IL | none (dotnet, structure only) |

---

## Tool cache

| tool | cache path |
|------|-----------|
| Il2CppDumper (v39 fork) | $WORK_DIR/Il2CppDumper-v6.7.48/extracted/ |
| Cpp2IL | $WORK_DIR/Cpp2IL/ (structure only) |
| Ghidra | wherever you install it (12+) |

---

## Output

1. Structure — dump.cs (classes/fields/signatures), source/ skeleton from Cpp2IL
2. Bodies — Ghidra decompilation of target functions (the real logic)
3. ARM64 disasm — objdump of key functions with resolved callee names
4. Strings — URLs / keys / constants from stringliteral.json
5. Architecture summary — module deps + call chains
