---
name: android-reverse-engineering
description: Decompile Android APK, XAPK, JAR, and AAR files using jadx or Fernflower/Vineflower. Reverse engineer Android apps, extract HTTP API endpoints (Retrofit, OkHttp, Volley), and trace call flows from UI to network layer. For Unity IL2CPP games, recover method bodies via headless Ghidra (pyghidra) + Il2CppDumper — full command-line pipeline, no GUI needed — and extract Unity assets (scene hierarchy, prefab structure, serialized component values, textures, meshes, animations, audio) via UnityPy + AssetStudioMod (NOT Cpp2IL, whose IL-recovery is a known unimplemented stub). Use when the user wants to decompile, analyze, or reverse engineer Android packages, find API endpoints, follow call flows, or extract game assets. 中文触发词：反编译APK、安卓逆向、提取API、分析安卓应用、反编译安卓、逆向工程、追踪调用链、提取接口、命令行反编译、无GUI反编译、提取贴图、提取模型、提取场景、prefab层级
trigger: decompile APK|decompile XAPK|reverse engineer Android|extract API|analyze Android|jadx|fernflower|vineflower|follow call flow|decompile JAR|decompile AAR|Android reverse engineering|find API endpoints|unity il2cpp|libil2cpp|reverse unity game|ghidra headless|pyghidra|command line decompile|decompile without GUI|extract assets|scene hierarchy|prefab|UnityPy|AssetStudio|extract texture|extract model|反编译APK|安卓逆向|提取API|分析安卓应用|逆向unity|命令行反编译|无GUI反编译|提取贴图|提取模型|提取场景|prefab层级
---

# Android Reverse Engineering

Decompile Android APK/XAPK/JAR/AAR with jadx and Fernflower/Vineflower, trace call flows, and produce structured API documentation. Two decompiler engines: jadx for broad Android coverage and Fernflower for higher-quality Java on complex code. For Unity IL2CPP games, see the dedicated workflow below — this is a different problem and jadx alone is useless there.

## Prerequisites

- JDK 17+ (jadx / Fernflower)
- JDK 21+ (Ghidra — required for Unity IL2CPP body recovery)
- jadx, Ghidra 12+, Python 3 with: capstone, pyghidra, dnfile, UnityPy (`pip install capstone pyghidra dnfile UnityPy`; after installing pyghidra run ONCE: `pyghidra --install-dir <GHIDRA_DIR>`)
- Il2CppDumper (auto-downloaded from wklin8607/Il2CppDumper if missing — that fork supports metadata v39, incl. the new magic 0xFAB11BAF and Unity 6 builds)
- AssetStudioMod CLI (aelurum fork, optional but recommended — the only reliable way to read STRIPPED MonoBehaviour serialized values, via `--assembly-folder` + Il2CppDumper's DummyDll)
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
    WORK_DIR="<work-dir>"            # ASCII-only path on Windows (non-ASCII breaks dotnet/ghidra/objdump)
    mkdir -p "$WORK_DIR/apk-extracted"
    unzip -o "$APK" "lib/arm64-v8a/libil2cpp.so" -d "$WORK_DIR/apk-extracted"
    unzip -o "$APK" "assets/bin/Data/Managed/Metadata/global-metadata.dat" -d "$WORK_DIR/apk-extracted"
    unzip -o "$APK" "assets/bin/Data/data.unity3d" -d "$WORK_DIR/apk-extracted" 2>/dev/null

OBB expansion packs (Google Play / Quest sideload layouts): large Unity games ship the
FULL data.unity3d + Addressables bundles + databases in a sibling .obb (a plain ZIP).
fingerprint.sh auto-detects it; extract it too when present:

    OBB="<path/to/main.<ver>.<pkg>.obb>"     # or: find "$(dirname "$APK")" -name '*.obb'
    unzip -o -q "$OBB" -d "$WORK_DIR/obb-extracted"
    # the bigger data.unity3d is usually at obb-extracted/assets/bin/Data/data.unity3d
    # Addressables content packs: obb-extracted/assets/aa/Android/*.bundle + catalog.bin
    # watch for *.db/*.sqlite — if libsqlcipher.so is among native libs, they are
    # SQLCipher-encrypted; the key is embedded in code (find it in the decompiled output)

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

Gotchas proven in practice:
- Output location: despite the output-dir argument, the dumper may write dump.cs/script.json/il2cpp.h/DummyDll NEXT TO ITSELF (the extracted/ folder). Check both locations and move the files.
- The trailing "Press any key" ReadKey exception when run non-interactively is harmless — the outputs are already complete.
- Keep WORK_DIR ASCII-only on Windows: non-ASCII (e.g. Chinese) paths have broken Ghidra/dotnet/objdump in practice. Use e.g. D:/tmp/<app>-re/.
- il2cpp.h (often 100+ MB) is only needed for the Ghidra GUI struct route. The headless route (Phase U6) skips it entirely — read field offsets from dump.cs instead.

### Phase U3: Pre-filter the symbol table (script.json is huge)

script.json holds EVERY managed method (engine + SDK + app, e.g. 292k entries). You only want the app's own code. Two ways:

Preferred — derive app types automatically from DummyDll. Multi-assembly apps are common
(Mondly VR: 39 `ATiStudios.*.dll` + Assembly-CSharp; DreamSpace: Assembly-CSharp only) —
pass glob patterns, `ls DummyDll/` first to see what exists:

    python3 "$SKILL_DIR/scripts/filter_symbols.py" "$WORK_DIR/il2cpp-output" "$WORK_DIR" \
        --assemblies "Assembly-CSharp.dll,ATiStudios.*.dll"
    # reads the matched DummyDll assemblies, writes symbols_map.txt (hexaddr|Class$$Method),
    # game_types.txt, game_methods.json (engine/SDK dlls are excluded by prefix fallback)

Manual alternative — keyword filter when you already know the brand namespaces:

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
- On Windows, binutils objdump may print NOTHING for these addresses (RX-segment VMA/file-offset skew, e.g. +0x4000). Use capstone with program-header-based offset conversion instead — `scripts/verify_addresses.py` does exactly that:

    python3 "$SKILL_DIR/scripts/verify_addresses.py" "$WORK_DIR/apk-extracted/lib/arm64-v8a/libil2cpp.so" "$WORK_DIR/symbols_map.txt" 6

### Phase U6: Ghidra — the ONLY body-recovery path (HEADLESS, no GUI needed)

Ghidra is NOT GUI-only. The verified route is pyghidra (Python driving Ghidra's API in-process): open the .so, create functions at Il2CppDumper addresses, batch-decompile every app method, write one .c file per class. Proven end-to-end on a 110 MB libil2cpp.so / 292k symbols / metadata v39: **2779/2779 app methods decompiled, 0 failures, ~40 min on 64 GB RAM.**

    export GHIDRA_INSTALL_DIR="<path/to/ghidra_12.x_PUBLIC>"
    export JAVA_HOME="<path/to/JDK-21>"          # Ghidra REQUIRES JDK 21
    # one-time after pip install pyghidra:  pyghidra --install-dir "$GHIDRA_INSTALL_DIR"
    python3 "$SKILL_DIR/scripts/decompile_il2cpp_headless.py" \
        "$WORK_DIR/apk-extracted/lib/arm64-v8a/libil2cpp.so" \
        "$WORK_DIR/symbols_map.txt" \
        "$WORK_DIR/decompiled" <project-name>

What it does internally (for debugging): `pyghidra.start()` (NO vm_args param in pyghidra 3.x; JVM heap defaults to 1/4 physical RAM) -> `open_program(..., analyze=False)` (full auto-analysis is a waste here) -> for each hex address in symbols_map.txt: `createFunction` at `imageBase + RVA` (Ghidra's image base is 0x100000 for these ELF .so; script.json addresses are RVA) -> `DecompInterface().decompileFunction(f, 120, monitor)` -> group output by the class part of `Class$$Method`.

BEFORE the long run, spend 10 s verifying the address map (catches wrong .so/metadata pairs):

    python3 "$SKILL_DIR/scripts/verify_addresses.py" "$SO" "$WORK_DIR/symbols_map.txt"

AFTER it finishes, resolve call targets — decompiled bodies call other methods as `func_0xADDR`; rewrite them to real names using the FULL script.json:

    python3 "$SKILL_DIR/scripts/annotate_decompiled.py" "$WORK_DIR/il2cpp-output/script.json" "$WORK_DIR/decompiled"
    # Ghidra addr = imageBase(0x100000) + RVA. On a real build this resolved 41,515 call sites;
    # leftovers are il2cpp runtime internals (C++ side, no managed symbols) — expected.

Then annotate FIELD OFFSETS with real names — decompiled bodies read fields as `*(long*)(param_1 + 0x50)`; dump.cs knows every field's offset, so map them back:

    python3 "$SKILL_DIR/scripts/annotate_fields.py" "$WORK_DIR/il2cpp-output/dump.cs" "$WORK_DIR/decompiled"
    # -> *(long*)(param_1 + 0x50 /*this.DLCManager.assetFilePath*/)   (5,313 sites annotated on the reference build)
    # conservative: only annotates param_1 (the this pointer) of instance methods, only on offset hit

What noise REMAINS after both passes (and why it is normal, not a bug):
- `func_0x...` on some calls = il2cpp C++ runtime internals (GC, codegen helpers) — no symbols exist for them
- `PTR_DAT_xxx / bRam... / cRam...` = Ghidra auto-names for static-field storage & metadata pointers; the recurring `if ((bRam.. & 1) == 0) { func_0x..; bRam.. = 1; }` idiom is the IL2CPP one-time type-init guard — ignorable
- `uVar3 / lVar5 / puVar1` = decompiler-local names — inherent to pseudocode; there is NO route back to real C# variable names

Timing/memory: ~0.4-1 s per function. On 8-16 GB machines, shrink symbols_map.txt instead of raising heap — decompiling 300-500 key methods is usually enough for a given question.

GUI alternative (only for interactive browsing): `analyzeHeadless <proj> <name> -import <so> -noanalysis`, then in the GUI parse il2cpp_ghidra.h and run Il2CppDumper's ghidra_with_struct.py. The headless route above replaces all of that.

Output: real C-level decompilation of each Class$$Method — this is what Cpp2IL cannot give you. Pair each .c file with the same class in dump.cs for field names/offsets (the decompiler shows raw offsets like `*(long *)(param_1 + 0x50)`; dump.cs tells you that 0x50 is e.g. `private string assetFilePath`).

### Phase U7: strings / constants (strongest signal)

    python3 -c "
    import json
    for it in json.load(open('<work-dir>/il2cpp-output/stringliteral.json')):
        v = it.get('value','')
        if 'http' in v or 'api' in v or 'key' in v or 'secret' in v:
            print(v[:200])
    "

Bonus: debug/error strings often leak the ORIGINAL PROJECT's source tree — grep for absolute .cs paths (skips PackageCache/Library to keep only app-authored files):

    python3 -c "
    import json
    vals = (it.get('value','') for it in json.load(open('<work-dir>/il2cpp-output/stringliteral.json')))
    for v in sorted({v for v in vals if v.endswith('.cs') and '/Users/' in v and 'PackageCache' not in v and 'Library/' not in v}):
        print(v)
    "

### Phase U8: Unity assets — scene layout, prefab hierarchy, serialized values, media

Code tells you WHAT the app can do; assets tell you what it IS CONFIGURED to do. Full details: references/unity-assets-extraction.md. Verified on an 864 MB data.unity3d (metadata v39 build): 10.7k GameObjects, 5.9k MonoBehaviours, 381 textures, 555 meshes, 332 animation clips, 79 audio clips.

Extract data.unity3d first — and note there may be TWO of them when an OBB is present
(the APK ships a bootstrap copy; the OBB ships the full one; scenes may live in either —
run inventory on BOTH, e.g. Mondly: scene list in the APK-side file, bulk content in the OBB):

    unzip -o -j "$APK" "assets/bin/Data/data.unity3d" -d "$WORK_DIR/apk-extracted"
    [ -f "$OBB" ] && unzip -o -q "$OBB" -d "$WORK_DIR/obb-extracted"

A) UnityPy quick route (scripts/extract_assets.py, pure CLI):

    python3 "$SKILL_DIR/scripts/extract_assets.py" "$WORK_DIR/apk-extracted/data.unity3d" "$WORK_DIR/asset-out" inventory
    # -> type counts + BuildSettings scene list + MonoBehaviour typetree availability
    python3 "$SKILL_DIR/scripts/extract_assets.py" "$WORK_DIR/apk-extracted/data.unity3d" "$WORK_DIR/asset-out" extract --types Texture2D,TextAsset,Font --limit 200
    # -> png/txt/ttf (also: AudioClip->wav best-effort, Mesh->obj best-effort; filter --name-like eagle)
    python3 "$SKILL_DIR/scripts/extract_assets.py" "$WORK_DIR/apk-extracted/data.unity3d" "$WORK_DIR/asset-out" hierarchy
    # -> per-scene GameObject tree with mounted components and parent/child links (hierarchy/*.json)

B) AssetStudioMod CLI (aelurum fork) + DummyDll — the ONLY reliable route to STRIPPED MonoBehaviour serialized values (UnityPy read_typetree fails on them; 5883/5910 were stripped on the reference build):

    gh release download --repo aelurum/AssetStudio --pattern "AssetStudioModCLI_net9_win64.zip"
    AssetStudioModCLI.exe "$WORK_DIR/apk-extracted/data.unity3d" -m dump -t monoBehaviour       --assembly-folder "$WORK_DIR/il2cpp-output/DummyDll" -o "$WORK_DIR/asset-out/mb-dump"
    # verified 5905/5910 dumped with real field names + values (volumes, thresholds, SKUs, PPtr refs)
    # also: -t tex2d,mesh,audio,shader,font,textAsset / -m export for png/fbx/wav / -g sceneHierarchy

Three-way cross-read for maximum fidelity: dump.cs (field layout) + hierarchy/*.json (where each component instance sits) + mb-dump/*.txt (what values each instance holds).

Addressables content packs (OBB `assets/aa/Android/*.bundle`, catalog.bin + settings.json):
each .bundle is a standalone Unity asset file — point UnityPy/extract_assets.py or
AssetStudioMod directly AT the .bundle path to pull its textures/meshes/MonoBehaviours
(verified: animals bundle -> crocodile/cow/chicken/sheepdog textures in seconds).
Encrypted *.db: if libsqlcipher.so is present the databases are SQLCipher-encrypted;
recover the passphrase from the decompiled code, then open with sqlcipher CLI.

Shader note: original ShaderLab/HLSL is NOT recoverable from a build — dumps give structure/property names only; effects must be re-inferred from SPIR-V or rewritten.

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
2. Bodies — decompiled/<Class>.c per-class C pseudocode from Ghidra headless, call sites annotated with real Class$$Method names (_INDEX.md lists all classes)
3. ARM64 disasm — objdump/capstone of key functions with resolved callee names
4. Strings — URLs / keys / constants from stringliteral.json (+ leaked original source paths)
5. Assets — scene hierarchy JSON, MonoBehaviour serialized values with real field names, png/ttf/wav/obj media
6. Architecture summary — module deps + call chains
