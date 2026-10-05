# Unreal Engine 4 / 5 Reversing Reference

Companion to the **Unreal Engine 4 Game Workflow (Phases E1-E6)** in SKILL.md. Everything here was
verified end-to-end on a shipping UE4.20 / arm64 Android VR title (110 MB libUE4.so, 295,193
dynsym entries, a 3.5 GB pak v5).

---

## 1. Why UE4 is a different problem from Unity

| | Unity IL2CPP | UE4 / UE5 |
|---|---|---|
| Game logic lives in | C# compiled to C++ (libil2cpp.so) + global-metadata.dat | C++ compiled to .so + **Blueprints serialized in .uasset** |
| Type information | global-metadata.dat (always present, always rich) | .dynsym **if not stripped** - otherwise very little |
| Body recovery | Ghidra + Il2CppDumper (dumper supplies addresses) | Ghidra alone (addresses come from .dynsym) |
| Signature names | mangled, need demangling from metadata | **reflected Z_Construct_* symbols encode class + function + parameter names** |
| Assets | data.unity3d, Addressables .bundle | <Project>/Content/Paks/*.pak (often in the OBB) |
| Asset payload | readable | **often AES-256 encrypted** |

Consequence: the single most valuable first check in UE4 is **whether .dynsym survived**. It decides
whether you get a rich structural picture or a slow string-archaeology job.

---

## 2. Fingerprinting

### 2.1 Engine family

    unzip -l app.apk | grep -E 'libil2cpp|libUE4|libmonobdwgc|Assembly-CSharp'

A libUE4.so in lib/arm64-v8a/ settles it. (libUE4.so is also used by UE5 builds; the name did not change.)

### 2.2 Exact engine version

Leaked build-machine paths inside the engine binary are the fastest signal:

    python -c "
    import re
    d = open('libUE4.so','rb').read()
    for m in list(re.finditer(rb'\+\+UE4\+Release-4\.[0-9]+', d))[:3]:
        print(m.group(0).decode())
    "
    # -> ++UE4+Release-4.20

Also visible: third-party library paths (ThirdParty/PhysX3/...), module names, and sometimes the
packaging host name. **Pin the version** - pak entry layout and .uasset serialization both changed
across 4.x releases.

### 2.3 Project name and launch arguments

    unzip -p app.apk assets/UE4CommandLine.txt
    # -> ../../../Travel/Travel.uproject

<Project>.uproject gives you the project name, which is exactly the directory prefix inside the pak
(<Project>/Content/...) and usually the prefix of the app's own C++ classes.

---

## 3. The reflected-symbol trick (highest value per minute)

UnrealHeaderTool generates, for every reflected type and member, a Z_Construct_* function whose
Itanium-mangled name carries the **declaration's names**:

    UCLASS      _ZN<len>Z_Construct_UClass_<TypeName>_Statics<n><Field>E
    UFUNCTION   _ZN<len>Z_Construct_UFunction_<Class>_<Func>_Statics<n>NewProp_<Param>E
                ... with suffixes _Underlying / _SetBit / _Inner for enums, bitfields, containers
    UPROPERTY   _ZN<len>Z_Construct_UClass_<Class>_Statics<n>NewProp_<Prop>E
    UENUM       _Z<len>Z_Construct_UEnum_<Module>_<EnumName>v
                (also _Z<len>Get_Z_Construct_UEnum_<Module>_<EnumName>_CRCv)

So a class's whole Blueprint API - functions *and their parameter names* - is recoverable with
**zero decompilation**. On the reference build this yielded 841 functions and 791 properties across
the app's classes before Ghidra was ever started.

### 3.1 Grammar gotchas (these cost real time)

1. **The leading length prefix covers the entire qualified body**, not each component. A positional
   _ZN<len><name><len><name>... walk mis-parses these symbols and silently returns nonsense.
   Use a direct regex.
2. **UClass and UEnum have different shapes.** UClass has *no* module component - after the kind
   comes the bare type name (UClass_UFFHandMovementComponent_...). UEnum/UStruct/UInterface
   **do** have one (UEnum_Travel_ETRCameraModeRequirementv).
3. The prefix may be _ZN<len>... (nested, common for classes) or _Z<len>... (local, common for
   enums). A pattern of the form ^_ZN?\d*Z?\d*(?:Get_)?Z_Construct_U(Kind)_(.+)$ covers both.
4. Enum variants carry a trailing v / _CRC / _NoRegister - strip them or you get duplicate entries
   like ETRCameraMode and ETRCameraModev.
5. **Enum values are not separate symbols.** You learn an enum exists and where it is used (from
   signatures), not its member names. Get members from the .uasset if readable, or from usage.

### 3.2 Finding the app's own classes among engine types

A typical build reflects 2,000-18,000 types, the vast majority engine/SDK. App code clusters under
a brand prefix. Discover it empirically rather than guessing:

    import json, collections, re
    syms = json.load(open('ue4-symbols/dynsym.json'))
    mods = collections.Counter()
    for s in syms:
        m = re.match(r'^_ZN?\d*Z?\d*Z_Construct_UEnum_([A-Za-z0-9]+)_', s['n'])
        if m:
            mods[m.group(1)] += 1
    print(mods.most_common(20))
    # -> [('Engine', 1200), ..., ('Travel', 56)]   <- 'Travel' is the project module

Then filter classes on that prefix. extract_ue4_symbols.py --class-prefix TR,FF handles the fact
that UE4 type names start with a kind letter (ATRBoxTraceButton, UFFHand) while users think in terms
of the brand (TR, FF).

---

## 4. pak files

### 4.1 Locating the real content

Android UE4 games ship a small bootstrap APK plus a large OBB (a plain ZIP, usually STORE-mode).
The pak lives in the OBB:

    unzip -l main.<ver>.<pkg>.obb | grep -i 'Content/Paks'
    # -> <Project>/Content/Paks/pakchunk0-Android_Multi.pak

**Copy the pak to an ASCII-only path before running repak.** Otherwise repak reports
io error: The system cannot find the path specified (os error 3) - pure non-ASCII path breakage,
not a corrupted pak.

### 4.2 Footer: read from EOF, never by scanning

    offset = filesize - 44
    i32  Magic          (0x5A6F12E1)
    i32  Version        (5 on UE4.20; higher on later releases, v11+ on UE5 IoStore)
    i64  IndexOffset
    i64  IndexSize
    byte Hash[20]      SHA1 of the index (decrypted, if encrypted)

> **Do not rfind the magic.** 0x5A6F12E1 also appears inside entry headers, and a scan will happily
> land on one of those and produce absurd index offsets (~8e18). This exact mistake was made and
> self-corrected during the reference session.

SHA1(index_bytes) == Hash proves the index is plaintext. If they differ, the index itself is
encrypted and you need the AES key even to list files.

### 4.3 v5 entry layout

    i32    nameLen
    char   name[nameLen]           (includes a NUL terminator)
    i64    Offset
    i64    CompressedSize
    i64    UncompressedSize
    i32    CompressionMethod       (0 = stored, 4 = LZ4 on this build)
    byte   Hash[20]
    if CompressionMethod != 0:
        i32 BlockCount
        { i64 CompressedSize; i64 UncompressedSize }[BlockCount]
    byte   Tail[5]

Notes that cost time to establish:
- There is **no CompressionBlockSize field** in this revision (it exists in others).
- The tail is a fixed **5 bytes**, not 1.
- A whole-index walk should consume exactly IndexSize; delta == 0 is your correctness proof.
- repak info may report 'compression: None' while individual entries still carry
  CompressionMethod = 4. Trust the per-entry value.

### 4.4 repak 0.2.3 quirks on older paks

| Symptom | Reality |
|---|---|
| panicked at entry.rs:397: index out of bounds: the len is 3 but the index is 3, on get/unpack | A repak bug on this entry shape. Not a usage error; the run still emits what it could decode. |
| --strip-prefix "" rejected | clap has no empty-prefix form; the default ../../../ strip is correct. |
| Error: pak is encrypted but no key was provided | **The data section is AES-encrypted.** This is the real, common case - see section 5. |

---

## 5. Encrypted paks: how to tell, and what to do

### 5.1 Confirming it (three independent checks)

1. repak unpack ... -i '<dir>'   ->   pak is encrypted but no key was provided
2. Take a **stored (CompressionMethod = 0)** entry - the smallest you can find - and read its
   payload. If the format is self-describing (INI, JSON), the first bytes must match. An INI always
   starts with a bracket; if it does not, the payload is ciphertext.
3. Bulk check: for every entry whose extension implies a known magic (.uasset/.umap -> 9E 2A 83 C1
   little-endian), count hits. On the reference build: **0 / 5,849 stored entries**, mean entropy
   7.33 (>= 7.0 for 5,300 of them).

### 5.2 Where the key is (and is not)

UE4 reads the AES key from the build's Crypto.json at **packaging** time; the key is **not written
into the pak**. Search the APK/OBB for:

- a Crypto.json file
- an -aes= argument in a launch script or the command line
- a 32-byte base64 (44 chars incl. padding) or 64-hex constant in any binary

On the reference build all three came up empty - 0 candidates in libUE4.so, 0 in the injected
script, no Crypto.json. **Expect this.** The key is usually supplied at runtime, so recovering it
requires dynamic analysis on a rooted device or an emulator.

### 5.3 What you can still deliver (a lot)

Plaintext index + unstripped symbols give a **structure-complete** result:

| Deliverable | Source |
|---|---|
| Every asset path and size | pak index |
| Level/scene list and streaming split | *.umap paths |
| DataAssets, Blueprints, WidgetBlueprints, StringTables | DA_*, BP_*, WBP_*, ST_* paths |
| Class / function / property API with parameter names | reflected symbols (section 3) |
| Game state machines | reflected E<Prefix>* enum names |
| Localization inventory | *.locres paths and byte sizes |
| Gameplay structure and flow | VO cue names (CUE_*), OBB-side plaintext JSON |
| Method bodies | Ghidra (section 6) |

**Not** recoverable without the key: .uasset serialized values, DataTable rows, StringTable text,
.locres prose. Report these as unavailable - do not infer them.

---

## 6. Ghidra on libUE4.so

### 6.1 The simplification versus Unity

The Unity path needs Il2CppDumper to produce an address map, because stripped IL2CPP binaries give
you no usable symbols. A UE4 build with intact .dynsym already has (address, name) for every method,
so symbols_map.txt goes straight into Ghidra.

### 6.2 API notes

    import pyghidra
    pyghidra.start()                                  # pyghidra 3.x: NO vm_args parameter
    from ghidra.base.project import GhidraProject
    proj = GhidraProject.createProject(proj_dir, name, False)
    prog = proj.importProgram(File(so_path))          # (File, bool) overload does NOT exist
    base = prog.getImageBase().getOffset()            # 0x100000 for these ELF .so

- .dynsym values are **RVAs**; the Ghidra address is base + rva.
- Ghidra needs **JDK 21**; jadx needs 17. Export GHIDRA_INSTALL_DIR and JAVA_HOME. These must be set
  in the **same shell invocation** as the script - exported vars do not persist across separate
  command invocations.
- Filter Z_Construct_* out of the symbol map. They are registration stubs, and roughly 8% of the
  input can be duplicate addresses (the decompiler merges them automatically).

### 6.3 Measured performance, and what the output looks like

Reference build (110 MB libUE4.so, 7,731 app methods):

    imported: libUE4.so imageBase: 0x100000
    DONE ok=7114 fail=0 created=0 classes=234    (~280 s, ~50 functions/s)

Bodies arrive already demangled, so the Unity post-passes (annotate_decompiled.py,
annotate_fields.py, annotate_metadata.py) are **unnecessary**. You can read the algorithm directly:

    /* _ZN18UTRProgressionData18SetChallengeStatusEi18ETRChallengeStatus */
    void _ZN18UTRProgressionData18SetChallengeStatusEi18ETRChallengeStatus
                   (long param_1, undefined4 param_2, undefined1 param_3)
    {
      undefined1 auStack_28 [4];
      undefined4 uStack_24;
      undefined4 *puStack_20;
      undefined1 *puStack_18;

      puStack_20 = &uStack_24;
      puStack_18 = auStack_28;
      auStack_28[0] = param_3;
      uStack_24 = param_2;
      _ZN4TSetI6TTupleIJi18ETRChallengeStatusEE27TDefaultMapHashableKeyFuncsIiS1_Lb0E
        E20FDefaultSetAllocatorE7EmplaceI16TPairInitializerIRKiRKS1_EEE13FSetElementIdOT_Pb
                (param_1 + 0x1c8, &puStack_20, 0);
      return;
    }

That single body tells you the container type (TSet<TTuple<int, ETRChallengeStatus>, ...>), the
field offset (this + 0x1c8), and the storage strategy (Emplace of a key/value pair).

Sanity check the whole run afterwards: 0 files containing 'throw null' (the Cpp2IL stub smell),
0 empty {} bodies.

---

## 7. Reading the game from asset names alone

Even without payloads, asset paths plus reflected enums reconstruct the design:

| Signal | What it reveals |
|---|---|
| DA_Experience_* / DA_Activity_* / DA_Challenge* | the progression hierarchy |
| DA_*Photo*, FTRPhotoEvaluationResult, ETRCameraMode | the photo/scoring mechanic and its criteria |
| Maps/<Region>/<Scene>/<Scene>_<Aspect>.umap | how levels split into streaming sublevels (Gameplay/Environment/Audio/VFX/Lighting) |
| _Past / _Present / _Night map suffixes | time-shift mechanics |
| CUE_* / DIA_* / SA_* audio cue names | tutorial and onboarding order, verbatim |
| BP_*Map, BP_*Target, BP_*Prop | interactive-object systems |
| DA_Credits_* | who actually built it (developer, publisher, outsourcing) |
| Content/L10N/<lang>/ | languages shipped, and whether UI art is duplicated per locale |

Cross-check these against reflected enums and function names; when two independent sources agree
(asset naming vs symbol names), the conclusion is solid.

---

## 8. Enumerating what ships next to the engine

A UE4 APK's lib/ directory mixes engine, vendor SDK, and - sometimes - third-party additions.
Classify every .so before trusting it:

    for f in lib/arm64-v8a/*.so; do printf '%s ' "$f"; head -c4 "$f" | xxd -p; done
    # 7f454c46 = ELF ; anything else is a payload carrier, not a library

    readelf -d lib/arm64-v8a/<lib>.so | grep -E 'SONAME|NEEDED'

A library that names itself one thing but never links the engine is the tell for an injected layer.
See references/repackaging-forensics.md.

---

## 9. Quick command sequence

    # 0. fingerprint
    unzip -l app.apk | grep -E 'libUE4|libil2cpp'
    unzip -p app.apk assets/UE4CommandLine.txt          # project name

    # 1. extract (ASCII work dir!)
    mkdir -p /work && cd /work
    unzip -o app.apk 'lib/arm64-v8a/libUE4.so' -d apk-extracted
    unzip -o app.obb -d obb-extracted
    cp "$(find obb-extracted -name '*.pak')" ./game.pak

    # 2. symbol surface (needs unstripped .dynsym)
    python3 extract_ue4_symbols.py apk-extracted/lib/arm64-v8a/libUE4.so ue4-symbols --class-prefix <BRAND>

    # 3. asset graph (works even when data is encrypted)
    python3 parse_ue4_pak_index.py game.pak --out pak-index.json --list > filelist.txt

    # 4. bodies
    export GHIDRA_INSTALL_DIR=...  JAVA_HOME=...
    python3 decompile_ue4_headless.py apk-extracted/lib/arm64-v8a/libUE4.so \
            ue4-symbols/symbols_map.txt decompiled <project>

---

## 10. Checklist before calling a UE4 analysis done

- [ ] Engine version pinned from a leaked build path (not guessed from file dates)
- [ ] Project name from UE4CommandLine.txt
- [ ] .dynsym presence checked and stated (stripped vs unstripped changes everything)
- [ ] App-class prefix determined from the reflected module list, not assumed
- [ ] pak footer read from EOF-44; SHA1(index) == IndexHash recorded
- [ ] Index walk consumed exactly IndexSize (delta == 0)
- [ ] Encryption status of the DATA section established and stated explicitly
- [ ] Key search performed and its result reported (including not-found)
- [ ] Non-engine native libs classified (engine / vendor / third-party-injected)
- [ ] Every unavailable deliverable listed as unavailable, with the reason
