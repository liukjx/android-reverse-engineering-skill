# Android Reverse Engineering & API Extraction — Claude Code skill

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![GitHub stars](https://img.shields.io/github/stars/SimoneAvogadro/android-reverse-engineering-skill?style=social)](https://github.com/SimoneAvogadro/android-reverse-engineering-skill/stargazers) [![GitHub last commit](https://img.shields.io/github/last-commit/SimoneAvogadro/android-reverse-engineering-skill)](https://github.com/SimoneAvogadro/android-reverse-engineering-skill/commits/master)

A Claude Code skill that decompiles Android APK/XAPK/JAR/AAR files and **extracts the HTTP APIs** used by the app — Retrofit endpoints, OkHttp calls, hardcoded URLs, authentication patterns — so you can document and reproduce them without the original source code.

> **First-class Kotlin support**: modern Android apps are Kotlin/KMP, heavily obfuscated with R8. This skill recovers the **original Kotlin class names** from metadata R8 cannot strip, and extracts APIs from **Ktor**, **Apollo (GraphQL)** and **Koin** — not just the classic Retrofit/OkHttp stack. See [Kotlin name recovery](#kotlin-name-recovery-r8-deobfuscation) below.

> **Windows / PowerShell support (experimental)**: The `*.ps1` scripts alongside the bash ones are a recent community contribution, still being stabilised. For any issues please open an issue on **this** repository (not on the contributors' upstream forks): the PowerShell scripts are maintained here by [@SimoneAvogadro](https://github.com/SimoneAvogadro).

## Table of Contents

- [What it does](#what-it-does)
- [Engine-first triage](#engine-first-triage)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Repository Structure](#repository-structure)
- [References](#references)
- [Acknowledgments](#acknowledgments)
- [Disclaimer](#disclaimer)
- [License](#license)

## What it does

| Capability | Description |
|------------|-------------|
| **Fingerprint first (Phase 0)** | Triage an APK/XAPK in seconds — detect the framework (Flutter / React Native / Cordova / Xamarin / native-Kotlin), HTTP stack, obfuscation level and native libs *before* spending time on a full decompile |
| **Decompile** | APK, XAPK, JAR, and AAR files using jadx and Fernflower/Vineflower (single engine or side-by-side comparison) |
| **Recover Kotlin names** | Rebuild original `*Repository` / `*ViewModel` / `*UseCase` class names from R8-obfuscated binaries using Kotlin metadata that R8 cannot strip |
| **Extract APIs** | Retrofit, OkHttp, Volley **and modern Kotlin/KMP stacks: Ktor, Apollo (GraphQL), Koin DI** — endpoints, hardcoded URLs, auth headers, tokens and HMAC request-signing schemes |
| **Trace call flows** | From Activities/Fragments through ViewModels and repositories down to HTTP calls |
| **Analyze structure** | Manifest, packages, architecture patterns |
| **Handle obfuscation** | R8-resistant path/URL extraction plus strategies for navigating ProGuard/R8 output |
| **Unity IL2CPP games** | Structure via Il2CppDumper, real method bodies via headless Ghidra, assets via UnityPy + AssetStudioMod |
| **Unreal Engine 4/5 games** | Full class/function/property API rebuilt from reflected `Z_Construct_*` symbols (parameter names included), pak container parsing that works even when the data section is AES-encrypted, and method bodies via headless Ghidra |
| **Repackaging detection** | Flags injected instrumentation (Frida Gadget and similar), non-ELF files masquerading as `.so`, and re-signed builds — so crack behaviour is never reported as app behaviour |

## Engine-first triage

Engines differ enough that picking the wrong workflow wastes the whole session. Phase 0 decides:

| Found in `lib/` | Engine | Workflow |
|---|---|---|
| `libil2cpp.so` | Unity IL2CPP | Phases U1–U8 |
| `Assembly-CSharp.dll` (no libil2cpp) | Unity Mono | open directly in dnSpy / ICSharpCode.Decompiler |
| `libUE4.so` | **Unreal Engine 4/5** | **Phases E1–E6** |
| neither | standard Android app | Phases 1–5 |

Two checks that materially change the plan and are worth doing immediately:

1. **Is the engine binary stripped?** If `.dynsym` survives, UE4 gives you every class, function and
   parameter name without decompiling anything.
2. **Is the pak data section AES-encrypted?** The index usually stays readable (so you get the full
   asset graph), but `.uasset` payloads may be unrecoverable if the key is not shipped — which is
   the normal case. The skill treats that as a bounded, reportable outcome rather than a failure.

A repackaging check (Phase 0c) also runs early, because a large share of APKs circulating outside
official channels carry injected instrumentation — and mistaking that layer's behaviour for the
app's is the easiest way to produce a wrong report. See
[`repackaging-forensics.md`](plugins/android-reverse-engineering/skills/android-reverse-engineering/references/repackaging-forensics.md).

## Requirements

**Required:**

- Java JDK 17+
- [jadx](https://github.com/skylot/jadx) (CLI)

**Optional (recommended):**

- [Vineflower](https://github.com/Vineflower/vineflower) or [Fernflower](https://github.com/JetBrains/fernflower) — better output on complex Java code
- [dex2jar](https://github.com/ThexXTURBOXx/dex2jar) — needed to use Fernflower on APK/DEX files

**Optional — game engines:**

- Java JDK 21+ and [Ghidra](https://ghidra-sre.org/) 12+ — method-body recovery for both Unity IL2CPP and Unreal Engine
- Python 3 with `pyghidra`, `capstone`, `dnfile`, `UnityPy` (Unity) and `pyelftools` (native-library classification)
- [repak](https://github.com/trumank/repak) — Unreal Engine pak listing/unpacking

See `plugins/android-reverse-engineering/skills/android-reverse-engineering/references/setup-guide.md` for detailed installation instructions.

## Installation

### From GitHub (recommended)

Inside Claude Code, run:

```text
/plugin marketplace add SimoneAvogadro/android-reverse-engineering-skill
/plugin install android-reverse-engineering@android-reverse-engineering-skill
```

The skill will be permanently available in all future sessions.

### From a local clone

```bash
git clone https://github.com/SimoneAvogadro/android-reverse-engineering-skill.git
```

Then in Claude Code:

```text
/plugin marketplace add /path/to/android-reverse-engineering-skill
/plugin install android-reverse-engineering@android-reverse-engineering-skill
```

## Usage

### Slash command

```text
/decompile path/to/app.apk
```

This runs the full workflow: dependency check, decompilation, and initial structure analysis.

### Natural language

The skill activates on phrases like:

- "Decompile this APK"
- "Reverse engineer this Android app"
- "Extract API endpoints from this app"
- "Follow the call flow from LoginActivity"
- "Analyze this AAR library"

### Manual scripts

The scripts can also be used standalone:

```bash
# Check dependencies
bash plugins/android-reverse-engineering/skills/android-reverse-engineering/scripts/check-deps.sh

# Install a missing dependency (auto-detects OS and package manager)
bash plugins/android-reverse-engineering/skills/android-reverse-engineering/scripts/install-dep.sh jadx
bash plugins/android-reverse-engineering/skills/android-reverse-engineering/scripts/install-dep.sh vineflower

# Fingerprint an APK/XAPK BEFORE decompiling (Phase 0 triage):
# framework, HTTP stack, obfuscation level, native libs, notable SDKs
bash plugins/android-reverse-engineering/skills/android-reverse-engineering/scripts/fingerprint.sh app.apk

# Decompile APK with jadx (default)
bash plugins/android-reverse-engineering/skills/android-reverse-engineering/scripts/decompile.sh app.apk

# Decompile XAPK (auto-extracts and decompiles each APK inside)
bash plugins/android-reverse-engineering/skills/android-reverse-engineering/scripts/decompile.sh app-bundle.xapk

# Decompile with Fernflower
bash plugins/android-reverse-engineering/skills/android-reverse-engineering/scripts/decompile.sh --engine fernflower library.jar

# Run both engines and compare
bash plugins/android-reverse-engineering/skills/android-reverse-engineering/scripts/decompile.sh --engine both --deobf app.apk

# Find API calls — defaults to a full scan across every supported stack
bash plugins/android-reverse-engineering/skills/android-reverse-engineering/scripts/find-api-calls.sh output/sources/
bash plugins/android-reverse-engineering/skills/android-reverse-engineering/scripts/find-api-calls.sh output/sources/ --retrofit
bash plugins/android-reverse-engineering/skills/android-reverse-engineering/scripts/find-api-calls.sh output/sources/ --urls

# Modern Kotlin/KMP stacks and obfuscation-resistant extraction
bash plugins/android-reverse-engineering/skills/android-reverse-engineering/scripts/find-api-calls.sh output/sources/ --ktor    # Ktor client
bash plugins/android-reverse-engineering/skills/android-reverse-engineering/scripts/find-api-calls.sh output/sources/ --apollo  # Apollo / GraphQL
bash plugins/android-reverse-engineering/skills/android-reverse-engineering/scripts/find-api-calls.sh output/sources/ --paths   # quoted path literals that survive R8 inlining
```

### Kotlin name recovery (R8 deobfuscation)

Most real-world Kotlin/KMP apps ship through R8, so the decompiled classes come
out as `a.b.c`. R8 renames the JVM symbols but **cannot strip the Kotlin
metadata strings** — the Kotlin runtime (reflection, coroutines) needs the
original fully-qualified names at runtime. This skill mines those
`@DebugMetadata` / `@Metadata` annotations to rebuild an `obfuscated → real`
class-name map. On a typical app it recovers ~100 % of the
`*Repository` / `*ViewModel` / `*UseCase` / `*Impl` classes you actually want to
read.

```bash
# 1. Build the mapping from the decompiled sources
bash plugins/android-reverse-engineering/skills/android-reverse-engineering/scripts/recover-kotlin-names.sh output/sources/ output/names/
#    → output/names/mapping.tsv, mapping.json, by_package/

# 2. Query it: resolve an obfuscated name, search by real name, or grep
#    the sources with each hit annotated with its recovered class name
bash plugins/android-reverse-engineering/skills/android-reverse-engineering/scripts/lookup-name.sh output/names/ LoginRepository
bash plugins/android-reverse-engineering/skills/android-reverse-engineering/scripts/lookup-name.sh output/names/ -o a.b.c
bash plugins/android-reverse-engineering/skills/android-reverse-engineering/scripts/lookup-name.sh output/names/ --grep 'login' output/sources/
```

## Repository Structure

```text
android-reverse-engineering-skill/
├── .claude-plugin/
│   └── marketplace.json                    # Marketplace catalog
├── plugins/
│   └── android-reverse-engineering/
│       ├── .claude-plugin/
│       │   └── plugin.json                 # Plugin manifest
│       ├── skills/
│       │   └── android-reverse-engineering/
│       │       ├── SKILL.md                # Core workflow (Phase 0–5)
│       │       ├── references/
│       │       │   ├── setup-guide.md
│       │       │   ├── jadx-usage.md
│       │       │   ├── fernflower-usage.md
│       │       │   ├── api-extraction-patterns.md
│       │       │   ├── kotlin-name-recovery.md
│       │       │   ├── third_party_hosts.txt   # denylist for first/third-party bucketing
│       │       │   ├── call-flow-analysis.md
│       │       │   ├── unity-assets-extraction.md
│       │       │   ├── unity-il2cpp-reversing.md
│       │       │   ├── ue4-reversing.md        # Unreal Engine 4/5 workflow (Phases E1–E6)
│       │       │   └── repackaging-forensics.md # injected/re-signed build detection
│       │       └── scripts/
│       │           ├── check-deps.sh       # Bash
│       │           ├── check-deps.ps1      # PowerShell
│       │           ├── install-dep.sh
│       │           ├── install-dep.ps1
│       │           ├── decompile.sh
│       │           ├── decompile.ps1
│       │           ├── fingerprint.sh          # Phase 0 — pre-decompile triage
│       │           ├── recover-kotlin-names.sh # R8 → real Kotlin class names
│       │           ├── lookup-name.sh          # query the recovered name map
│       │           ├── find-api-calls.sh
│       │           ├── find-api-calls.ps1
│       │           ├── extract_ue4_symbols.py       # UE4: reflected-symbol API recovery
│       │           ├── parse_ue4_pak_index.py       # UE4: pak index parser (no AES key needed)
│       │           ├── decompile_ue4_headless.py    # UE4: Ghidra body recovery
│       │           ├── decompile_il2cpp_headless.py # Unity: Ghidra body recovery
│       │           ├── annotate_decompiled.py
│       │           ├── annotate_fields.py
│       │           ├── annotate_metadata.py
│       │           ├── filter_symbols.py
│       │           ├── verify_addresses.py
│       │           └── extract_assets.py
│       └── commands/
│           └── decompile.md                # /decompile slash command
├── LICENSE
└── README.md
```

## References

- [jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Fernflower — JetBrains analytical decompiler](https://github.com/JetBrains/fernflower)
- [Vineflower — Fernflower community fork](https://github.com/Vineflower/vineflower)
- [dex2jar — DEX to JAR converter](https://github.com/ThexXTURBOXx/dex2jar)
- [apktool — Android resource decoder](https://apktool.org/)
- [Ghidra — software reverse engineering suite](https://ghidra-sre.org/)
- [pyghidra — Python bindings for Ghidra](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/PyGhidra)
- [Il2CppDumper — Unity IL2CPP metadata dumper](https://github.com/Perfare/Il2CppDumper)
- [repak — Unreal Engine pak reader/writer](https://github.com/trumank/repak)
- [UAssetAPI / UAssetGUI — Unreal Engine asset parsing](https://github.com/atenfyr/UAssetAPI)

## Acknowledgments

Thanks to the contributors who have shaped this skill:

- [@tajchert](https://github.com/tajchert) — Phase 0 fingerprinting, R8-resistant Kotlin name recovery (`recover-kotlin-names.sh`, `lookup-name.sh`), and Ktor / Apollo / Koin / HMAC extraction patterns (#16)
- [@philjn](https://github.com/philjn) — Native Windows / PowerShell support (`check-deps.ps1`, `install-dep.ps1`, `decompile.ps1`, `find-api-calls.ps1`) and split/bundled APK detection in `decompile.sh` (#8)
- [@txhno](https://github.com/txhno) — Migration to the maintained [`ThexXTURBOXx/dex2jar`](https://github.com/ThexXTURBOXx/dex2jar) fork (#12)
- [@muqiao215](https://github.com/muqiao215) — Decompile partial-success handling, Fernflower timeout safeguard, intermediate-artifact directory (#10)
- [@kevinaimonster](https://github.com/kevinaimonster) — Chinese localization (`SKILL.md` discovery keywords) (#4)

## Disclaimer

This plugin is provided strictly for **lawful purposes**, including but not limited to:

- Security research and authorized penetration testing
- Interoperability analysis permitted under applicable law (e.g., EU Directive 2009/24/EC, US DMCA §1201(f))
- Malware analysis and incident response
- Educational use and CTF competitions

**You are solely responsible** for ensuring that your use of this tool complies with all applicable laws, regulations, and terms of service. Unauthorized reverse engineering of software you do not own or do not have permission to analyze may violate intellectual property laws and computer fraud statutes in your jurisdiction.

The authors disclaim any liability for misuse of this tool.

## License

Apache 2.0 — see [LICENSE](LICENSE)