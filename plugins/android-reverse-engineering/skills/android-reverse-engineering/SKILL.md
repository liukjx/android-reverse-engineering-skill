---
name: android-reverse-engineering
description: Decompile Android APK, XAPK, JAR, and AAR files using jadx or Fernflower/Vineflower. Reverse engineer Android apps, extract HTTP API endpoints (Retrofit, OkHttp, Volley), and trace call flows from UI to network layer. Use when the user wants to decompile, analyze, or reverse engineer Android packages, find API endpoints, or follow call flows. 中文触发词：反编译APK、安卓逆向、提取API、分析安卓应用、反编译安卓、逆向工程、追踪调用链、提取接口
trigger: decompile APK|decompile XAPK|reverse engineer Android|extract API|analyze Android|jadx|fernflower|vineflower|follow call flow|decompile JAR|decompile AAR|Android reverse engineering|find API endpoints|反编译APK|安卓逆向|提取API|分析安卓应用
---

# Android Reverse Engineering

Decompile Android APK, XAPK, JAR, and AAR files using jadx and Fernflower/Vineflower, trace call flows through application code and libraries, and produce structured documentation of extracted APIs. Two decompiler engines are supported — jadx for broad Android coverage and Fernflower for higher-quality output on complex Java code — and can be used together for comparison.

## Prerequisites

This skill requires **Java JDK 17+** and **jadx** to be installed. Run the dependency checker first.

**重要：本机已预装的环境（无需再次安装）：**

| 工具 | 路径 |
|------|------|
| JDK 17 (jadx 用) | `/d/program/openjdk-17+35_windows-x64_bin/jdk-17/` |
| JDK 21 (Ghidra 用) | `/d/program/jdk-21.0.12.1/` |
| jadx | `/d/static/jadx/bin/jadx` |
| Ghidra 12.1.3 | `/d/program/ghidra_12.1.3_PUBLIC/` |
| dotnet 9.0 | 系统已安装 |
| Python capstone | `pip install capstone` |
| Il2CppDumper | 若不存在自动从 `wklin8607/Il2CppDumper` 下载 |
| Cpp2IL | 若不存在自动从 `SamboyCoding/Cpp2IL` 下载 |

## Workflow

### Phase 0: Fingerprint the App

Run this BEFORE anything else to determine what kind of app you're looking at:

```bash
APK="<path/to/app.apk>"
bash C:/Users/13087/.claude/plugins/repos/android-reverse-engineering/plugins/android-reverse-engineering/skills/android-reverse-engineering/scripts/fingerprint.sh "$APK"
```

**关键判断：**
- 有 `libil2cpp.so` → **Unity IL2CPP** → 跳转到 Phase U1（以下标准 Phases 1-5 无用）
- 有 `Assembly-CSharp.dll`（无 libil2cpp）→ **Unity Mono** → 用 dnSpy 直接打开
- 无上述文件 → 标准 Android 应用 → 继续 Phase 1

---

## 标准 Android 应用工作流（Phases 1-5）

### Phase 1: 依赖检查

```bash
export JAVA_HOME="/d/program/openjdk-17+35_windows-x64_bin/jdk-17"
export PATH="$JAVA_HOME/bin:$PATH"
bash C:/Users/13087/.claude/plugins/repos/android-reverse-engineering/plugins/android-reverse-engineering/skills/android-reverse-engineering/scripts/check-deps.sh
```

如果 jadx 缺失，它内置在 `/d/static/jadx/bin/jadx` 中，确保它在 PATH 中。

### Phase 2: jadx 反编译

```bash
export JAVA_HOME="/d/program/openjdk-17+35_windows-x64_bin/jdk-17"
export PATH="$JAVA_HOME/bin:$PATH"
bash C:/Users/13087/.claude/plugins/repos/android-reverse-engineering/plugins/android-reverse-engineering/skills/android-reverse-engineering/scripts/decompile.sh \
  --engine jadx -o <output-dir> "$APK"
```

### Phase 3-5: 结构分析和 API 提取

详见原 SKILL.md 对应章节（分析 AndroidManifest、BuildConfig、Retrofit 注解等）。

---

## Unity IL2CPP 游戏工作流（Phases U1-U8）

> 如果 Phase 0 检测到 `libil2cpp.so`，走此工作流。此处整合了全部工具链，修复了 JAVA_HOME 冲突，增加了 C# 恢复步骤。

### Phase U1: 提取关键文件

从 APK 中解压出两个核心文件：

```bash
APK="<path/to/app.apk>"
WORK_DIR="<work-dir>"
mkdir -p "$WORK_DIR/apk-extracted"

unzip -o "$APK" "lib/arm64-v8a/libil2cpp.so" -d "$WORK_DIR/apk-extracted"
unzip -o "$APK" "assets/bin/Data/Managed/Metadata/global-metadata.dat" -d "$WORK_DIR/apk-extracted"
```

### Phase U2: Il2CppDumper（方法结构提取）

**JAVA_HOME 使用 JDK 17（与 jadx 保持一致，Il2CppDumper 不需要 Java）。**

```bash
# 检查是否已有 Il2CppDumper
IL2CPP_DUMPER="$WORK_DIR/Il2CppDumper-v6.7.48/extracted"
if [ ! -f "$IL2CPP_DUMPER/Il2CppDumper.exe" ]; then
  # 下载 wklin8607 分支（支持 metadata v39）
  gh release download --repo wklin8607/Il2CppDumper --pattern "*net8.0*" -D "$WORK_DIR/Il2CppDumper-v6.7.48"
  unzip -o "$WORK_DIR/Il2CppDumper-v6.7.48/Il2CppDumper-v6.7.48-net8.0.zip" -d "$IL2CPP_DUMPER"
fi

"$IL2CPP_DUMPER/Il2CppDumper.exe" \
  "$WORK_DIR/apk-extracted/lib/arm64-v8a/libil2cpp.so" \
  "$WORK_DIR/apk-extracted/assets/bin/Data/Managed/Metadata/global-metadata.dat" \
  "$WORK_DIR/il2cpp-output"
```

**关键输出：**
| 文件 | 用途 |
|------|------|
| `dump.cs` (99MB) | 所有类/字段/方法定义 |
| `script.json` (293MB) | 完整符号表（地址→方法名） |
| `stringlteral.json` | 所有字符串常量 |
| `DummyDll/` | 伪 DLL（可用于 dnSpy 浏览结构） |

### Phase U3: 预过滤符号表

> script.json 有 293MB/644K 方法，直接使用太慢。过滤出应用自身代码。

```bash
python3 << 'PYEOF'
import json
WORK_DIR = "<work-dir>"
keywords = ["ATiStudios", "Mondly", "Chatbot", "Grader", "Speech", "AI",
            "Database", "OpenAI", "Azure", "Gemini", "Whisper", "Oculus",
            "HandsFree", "Vocabulary", "Lesson"]

with open(f"{WORK_DIR}/il2cpp-output/script.json", "rb") as f:
    data = json.loads(f.read().decode("utf-8"))

filtered = {
    "ScriptMethod": [m for m in data["ScriptMethod"] if any(k in m["Name"] for k in keywords)],
    "ScriptString": [s for s in data["ScriptString"] if "http" in str(s.get("Value", ""))],
    "Addresses": data["Addresses"]
}

with open(f"{WORK_DIR}/il2cpp-output/script_filtered.json", "w") as f:
    json.dump(filtered, f)

# 同时生成地址→名称映射文件（给 Capstone/Ghidra 用）
with open("/d/ghidra-scripts/symbols_map.txt", "w") as f:
    for m in filtered["ScriptMethod"]:
        name = m["Name"].replace(" ", "_").replace(":", "_").replace("/", "_")
        f.write(f"{m['Address']:x}|{name}\n")

print(f"Filtered: {len(filtered['ScriptMethod'])} methods")
PYEOF
```

### Phase U4: Cpp2IL（C# 源码恢复）

> 这是将 IL2CPP 转回 C# 源码的关键步骤。Cpp2IL 从 `libil2cpp.so` 中恢复 IL 字节码，生成包含方法签名的 DLL。

```bash
# 检查是否有 Cpp2IL
CPP2IL="$WORK_DIR/Cpp2IL/Cpp2IL-2022.1.0-pre-release.21-Windows.exe"
if [ ! -f "$CPP2IL" ]; then
  gh release download "2022.1.0-pre-release.21" \
    --repo SamboyCoding/Cpp2IL --pattern "*Windows.exe" -D "$WORK_DIR/Cpp2IL"
fi

# 运行（约 1-2 分钟）
"$CPP2IL" \
  --force-binary-path "$WORK_DIR/apk-extracted/lib/arm64-v8a/libil2cpp.so" \
  --force-metadata-path "$WORK_DIR/apk-extracted/assets/bin/Data/Managed/Metadata/global-metadata.dat" \
  --force-unity-version "2023.3.0" \
  --output-as dll_il_recovery \
  --output-to "$WORK_DIR/cpp2il-output" \
  --use-processor "attributeanalyzer,attributeinjector"
```

**输出**：233+ 个 DLL 文件，包含 IL 字节码和方法签名。

### Phase U5: 用 ICSharpCode.Decompiler 反编译 DLL 为 C# 源码

> 通过 .NET 工具批量将 DLL 转成 .cs 文件。

```bash
# 创建 .NET 反编译控制台项目（首次需要）
if [ ! -f "$WORK_DIR/tmp_decomp/Program.cs" ]; then
  dotnet new console -o "$WORK_DIR/tmp_decomp"
  dotnet add "$WORK_DIR/tmp_decomp/tmp_decomp.csproj" \
    package ICSharpCode.Decompiler --version 8.2.0.7535

  # 写入反编译代码
  cat > "$WORK_DIR/tmp_decomp/Program.cs" << 'EOS'
using System;
using System.IO;
using System.Linq;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;

string inputDir = args.Length >= 1 ? args[0] : @"<WORK_DIR>/cpp2il-output";
string outputDir = args.Length >= 2 ? args[1] : @"<WORK_DIR>/source";
Directory.CreateDirectory(outputDir);

var dlls = Directory.GetFiles(inputDir, "*.dll")
    .Where(f => Path.GetFileName(f).Contains("ATiStudios") ||
                Path.GetFileName(f) == "Assembly-CSharp.dll")
    .OrderBy(f => f).ToList();

var settings = new DecompilerSettings(LanguageVersion.Latest) {
    ThrowOnAssemblyResolveErrors = false,
    AsyncAwait = true, AutomaticProperties = true,
    UsingDeclarations = true,
};

int total = 0;
foreach (var dll in dlls) {
    string name = Path.GetFileNameWithoutExtension(dll);
    string outDir = Path.Combine(outputDir, name);
    Directory.CreateDirectory(outDir);
    Console.Write($"Decompiling {name}... ");
    try {
        var decompiler = new CSharpDecompiler(dll, settings);
        var types = decompiler.TypeSystem.MainModule.TypeDefinitions.ToList();
        int count = 0;
        foreach (var type in types) {
            try {
                string fullName = type.FullName;
                if (fullName.Contains("<>") || fullName.Contains("DisplayClass")) continue;
                string code = decompiler.DecompileTypeAsString(type.FullTypeName);
                if (code.Length < 30) continue;
                string fileName = type.Name.Replace("<", "_").Replace(">", "_") + ".cs";
                int lastDot = fullName.LastIndexOf('.');
                string filePath;
                if (lastDot > 0) {
                    string ns = fullName.Substring(0, lastDot);
                    string nsDir = Path.Combine(outDir, ns.Replace('.', Path.DirectorySeparatorChar));
                    Directory.CreateDirectory(nsDir);
                    filePath = Path.Combine(nsDir, fileName);
                } else {
                    filePath = Path.Combine(outDir, fileName);
                }
                File.WriteAllText(filePath, code);
                count++;
            } catch { }
        }
        total += count;
        Console.WriteLine($"{count} files");
    } catch (Exception e) {
        Console.WriteLine($"FAILED: {e.Message}");
    }
}
Console.WriteLine($"\nDone: {total} .cs files");
EOS
fi

# 运行反编译
dotnet run --project "$WORK_DIR/tmp_decomp"
```

**输出**：2,000-3,000 个 `.cs` 文件，包含完整的类结构和方法签名。

### Phase U6: ARM64 汇编级反编译（Capstone）

> 对于需要看实际逻辑的关键函数，直接从二进制提取 ARM64 指令。

```bash
python3 << 'PYEOF'
import struct, os
from capstone import *

WORK_DIR = "<work-dir>"
BINARY = WORK_DIR + "/apk-extracted/lib/arm64-v8a/libil2cpp.so"
MAP_FILE = "D:/ghidra-scripts/symbols_map.txt"
OUTPUT = WORK_DIR + "/decompiled_disassembly.txt"

entries = []
with open(MAP_FILE) as f:
    for line in f:
        p = line.strip().split("|", 1)
        if len(p) == 2: entries.append((int(p[0], 16), p[1]))
entries.sort()

with open(BINARY, "rb") as f: elf = f.read()
e_shoff = struct.unpack_from("<Q", elf, 0x28)[0]
e_shentsize = struct.unpack_from("<H", elf, 0x3A)[0]
e_shnum = struct.unpack_from("<H", elf, 0x3C)[0]
e_shstrndx = struct.unpack_from("<H", elf, 0x3E)[0]
st_off = struct.unpack_from("<Q", elf, e_shoff + e_shstrndx * e_shentsize + 24)[0]
st_size = struct.unpack_from("<Q", elf, e_shoff + e_shstrndx * e_shentsize + 32)[0]
shstrtab = elf[st_off:st_off+st_size]

for i in range(e_shnum):
    o = e_shoff + i * e_shentsize
    name_off = struct.unpack_from("<I", elf, o)[0]
    name = shstrtab[name_off:shstrtab.index(b"\x00", name_off)].decode()
    if name == "il2cpp":
        sec_addr = struct.unpack_from("<Q", elf, o + 16)[0]
        sec_off = struct.unpack_from("<Q", elf, o + 24)[0]
        break

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
with open(OUTPUT, "w") as outf:
    for ah, nm in entries[:100]:
        off = ah - sec_addr + sec_off
        next_a = next((a for a, _ in entries if a > ah), ah + 0x400)
        sz = min(next_a - ah, 0x400)
        if off + sz > len(elf): sz = len(elf) - off
        code = elf[off:off+sz]
        outf.write(f"\n// {nm}\n// 0x{ah:x} size={sz}\n")
        for i in md.disasm(code, ah):
            outf.write(f"  {i.address:#010x}: {i.mnemonic:12s} {i.op_str}\n")
print(f"Output: {OUTPUT}")
PYEOF
```

如果关心特定的 3-5 个函数，这个步骤可以快速给出 ARM64 指令级视图，结合上一阶段的 C# 签名可以间接推导逻辑。

### Phase U7: Ghidra 深度分析（需要时使用）

> 需要 C 级别反编译时用 Ghidra。由于 IL2CPP 的函数入口非标准，建议通过 Ghidra GUI 操作。

```bash
# 设置 JDK 21（Ghidra 需要）
export JAVA_HOME="/d/program/jdk-21.0.12.1"  
export PATH="$JAVA_HOME/bin:$PATH"

# 创建 Ghidra 项目
GHIDRA_HOME="/d/program/ghidra_12.1.3_PUBLIC"
"$GHIDRA_HOME/support/analyzeHeadless.bat" \
    "$WORK_DIR/ghidra_project" "mondly_re" \
    -import "$WORK_DIR/apk-extracted/lib/arm64-v8a/libil2cpp.so" \
    -noanalysis -overwrite

# 应用符号表
# （在 Ghidra GUI 中操作：Script Manager → 添加 /d/ghidra-scripts/ → 运行 LoadSymbols.java）
# 或者直接使用符号映射文件：D:/ghidra-scripts/symbols_map.txt
```

> ⚠️ **JAVA_HOME 切换提醒**：Ghidra 需要 JDK 21，而 jadx 需要 JDK 17。两者冲突时：
> - jadx 用：`export JAVA_HOME="/d/program/openjdk-17+35_windows-x64_bin/jdk-17"`
> - Ghidra 用：`export JAVA_HOME="/d/program/jdk-21.0.12.1"`
> 建議在脚本中显式设置，不要依赖全局 JAVA_HOME。

### Phase U8: 字符串常量分析（信号最强）

```bash
# 从 stringiteral.json 提取所有 URL 和 API Key
python3 -c "
import jso
with open('$WORK_R/il2cpp-output/stringliteral.json') as f:
    for itm in json.load(f):
        val = tem.get('value', ")
        if 'htp' i val or 'api' i val or 'ey' i va:
            prit(val[:150])
"
```

---

## Java 版本速查

| 操作 | JAVA_HOME 设置 |
|-----|------|
| jadx 反编译 | `export JAVA_HOME="/d/program/openjdk-17+35_windows-x64_bin/jdk-17"`|
| Ghidra 导入/分析 | `export A_OME="/d/program/jdk-21.0.12.1"`|
| Il2CppDumper | 不需要 Java |
| Cpp2IL | 不需要 Java |
| ICSharpCode.Decompiler | 使用 dotnet，不需要 Java |

---

## 工具缓存位置

所有工具下载一次后可重复使用：

| 工具 | 缓存路径 |
|------|---------|
|Il2CppDumper（支持 v39）| `$WORK_DIR/Il2CppDumper-v6.7.48/extracted/` |
| Cpp2IL | `$WORK_DIR/Cpp2IL/Cpp2IL-*.exe` |
| Ghidra | `/d/program/ghidra_12.1.3_PUBLIC/` |
| ILSpy 源码生成器 | `$WORK_TMP/tmp_decomp/` |

---

## Output

最终交付物：
1. **C# 结构源码** — 见 `source/` 目录
2. **ARM64 汇编**（关键函数） — 见 `decompiled_key_functions.txt`
3. **dump.cs** — 完整类定义
4. **API 文档** — 字符串常量中提取的所有 URL
5. **架构总结** — 模块依赖和调用链