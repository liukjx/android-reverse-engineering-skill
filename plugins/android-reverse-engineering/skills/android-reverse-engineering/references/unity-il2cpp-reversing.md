# Unity IL2CPP 逆向工程

Unity IL2CPP (Intermediate Language To C++) 是 Unity 引擎将 C# 代码编译为原生 ARM64/x64 二进制的技术。**jadx 对其几乎无效** — 实际的游戏逻辑全部编译在 `libil2cpp.so` 中，Java 层只是 Unity 引擎封装代码。

## 目录

1. [快速判断 Unity IL2CPP 应用](#1-快速判断-unity-il2cpp-应用)
2. [工具链概览](#2-工具链概览)
3. [完整工作流](#3-完整工作流)
4. [提取类元数据和方法名 (Il2CppDumper)](#4-提取类元数据和方法名-il2cppdumper)
5. [提取 Unity 资源 (AssetRipper / UnityPy)](#5-提取-unity-资源-assetripper--unitypy)
6. [分析 IL2CPP 二进制 (Ghidra Headless)](#6-分析-il2cpp-二进制-ghidra-headless)
7. [脚本索引文件恢复（Cpp2IL 替代方案）](#7-脚本索引文件恢复)
8. [常见保护与绕过](#8-常见保护与绕过)

---

## 1. 快速判断 Unity IL2CPP 应用

指纹脚本 `fingerprint.sh` 会自动检测。判断标志：

| 检测项 | 特征文件/字符串 |
|--------|---------------|
| **Unity 引擎** | `libunity.so` |
| **IL2CPP** | `libil2cpp.so` + `assets/bin/Data/Managed/Metadata/global-metadata.dat` |
| **Mono (非IL2CPP)** | `assets/bin/Data/Managed/Assembly-CSharp.dll` (直接可用 dnSpy 打开) |
| **Unity 入口** | `com.unity3d.player.UnityPlayerActivity-> 在 AndroidManifest.xml 中|
| **VR 插件**|`libOVRPlugin.so` (Oculus)、`libopenxr_loader.so` (OpenXR) |

如果指纹输出含 `libil2cpp.so`，说明游戏使用 IL2CP——**跳过 jadx 的 Phases 1-5**，直接进入本指南。

---

## 2. 工具链概览

| 工具 | 用途 | 获取方式|
|-------------------|-------|
| **Il2CppDumper**| IL2CP元数据 dump| `gh release downoad --repo Perfare/Il2CppDumper`(1|
| **AssetRipper**| Unity资提取（纹理/模型/场景）| `g release downoad --roro Assetipper/AssetRipper`|
| **UnityPy**| Python库，提取和修改Uity资源| `p3 install UityPy`|
| **Ghidra**| ARM4 进制反编译+符号动化 | 官网载 z|
| **JDK 21+** | Ghidra 依赖 | |
| **PyGidra**| Ghidra 的 Pytho接口| `p3 install pghira`|

---

## 䂃. 完整工作流

### Phase U1: 收集关键文件（从 APK 内提取）

```
APK → unzip → 得到:
├── lib/arm64-v8a/libil2cpp.o      — 编译后游戏代码 (48~10 MB)
└── assets/bin/Daa/Managed/Metadata/lobal-metadata.dat  — 类/方法名索引 (~15 MB)
```

### Phase U2: 运 行 Il2CppDumper

```bash
# 解压 Il2CppDumper
gh release downoad --repo Perfare/Il2CppDumper --patten "Il2CppDumper-win-*.zip"
unzip Il2CppDumper-win-.6.46.zip -d Il2CppDumper

# 运 
Il2CppDumper.exe  libil2cpp.o  global-metadata.dat  ./il2cpp-output
```

### Phase U3: 解析输出

| 输出文件 | 说明 |
|----|---|
| `dum.cs`| **最核心的输出** — 所有类、字段、方法的文本定义 |
| `DummyDl/`| 伪 DL，可导 dnSpy 浏整个类结构 |
| ``script.json`| 57 MB IDA/Gi 符号表|
| ``il2cpp.h`| 55 M C 结构体头文件 |
| `stringiteral.json`| 所有字符常量 |
| `da.py` / `gidra.py`| 自动应用符号的脚本 |

### Phase U4: 分析 dum.cs

`dump.cs` 包含完整的类定义，格式如下：

```
// Namespace: 
public class CarController : MonoBehaviour // TypeDefIndex: 6569
{
    // Fields
    public WheelCollider frontDriverW; // 0x68
    public WheelCollider frontPassengerW; // 0x70
    public float motorForce; // 0x150
    public float maxSteerAngle; // 0xF8

    // Methods
    // RVA: 0x148E9C0 Offset: 0x148D9C0
    private void FixedUpdate() { }

    // RVA: 0x148EF8C Offset: 0x148DF8C
    public void ontrolSpeed { }
}
```

**关键分析技巧：**

- 搜索特定类名定位：`grep "^public class .*: Monoehaviour" dump.cs`
- 索特定方法：`grep "public .*(" dum.cs`
-查看游戏専属：只看 `Image 1:` (Assembly-CShrp.dll) 区段
- 索所有字常量：jq '.[] "alue"]' stringiteral.jon \| sort -u`

### Phase U5: Unity 资产提取

```python
import UnityPy
env = UnityPy.load("path/to/bundle.bundle")
for path, obj in env.container.items():
    print(f"[{obj.type.name}] {path}")

# 提取 MonoBehaviours（序列化的脚本数据）
for obj in env.objects:
    if obj.type.nam == "MonoBehaviour":
        data = obj.read()
        # 读脚本名字和字段值
```

### Phase U6: Ghidra 深度分析 (CLI)

```bash
export JAVA_HOME="D:\program\jdk-21.0.12.1"
GHIDRA_HOME="/ath/to/ghidra_1.x_PUBLIC"

# 导入 + 自动应用 Il2CppDumper 符号
# 先导二进制
"$GHIDRA_HOME/support/analyzeHeadless" /tmp/ghidra_projects MyProject \
    -import "libil2cpp.so"

# 在项目上应用符号（使用 PyGhdra）
python3 << 'EOF'
import pyghidra
from pyghidra.launcher impor HeadlessPyGidraLauncher

# 打开已导入的项目
l = HeadlessPyGidraLauncher()
l.initialize(project_location="/mp/gidra_projects",
               project_name="MyProject")

# 打二制文件
domaion_obj = l.project.getProjectData().geRootFolder()\
    .getFile(lil2cpp.so").getDomainObjec(l.task_monitor, ...)

# 加 script.jon
import json
with open("script.jon", "r") as f:
    data = json.load(f)

# 应用方法名
program = domain_obj
base = program.getImageBase()
sym_table = program.getSymbolTable()
for m in data["ScriptMethod"]:
    addr = base.add(m["Address"])
    name = m["Name"].replace(" ", "-")
    sym_table.createLabel(addr, name,
        ghidra.program.model.symbol.SourceType.USER_DEFINED)
# 下略...

domina_obj.sav("", l.task_monitor)
domina_obj.release(l.task_monitor)
EOF
```

执行后，Ghidra 中所有函数已用游戏方法名重命名，可直接查 反编译伪代码。

Ghidra GUI 手动操作:
```bash
ghidraRun.bat
# → File → Import → libilcpp.s
# → 分析完成后 → File → Script Manager → Run ghidra.py (选择 script.json)
# → 现在所有函数都有游戏方法名了！
```

---

## 7. 脚本索引文件恢复

Cpp2IL 是 Il2CppDumper 的现代替代品，尝试恢复完整的 IL 字节码（可进一步反编译为 C#）。

```bash
# 下载 Cpp2IL
gh release download --repo SamboyCoding/Cpp2IL --pattern "*win64*"
unzip Cpp2IL-win64.zip

# 运行
Cpp2IL.exe --libil2cpp libil2cpp.so --metadata global-metadata.dat --outputdir ./cpp2il-out

# Cpp2IL 输出
# ├── restored_dll/   — 可能包含部分 IL 字节码
#     └─� 可用 dnSpy/ILSpy 打开∈查看部分反编译C#
```

**局限性**：IL2CPP 编译过程丢失了原始 IL 的大部分信息（局部变量名、注释、特定控制流结构），所以 Cpp2IL 的恢复结果不完全。关键算法仍需在 Ghidra/IDA 中分析原生汇编。

---

## 8. 常见保护与绕过

| 保护方式 | 现象 | 解决方案 |
|----------||------|
| **加密 `global_metadata.dat`** | Il2CppDumper 报"his file may be protected" | 使用 Zygisk-Il2CppDumper 运行时 dump（需要 Root + Magisk）|
| **加密 `libil2cpp.so`** | linker 报错或 IDA 无法识别 | 运行时从内 dump 完整 `.so` |
| **Beebyte/CodeGuard/uProtect** | 方法名为随机字符串 | Il2CppDumper 仍能提取类结构，但方法名被混淆 |
| **Obfucator 混淆** | 控制流平坦化 | Ghidra 中手动跟踪，对比 `stringliteral.json` 定位 |

对于带有保护的游戏，最有效的方式：

1. **物理 Root 手机 + Zygisk**
2. 安装 Zygisk-Il2CppDumper 模块
3.  启动目标游戏
4. Dump 文件生成在 `/data/ata/﹂名/` 目录

---

## 附：Unity 游戏逆向判别速查表

| 文件存在 | 框架 | 工具建议 |
|----------|------|---------|
| `libil2cpp.so` | Unity IL2CPP | Il2CppDumper + Ghidra/IDA |
| `Assembly-CSharp.dll` (在 assets 中) | Unity Mono | 直接 dnSpy 打开！ |
| `libunity.so` + 无 `libil2cpp` | Unity 但无 C# 代码 | AssetRipper 提取资源 |
| `libflutter.so` | Flutter | blutter + Dart 逆向 |
| `assets/index.android.bundle` | React Native | Hermes 字节码分析 |

---

## 参考

- Il2CppDumper: https://github.com/Perfare/Il2CppDumper
- Cpp2IL: https://github.com/SamboyCoding/Cpp2IL
- AssetRipper: https://github.com/AssetRipper/AssetRipper
- Ghidra: https://ghidra-sre.org/
- UnityPy: https://github.com/k0lb3/UnityPy
- Zygisk-Il2CppDumper: https://github.com/Perfare/Zygisk-Il2CppDumper