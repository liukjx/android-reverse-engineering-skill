# Unity IL2CPP 逆向工程

Unity IL2CPP (Intermediate Language To C++) 把 C# 编译成原生 ARM64/x64 二进制。**jadx 对它几乎无效** —— 真正的游戏逻辑全在 libil2cpp.so 里，Java 层只是 Unity 引擎封装。

## 目录

1. 快速判断 Unity IL2CPP 应用
2. 工具链概览
3. 完整工作流
4. 提取类元数据和方法名 (Il2CppDumper)
5. 提取 Unity 资源 (AssetRipper / UnityPy)
6. 分析 IL2CPP 二进制 (Ghidra) —— 拿到方法体的唯一路径
7. Cpp2IL 的真实定位（只能拿结构，拿不到方法体）
8. 常见保护与绕过

---

## 1. 快速判断 Unity IL2CPP 应用

指纹脚本 fingerprint.sh 会自动检测。判断标志：

| 检测项 | 特征文件/字符串 |
|--------|---------------|
| Unity 引擎 | libunity.so |
| IL2CPP | libil2cpp.so + assets/bin/Data/Managed/Metadata/global-metadata.dat |
| Mono (非IL2CPP) | assets/bin/Data/Managed/Assembly-CSharp.dll (直接 dnSpy 打开) |
| Unity 入口 | com.unity3d.player.UnityPlayerActivity (AndroidManifest.xml) |
| VR 插件 | libOVRPlugin.so (Oculus)、libopenxr_loader.so (OpenXR) |

指纹含 libil2cpp.so → 走本指南，跳过 jadx 的 Phases 1-5。

---

## 2. 工具链概览

| 工具 | 用途 | 获取 |
|------|------|------|
| Il2CppDumper | IL2CPP 元数据 dump（结构 + 符号表） | gh release download --repo wklin8607/Il2CppDumper （支持 metadata v39 的分支；Perfare 原版亦可） |
| AssetRipper | Unity 资源提取（纹理/模型/场景） | gh release download --repo AssetRipper/AssetRipper |
| UnityPy | Python 库，提取/修改 Unity 资源 | pip install UnityPy |
| Ghidra 12+ | ARM64 二进制反编译 + 符号自动化（拿方法体） | 官网下载 zip |
| JDK 21+ | Ghidra 依赖 | |
| Cpp2IL | 仅结构（桩 DLL），拿不到方法体 | gh release download --repo SamboyCoding/Cpp2IL |

---

## 3. 完整工作流

### Phase U1: 提取关键文件
APK → unzip：
- lib/arm64-v8a/libil2cpp.so      —— 编译后的游戏代码（几十~上百 MB）
- assets/bin/Data/Managed/Metadata/global-metadata.dat —— 类/方法名索引（~15 MB）
- assets/bin/Data/data.unity3d     —— 场景/资源包（AssetRipper 用）

### Phase U2: 运行 Il2CppDumper
    dotnet Il2CppDumper.dll libil2cpp.so global-metadata.dat ./il2cpp-output
（wklin8607 分支产物是 Il2CppDumper.dll，用 dotnet 跑；Perfare 原版是 Il2CppDumper.exe，Windows 用）

### Phase U3: 解析输出
| 文件 | 说明 |
|------|------|
| dump.cs | 最核心：所有类/字段/方法的文本定义（结构） |
| DummyDll/ | 桩 DLL，dnSpy/ILSpy 浏览类结构 |
| script.json | 完整符号表：地址 → Class$$Method |
| il2cpp.h | C 结构体头文件（喂给 Ghidra） |
| stringliteral.json | 所有字符串常量 |
| ghidra_with_struct.py / il2cpp_header_to_ghidra.py | Ghidra 符号加载脚本（在 Il2CppDumper 目录里） |

### Phase U4: 分析 dump.cs
dump.cs 含完整类定义：
    // Namespace:
    public class CarController : MonoBehaviour
    {
        public float motorForce; // 0x150
        // RVA: 0x148E9C0 Offset: 0x148D9C0
        private void FixedUpdate() { }
    }
技巧：
- 定位类：grep "^public class .* : MonoBehaviour" dump.cs
- 定位方法：grep "public .*(" dump.cs
- 只看游戏代码：Assembly-CSharp.dll 区段
- 字符串：jq '.[]."value"' stringliteral.json | sort -u

### Phase U5: Unity 资源提取（可选）
    import UnityPy
    env = UnityPy.load("path/to/bundle.bundle")
    for path, obj in env.container.items():
        print(f"[{obj.type.name}] {path}")
    for obj in env.objects:
        if obj.type.name == "MonoBehaviour":
            data = obj.read()

---

## 6. 分析 IL2CPP 二进制 (Ghidra) —— 拿到方法体的唯一路径

⚠️ 这一步才是拿到"真实函数体"的地方。流程（参考 Cpp2IL 作者 BadMagic100 的 gist）：

1. 装 JDK 21 + Ghidra 12。
2. 启动 Ghidra，New Project，Import libil2cpp.so（**先不选自动分析**，100MB+ 的 .so 自动分析很慢）。
3. File → Parse C Code：先跑 Il2CppDumper 目录里的 il2cpp_header_to_ghidra.py 把 il2cpp.h 转成 il2cpp_ghidra.h，再 Parse 它（遇语法错误就把出错 struct 体注掉，后面用 Structure Editor 补）。
4. Script Manager → 把 Il2CppDumper 目录加进脚本目录 → 跑 ghidra_with_struct.py（选 script.json）。
5. 让 Ghidra 分析，Functions 窗口搜 ClassName$$Method → 右键 Decompile 看伪 C。

协程/async 会出现成匿名状态机类 ClassName.<MethodName>d__NN$$MoveNext，真正的逻辑在 MoveNext 里。

内存：Ghidra 分析 100MB+ libil2cpp.so 建议 ≥16GB RAM；8GB 大概率 OOM。缓解：
- 设 -Xmx 但低于物理内存（如 8GB 机设 -Xmx6G）。
- 只对你关心的函数逐个 Decompile，不全量分析。
- 换 ≥16GB 的机器做全量。

---

## 7. Cpp2IL 的真实定位

Cpp2IL 是 Il2CppDumper 的现代替代品，但**它的 IL 恢复功能是未实现的桩**：

- --output-as dll_il_recovery 在作者 SamboyCoding 的 issue #223 / #528 中明确说明：当前是 stub，对所有方法只输出 throw null / 空体。
- 我们在一台 Unity 6000.4 / arm64 / metadata v39 的构建上实测：dll_il_recovery、dll_throw_null、diffable-cs 三种输出全部是空体或桩。
- 结论：Cpp2IL 只能用来生成"可浏览的桩 DLL 骨架"（给 IDE 看结构），**拿不到方法体**。需要方法体，回到 Phase U6 的 Ghidra。

macOS 提示：Cpp2IL 预编译的 Mach-O 未签名，Gatekeeper 会在 .NET 启动前静默杀掉（Killed: 9，~32KB RSS）。codesign --force --sign - 自签即可运行。

---

## 8. 常见保护与绕过

| 保护方式 | 现象 | 解决方案 |
|----------|------|----------|
| 加密 global_metadata.dat | Il2CppDumper 报 "this file may be protected" | Zygisk-Il2CppDumper 运行时 dump（需 Root + Magisk） |
| 加密 libil2cpp.so | linker 报错或 IDA 无法识别 | 运行时从内存 dump 完整 .so |
| Beebyte/CodeGuard/uProtect | 方法名为随机字符串 | Il2CppDumper 仍能提取类结构，但方法名被混淆 |
| Obfuscator 混淆 | 控制流平坦化 | Ghidra 中手动跟踪，对比 stringliteral.json 定位 |

带保护的游戏最有效方式：
1. Root 手机 + Zygisk
2. 装 Zygisk-Il2CppDumper 模块
3. 启动目标游戏
4. dump 文件生成在 /data/data/<包名>/ 目录

---

## 附：Unity 游戏逆向判别速查表

| 文件存在 | 框架 | 工具建议 |
|----------|------|----------|
| libil2cpp.so | Unity IL2CPP | Il2CppDumper（结构）+ Ghidra（方法体） |
| assets 中 Assembly-CSharp.dll | Unity Mono | 直接 dnSpy 打开 |
| libunity.so 但无 libil2cpp | Unity 但无 C# 代码 | AssetRipper 提取资源 |
| libflutter.so | Flutter | blutter + Dart 逆向 |
| assets/index.android.bundle | React Native | Hermes 字节码分析 |

---

## 参考
- Il2CppDumper: https://github.com/Perfare/Il2CppDumper
- Il2CppDumper (v39 fork): https://github.com/wklin8607/Il2CppDumper
- Cpp2IL: https://github.com/SamboyCoding/Cpp2IL （IL 恢复为已知未实现桩，见 issue #223/#528）
- AssetRipper: https://github.com/AssetRipper/AssetRipper
- Ghidra: https://ghidra-sre.org/
- UnityPy: https://github.com/k0lb3/UnityPy
- Zygisk-Il2CppDumper: https://github.com/Perfare/Zygisk-Il2CppDumper
- IL2CPP + Ghidra 指南（Cpp2IL 作者）: https://gist.github.com/BadMagic100/47096cbcf64ec0509cf75d48cfbdaea5
