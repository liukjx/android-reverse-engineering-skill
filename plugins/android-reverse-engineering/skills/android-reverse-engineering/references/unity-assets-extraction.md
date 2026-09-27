# Unity 资产提取（场景 / Prefab / 序列化值 / 媒体资源）

代码逆向（dump.cs + Ghidra）告诉你 App **能做什么**；资产提取告诉你它在**成品里实际配置了什么**：
场景布局、Prefab 层级、组件挂载关系、每个字段被策划调成的具体值、贴图/模型/动画/音频/视频。

已在一个 864 MB data.unity3d / 110 MB libil2cpp.so / metadata v39 的真实构建上全流程验证。

## 1. 能提取什么（实测数据）

| 类别 | 数量（参考构建） | 工具 | 结果 |
|------|------|------|------|
| GameObject/Transform/组件挂载 | 10,722 GO / 7,931 Transform | extract_assets.py hierarchy | 完整场景树 ✓ |
| MonoBehaviour 序列化值 | 5,910 个组件实例 | AssetStudioMod + DummyDll | 5,905 个带真实字段名 ✓ |
| 贴图 Texture2D/Sprite | 381 + 80 | UnityPy / AssetStudioMod | .png ✓ |
| 网格 Mesh | 555 | UnityPy(best-effort) / AssetStudioMod | .obj / .fbx ✓ |
| 动画 AnimationClip | 332 | AssetStudioMod（-t mesh + Animator → fbx） | .fbx ✓ |
| 音频 AudioClip | 79 | AssetStudioMod（内置 fmod.dll） | .wav ✓ |
| Shader | 203（名称被 strip） | dump 只能拿到结构/反汇编 | 原始 ShaderLab/HLSL 已丢 ✗ |
| TextAsset | 7（本地化文本等） | UnityPy / AssetStudioMod | 原始字节 ✓ |
| 字体 | 5 | UnityPy | .ttf ✓ |
| 视频 | 8 个 VideoPlayer | 名单+参数可导 | 媒体流多为外部引用 |
| 构建设置 | BuildSettings | extract_assets.py inventory | 场景清单/公司名 ✓ |
| VFX | VisualEffectAsset 11 | AssetStudioMod(best-effort) | 部分可导 |

## 2. 关键坑（都踩过）

- **MonoBehaviour 的 typetree 被 strip**（实测 5883/5910）：UnityPy 的 read_typetree/read() 会报
  "Expected to read N bytes, but only read M bytes"。**解法是 AssetStudioMod CLI 的
  --assembly-folder 指向 Il2CppDumper 的 DummyDll/**（Mono.Cecil 恢复字段布局）——这正是
  IL2CPP 代码逆向管线与资产管线的交汇点。
- **引擎内置类型永不被 strip**：Transform/GameObject/RectTransform/Camera 等永远可读，
  所以场景层级树不需要 DummyDll。
- data.unity3d 是 Unity 总档案，UnityPy 会自动解开其中 globalgamemanagers / level*N / sharedassets；
  container 键可能为空（0），不影响对象遍历。
- Shader 在构建时丢源码：ShaderLab/HLSL 不可恢复，只能从 dump 拿属性名/结构，或对 Vulkan SPIR-V 反推，或重写等效效果。
- 视频多为外部流引用（m_StreamData 指向 .resS/外部文件），本体常不在包内。

## 3. 命令速查

### 3.1 UnityPy 快速路线（scripts/extract_assets.py，纯命令行）

    pip install UnityPy
    unzip -o -j app.apk "assets/bin/Data/data.unity3d" -d apk-extracted

    # 清单：类型计数 + BuildSettings 场景清单 + MonoBehaviour typetree 可用性
    python extract_assets.py apk-extracted/data.unity3d asset-out inventory

    # 提取媒体：Texture2D/Sprite→png, TextAsset→原文, Font→ttf, AudioClip→wav, Mesh→obj
    python extract_assets.py apk-extracted/data.unity3d asset-out extract \
        --types Texture2D,TextAsset,Font --limit 200 [--name-like eagle]

    # 场景/Prefab 层级：每个场景一棵 GameObject 树（名称+挂载组件+父子关系）→ hierarchy/*.json
    python extract_assets.py apk-extracted/data.unity3d asset-out hierarchy

### 3.2 AssetStudioMod CLI（aelurum fork，MonoBehaviour 序列化值的唯一可靠路线）

    gh release download --repo aelurum/AssetStudio --pattern "AssetStudioModCLI_net9_win64.zip"

    # dump = 带真实字段名+值的文本 dump（配合 DummyDll 穿透被 strip 的 typetree）
    AssetStudioModCLI_net9_win64/AssetStudioModCLI.exe apk-extracted/data.unity3d \
        -m dump -t monoBehaviour \
        --assembly-folder il2cpp-output/DummyDll \
        -o asset-out/mb-dump

    # 其他：-t tex2d,mesh,audio,shader,font,textAsset；-m export 出 png/fbx/wav；
    # -g sceneHierarchy 按场景节点路径分组；--filter-by-name eagle 过滤名称
    # -m info 只看各类可导出数量

dump 输出形如：

    MonoBehaviour Base
      ...
      AudioClip[] palmCallClips  / float palmCallVolume = 0.5
      Vector2 perchIdleInterval  /  float x = 3   float y = 8
      PPtr<AudioClip> windLoopClip / float spatialBlend = 1 / float maxDistance = 40

### 3.3 三路数据对照读法（还原度最高）

1. `dump.cs`：字段定义与偏移（结构）
2. `hierarchy/*.json`：组件实例挂在哪棵树上（布局）
3. `mb-dump/*.txt`：每个实例的字段值（参数）
   → 三者合起来就是"某个功能在成品里的完整配置"：例如 DLCManager 的 sku/assetFileName、
   手势检测阈值、音频混音参数，全部可直接读出。

## 4. 参考
- UnityPy: https://github.com/K0lb3/UnityPy
- AssetStudioMod (CLI fork): https://github.com/aelurum/AssetStudio
- AssetRipper（GUI 全量导出工程）: https://github.com/AssetRipper/AssetRipper
