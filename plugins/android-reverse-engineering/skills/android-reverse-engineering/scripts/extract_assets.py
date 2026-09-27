#!/usr/bin/env python3
"""
Unity 资产提取器（UnityPy, 纯命令行）— 与 IL2CPP 代码逆向互补。

用法:
  python extract_assets.py <data.unity3d 或目录> <outdir> inventory
      类型计数 + 容器路径 + MonoBehaviour typetree 可用性 + BuildSettings 场景清单

  python extract_assets.py <file> <outdir> extract --types Texture2D,TextAsset,MonoBehaviour \
      [--name-like DLC] [--limit 200]
      Texture2D/Sprite -> .png | TextAsset -> 原始字节 | MonoBehaviour -> JSON(真实字段名)
      Font -> .ttf | AudioClip -> .wav(best-effort) | Mesh -> .obj(best-effort)
      MonoBehaviour 序列化值 = 场景里实际调的参数(sku/速度/颜色/引用)，代码逆向的完美互补

  python extract_assets.py <file> <outdir> hierarchy [--name-like Courtyard]
      每个场景一棵 GameObject 树: 名称 + 挂载的组件类型 + 父子关系 -> hierarchy/<scene>.json

说明:
- data.unity3d 是 Unity 打包的总档案, UnityPy 会自动解开其中的 globalgamemanagers / level*N / sharedassets
- MonoBehaviour 的 typetree 若未被 strip, read_typetree 直接给出真实字段名+值; strip 掉时本脚本回退为
  原始字节 + 提示改用 AssetRipper/AssetStudioMod 配合 Il2CppDumper 的 DummyDll
"""
import argparse, collections, json, os, sys, time

import UnityPy


def resolve_script(reader, by_pathid):
    """MonoBehaviour -> MonoScript (m_ClassName) 同文件内解析."""
    try:
        sc = reader.read_typetree().get("m_Script", {})
        if sc.get("m_FileID") == 0 and sc.get("m_PathID"):
            ms = by_pathid.get(sc["m_PathID"])
            if ms is not None and ms.type.name == "MonoScript":
                d = ms.read()
                ns, cls = getattr(d, "m_Namespace", ""), getattr(d, "m_ClassName", "")
                return (ns + "." if ns else "") + cls
    except Exception:
        pass
    return None


def do_inventory(path):
    env = UnityPy.load(path)
    types = collections.Counter()
    mb_ok = mb_strip = 0
    mb_classes = collections.Counter()
    settings = {}
    for obj in env.objects:
        t = obj.type.name
        types[t] += 1
        try:
            if t == "MonoBehaviour":
                try:
                    tree = obj.read_typetree()
                    mb_ok += 1
                except Exception:
                    mb_strip += 1
            elif t in ("BuildSettings", "PlayerSettings"):
                tt = obj.read_typetree()
                if t == "BuildSettings":
                    settings["scenes"] = tt.get("scenes", [])
                else:
                    settings["companyName"] = tt.get("companyName")
                    settings["productName"] = tt.get("productName")
                    settings["unityVersion"] = tt.get("unityVersion")
        except Exception:
            pass
    return {
        "types": dict(types.most_common()),
        "monobehaviour": {"typetree_ok": mb_ok, "typetree_stripped": mb_strip},
        "settings": settings,
        "container_paths": sorted(env.container.keys()),
    }


def export_one(obj, outdir, by_pathid):
    t = obj.type.name
    base = None
    d = obj.read()
    base = getattr(d, "m_Name", "") or f"pathid_{obj.path_id}"
    safe = "".join(c if c not in '<>:"/\\|?*' else "_" for c in base)[:80]
    if t in ("Texture2D", "Sprite"):
        img = d.image
        img.save(os.path.join(outdir, f"{safe}_{obj.path_id}.png"))
        return f"{safe}.png"
    if t == "TextAsset":
        raw = d.m_Script
        data = raw.encode("utf-8", "surrogateescape") if isinstance(raw, str) else bytes(raw)
        open(os.path.join(outdir, f"{safe}_{obj.path_id}.txt"), "wb").write(data)
        return f"{safe}.txt"
    if t == "MonoBehaviour":
        cls = resolve_script(obj, by_pathid) or "UnknownMono"
        try:
            tree = obj.read_typetree()
            fn = os.path.join(outdir, f"{cls}_{safe or obj.path_id}.json")
            json.dump(tree, open(fn, "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
            return os.path.basename(fn)
        except Exception:
            return f"{cls}_{safe}: typetree stripped (use AssetRipper + DummyDll)"
    if t == "Font":
        fd = d.m_FontData
        if fd:
            open(os.path.join(outdir, f"{safe}.ttf"), "wb").write(bytes(fd))
            return f"{safe}.ttf"
        return None
    if t == "AudioClip":
        try:
            samples = d.samples  # needs fmod; best-effort
            names = []
            for n, wav in samples.items():
                fn = f"{safe}_{n}.wav"
                open(os.path.join(outdir, fn), "wb").write(wav)
                names.append(fn)
            return names or None
        except Exception:
            return f"{safe}: audio needs fmod (skip)"
    if t == "Mesh":
        try:
            os.makedirs(outdir, exist_ok=True)
            cwd = os.getcwd(); os.chdir(outdir)
            from UnityPy.export import MeshExporter
            MeshExporter.save_mesh_obj(d)
            os.chdir(cwd)
            return f"{safe}.obj"
        except Exception:
            os.chdir(cwd) if "cwd" in dir() else None
            return None
    if t == "Shader":
        try:
            from UnityPy.export import ShaderConverter
            txt = ShaderConverter.convert_shader(d)
            fn = os.path.join(outdir, f"{safe}.shader.txt")
            open(fn, "w", encoding="utf-8", errors="ignore").write(txt)
            return os.path.basename(fn)
        except Exception:
            return None
    if t == "VideoClip":
        tt = obj.read_typetree()
        fn = os.path.join(outdir, f"{safe}.video.json")
        json.dump({k: tt.get(k) for k in ("m_OriginalPath", "m_Width", "m_Height", "m_FrameCount")},
                  open(fn, "w", encoding="utf-8"), indent=1)
        return os.path.basename(fn)
    return None


def do_extract(path, outdir, type_list, name_like, limit):
    os.makedirs(outdir, exist_ok=True)
    env = UnityPy.load(path)
    want = set(type_list)
    got, skipped = 0, 0
    # path_id map per file for MonoScript resolution
    by_pathid = {}
    for obj in env.objects:
        by_pathid.setdefault((id(obj.assets_file), obj.path_id), obj)
    for obj in env.objects:
        if got >= limit:
            break
        if obj.type.name not in want:
            continue
        if name_like:
            try:
                nm = getattr(obj.read(), "m_Name", "") or ""
            except Exception:
                nm = ""
            if name_like.lower() not in nm.lower():
                continue
        sub = os.path.join(outdir, obj.type.name)
        os.makedirs(sub, exist_ok=True)
        r = export_one(obj, sub, by_pathid)
        if r:
            got += 1
            print(f"  [{obj.type.name}] {r}")
        else:
            skipped += 1
    print(f"[+] exported {got}, skipped {skipped} -> {outdir}")


def do_hierarchy(path, outdir, name_like):
    os.makedirs(outdir, exist_ok=True)
    env = UnityPy.load(path)
    files = list({id(o.assets_file): o.assets_file for o in env.objects}.values())
    written = 0
    for sf in files:
        # only scene files (level*) contain GameObjects
        objs = list(sf.objects.values()) if hasattr(sf.objects, "values") else list(sf.objects)
        has_go = any(o.type.name == "GameObject" for o in objs)
        if not has_go:
            continue
        by_id = {o.path_id: o for o in objs}
        transforms, gos = {}, {}
        for o in objs:
            if o.type.name in ("Transform", "RectTransform"):
                try:
                    transforms[o.path_id] = o.read_typetree()
                except Exception:
                    pass
            elif o.type.name == "GameObject":
                try:
                    gos[o.path_id] = o.read_typetree()
                except Exception:
                    pass
        if not transforms:
            continue

        def go_node(go_id, depth, seen):
            g = gos.get(go_id, {})
            comps = []
            for cp in g.get("m_Component", []):
                pid = cp.get("component", {}).get("m_PathID")
                co = by_id.get(pid)
                comps.append(co.type.name if co else "?")
            node = {"name": g.get("m_Name", ""), "components": comps, "children": []}
            if depth < 12 and go_id not in seen:
                seen = seen | {go_id}
                for tr_id, tr in transforms.items():
                    if tr.get("m_GameObject", {}).get("m_PathID") == go_id:
                        for ch in tr.get("m_Children", []):
                            cpid = ch.get("m_PathID")
                            ctr = transforms.get(cpid)
                            if ctr:
                                node["children"].append(
                                    go_node(ctr["m_GameObject"]["m_PathID"], depth + 1, seen))
            return node

        roots = []
        for tr_id, tr in transforms.items():
            father = tr.get("m_Father", {}).get("m_PathID", 0)
            if not father or father not in transforms:
                gid = tr.get("m_GameObject", {}).get("m_PathID")
                if gid:
                    roots.append(go_node(gid, 0, frozenset()))
        label = getattr(sf, "name", None) or f"file_{id(sf):x}"
        if name_like and name_like.lower() not in label.lower() and not any(
                name_like.lower() in json.dumps(r, ensure_ascii=False) for r in roots[:5]):
            continue
        hier_dir = os.path.join(outdir, "hierarchy")
        os.makedirs(hier_dir, exist_ok=True)
        fn = os.path.join(hier_dir, f"{label}.json")
        json.dump({"file": label, "roots": roots}, open(fn, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
        print(f"  hierarchy/{label}.json  roots={len(roots)}")
        written += 1
    print(f"[+] {written} scene hierarchy files -> {outdir}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("outdir")
    ap.add_argument("mode", choices=["inventory", "extract", "hierarchy"])
    ap.add_argument("--types", default="Texture2D,TextAsset,MonoBehaviour")
    ap.add_argument("--name-like", default=None)
    ap.add_argument("--limit", type=int, default=200)
    a = ap.parse_args()

    t0 = time.time()
    if a.mode == "inventory":
        rep = do_inventory(a.path)
        os.makedirs(a.outdir, exist_ok=True)
        json.dump(rep, open(os.path.join(a.outdir, "inventory.json"), "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
        print(f"types: {len(rep['types'])}, MonoBehaviour typetree ok={rep['monobehaviour']['typetree_ok']} "
              f"stripped={rep['monobehaviour']['typetree_stripped']}")
        print("scenes:", rep["settings"].get("scenes"))
        print(f"[+] inventory.json -> {a.outdir} ({time.time()-t0:.0f}s)")
    elif a.mode == "extract":
        do_extract(a.path, a.outdir, [t.strip() for t in a.types.split(",") if t.strip()],
                   a.name_like, a.limit)
        print(f"({time.time()-t0:.0f}s)")
    else:
        do_hierarchy(a.path, a.outdir, a.name_like)
        print(f"({time.time()-t0:.0f}s)")


if __name__ == "__main__":
    main()
