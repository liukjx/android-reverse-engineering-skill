#!/usr/bin/env python3
"""Extract the app API surface from an UNSTRIPPED UE4/UE5 libUE4.so.

UE4's UnrealHeaderTool emits a Z_Construct_* symbol for every UCLASS / USTRUCT / UENUM /
UFUNCTION / UPROPERTY, and the Itanium-mangled name ENCODES the class, the function and
every parameter name. The whole Blueprint-callable API is therefore recoverable from the
dynamic symbol table alone -- no decompilation required.

    _ZN<len>Z_Construct_UFunction_<Class>_<Func>_Statics<n>NewProp_<Param>(_Underlying|_SetBit|_Inner)?E
    _ZN<len>Z_Construct_UClass_<Class>_Statics<n>NewProp_<Prop>E

Works for .so (ELF) and for desktop .dll/.dylib builds.

Usage:
    python3 extract_ue4_symbols.py <libUE4.so> <out-dir> [--class-prefix TR,FF] [--all-classes]

Outputs (into <out-dir>):
    dynsym.json                    every dynamic symbol [{n, v, s}]
    game-classes.json              app classes (prefix-filtered, or all)
    game-blueprint-functions.json  class -> function -> [param names]
    game-properties.json           class -> [property names]
    reflected-types.json           every reflected UClass/UStruct/UEnum/UInterface
    symbols_map.txt                hex-address|Class$$mangled  (feed to decompile_ue4_headless.py)
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import struct
import sys

# Reflection symbols are registration stubs, not app logic: keep them out of symbols_map.txt.
REFLECT_MARKERS = ("Z_Construct_", "InternalConstructor", "InternalVTableHelperCtorCaller")


def read_dynsym_elf(path):
    """Minimal ELF64 .dynsym reader (no pyelftools dependency)."""
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:4] != b"\x7fELF":
        return None
    if data[4] != 2:
        raise SystemExit("32-bit ELF unsupported here; adapt or use: readelf -sW")
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]

    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        fields = struct.unpack_from("<IIQQQQIIQQ", data, o)
        secs.append({"name": fields[0], "off": fields[4], "size": fields[5]})

    strtab_off = secs[e_shstrndx]["off"]

    def sec_name(idx):
        base = strtab_off + secs[idx]["name"]
        return data[base:data.index(b"\x00", base)].decode("latin1")

    for i, s in enumerate(secs):
        s["sname"] = sec_name(i)

    dynsym = next((s for s in secs if s["sname"] == ".dynsym"), None)
    dynstr = next((s for s in secs if s["sname"] == ".dynstr"), None)
    if not dynsym or not dynstr:
        return None

    out = []
    for i in range(dynsym["size"] // 24):
        o = dynsym["off"] + i * 24
        st_name, _info, _other, _shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", data, o)
        if st_name == 0:
            continue
        base = dynstr["off"] + st_name
        nm = data[base:data.index(b"\x00", base)].decode("latin1")
        out.append({"n": nm, "v": st_value, "s": st_size})
    return out


def read_symbols(path):
    """Try ELF .dynsym, then fall back to nm for other object formats."""
    syms = read_dynsym_elf(path)
    if syms is not None:
        return syms, "elf-dynsym"
    import subprocess
    for nm_args in (["-D", "--defined-only"], ["--defined-only"]):
        try:
            r = subprocess.run(["nm", *nm_args, path], capture_output=True, text=True, timeout=900)
        except (OSError, subprocess.SubprocessError):
            continue
        if r.returncode != 0:
            continue
        syms = []
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                try:
                    syms.append({"n": parts[2], "v": int(parts[0], 16), "s": int(parts[1], 16)})
                except ValueError:
                    pass
        if syms:
            return syms, "nm-fallback"
    return [], "none"


# MANGLING NOTE: in these symbols the leading _ZN length prefix covers the whole qualified
# body and the following component is a single length-prefixed chunk. A positional length
# walk therefore mis-parses them; a direct regex is the reliable route.
RX_FUNC_PARAM = re.compile(
    r"^_ZN\d+Z_Construct_UFunction_(.+?)_Statics\d+NewProp_([A-Za-z0-9_]+?)"
    r"(?:_Underlying|_SetBit|_Inner)?E$"
)
RX_CLASS_PROP = re.compile(
    r"^_ZN\d+Z_Construct_UClass_(.+?)_Statics\d+NewProp_([A-Za-z0-9_]+?)"
    r"(?:_Underlying|_SetBit|_Inner|_ElementProp|_Key_KeyProp|_ValueProp)?E$"
)
# Grammar (verified against a shipping UE4.20 build):
#   _ZN<len>Z_Construct_U<Kind>_<TypeName>_Statics<n><Field>E      (nested, ELF .so)
#   _Z<n>Z_Construct_U<Kind>_<TypeName>v                           (local, some builds)
#   _Z<n>Get_Z_Construct_U<Kind>_<TypeName>_CRCv
# UE4 does NOT encode a module component here: after the kind comes the bare type name
# (U/A/F/I/E prefixed), and everything from "_Statics" onward is generated boilerplate.
# Grammar (verified against a shipping UE4.20 build). Two families exist:
#
#   UClass  : _ZN<len>Z_Construct_UClass_<TypeName>_Statics<n>...E
#             -> no module component; after the kind comes the bare type name.
#   UEnum   : _Z<n>Z_Construct_UEnum_<Module>_<EnumName>v
#             -> HAS a module component (Engine, Travel, SlateCore, ...).
#             Enum values are not separate symbols; the count comes from the UFUNCTION
#             signatures / reflected type list.
#   UStruct / UInterface follow the UEnum shape.
# Prefix forms seen: _ZN<len>... (nested) and _Z<len>... (local, used by UEnum/UStruct).
# "_ZN?\d*Z?\d*" accepts both without over-matching.
RX_TYPE = re.compile(
    r"^_ZN?\d*Z?\d*(?:Get_)?Z_Construct_U(Class|Struct|Enum|Interface)_([A-Za-z0-9_]+)"
)

# Known engine modules: used to strip the module component from enum/struct tails.
ENGINE_MODULES = {
    "Engine", "Core", "CoreUObject", "SlateCore", "Slate", "UMG", "MovieScene",
    "MovieSceneTracks", "AIModule", "GameplayTasks", "NavigationSystem", "OnlineSubsystem",
    "OnlineSubsystemUtils", "InputCore", "RenderCore", "RHI", "PhysicsCore", "Chaos",
    "Landscape", "Foliage", "AudioMixer", "MediaAssets", "Paper2D", "Niagara",
    "CableComponent", "ResonanceAudio", "AndroidPermission", "AndroidRuntimeSettings",
    "MobilePatchingUtils", "ProceduralMeshComponent", "VRExpansionPlugin",
}


def normalise_type(kind, raw):
    """Return (type_name, module) for a reflected-symbol tail."""
    raw = re.split(r"_Statics|_CRC|_NoRegister", raw)[0]
    if raw.endswith("v"):
        raw = raw[:-1]           # local forms end with a trailing 'v'
    if kind == "Class":
        return raw, ""           # no module component
    # Enum / Struct / Interface: <Module>_<TypeName>
    head, _, tail = raw.partition("_")
    if tail and (head in ENGINE_MODULES or head[:1].isupper()):
        return tail, head
    return raw, ""


def split_class_func(body):
    """ATRARCamera_SetCameraMode -> (ATRARCamera, SetCameraMode)."""
    if "_" not in body:
        return body, "<ctor>"
    return body.split("_", 1)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("lib", help="libUE4.so (or .dll/.dylib)")
    ap.add_argument("outdir", help="output directory")
    ap.add_argument("--class-prefix", default="",
                    help="comma-separated brand/project prefixes for APP classes, e.g. 'TR,FF'")
    ap.add_argument("--all-classes", action="store_true",
                    help="treat every reflected type as app code")
    args = ap.parse_args()

    syms, how = read_symbols(args.lib)
    if not syms:
        print("ERROR: no symbols found -- binary is stripped?", file=sys.stderr)
        return 1
    print("symbols: %d (via %s)" % (len(syms), how), file=sys.stderr)
    os.makedirs(args.outdir, exist_ok=True)
    json.dump(syms, open(os.path.join(args.outdir, "dynsym.json"), "w"))

    types = collections.Counter()
    modules = collections.Counter()
    for s in syms:
        m = RX_TYPE.match(s["n"])
        if m:
            name, mod = normalise_type(m.group(1), m.group(2))
            if not name:
                continue
            types[(m.group(1), name)] += 1
            if mod:
                modules[mod] += 1

    funcs = collections.defaultdict(lambda: collections.defaultdict(set))
    props = collections.defaultdict(set)
    for s in syms:
        m = RX_FUNC_PARAM.match(s["n"])
        if m:
            cls, fn = split_class_func(m.group(1))
            funcs[cls][fn].add(m.group(2))
            continue
        m = RX_CLASS_PROP.match(s["n"])
        if m:
            props[m.group(1).split("_Statics")[0]].add(m.group(2))

    known = set(funcs) | set(props) | {name for _k, name in types}
    # UE4 type names carry a kind letter first: UFFHand, ATRBoxTraceButton, FTRGalleryItemData.
    # Users naturally supply the BRAND prefix ("TR", "FF"), so compare after that letter too.
    brands = tuple(b for b in (x.strip() for x in args.class_prefix.split(",")) if b)

    def is_app(name):
        if not brands:
            return True
        return any(
            name.startswith(b) or name[1:].startswith(b)
            for b in brands
        )

    if args.all_classes or not brands:
        app = set(known)
    else:
        app = {c for c in known if is_app(c)}

    app_funcs = {c: {f: sorted(ps) for f, ps in funcs[c].items()} for c in app if c in funcs}
    app_props = {c: sorted(ps) for c, ps in props.items() if c in app}

    json.dump(sorted(app), open(os.path.join(args.outdir, "game-classes.json"), "w"), indent=1)
    json.dump(app_funcs, open(os.path.join(args.outdir, "game-blueprint-functions.json"), "w"), indent=1)
    json.dump(app_props, open(os.path.join(args.outdir, "game-properties.json"), "w"), indent=1)
    json.dump(
        sorted(
            [{"kind": k, "name": n} for k, n in types],
            key=lambda x: (x["kind"], x["name"]),
        ),
        open(os.path.join(args.outdir, "reflected-types.json"), "w"), indent=1,
    )

    rows = []
    for s in syms:
        n = s["n"]
        if not n.startswith("_Z") or s["s"] <= 0:
            continue
        if any(mk in n for mk in REFLECT_MARKERS):
            continue
        cls = next((c for c in app if c in n), None)
        if cls:
            rows.append("%x|%s$$%s" % (s["v"], cls, n))
    rows.sort(key=lambda r: int(r.split("|", 1)[0], 16))
    with open(os.path.join(args.outdir, "symbols_map.txt"), "w") as fh:
        fh.write("\n".join(rows))

    if modules:
        appmods = [(m, c) for m, c in modules.most_common() if m not in ENGINE_MODULES]
        if appmods:
            print("app modules (non-engine): %s"
                  % ", ".join("%s(%d)" % (m, c) for m, c in appmods[:5]), file=sys.stderr)
    kinds = collections.Counter(k for k, _n in types)
    print("reflected types: %d  (%s)"
          % (len(types), ", ".join("%s=%d" % (k, c) for k, c in kinds.most_common())),
          file=sys.stderr)
    print("app classes: %d" % len(app), file=sys.stderr)
    print("blueprint functions: %d across %d classes"
          % (sum(len(v) for v in app_funcs.values()), len(app_funcs)), file=sys.stderr)
    print("properties: %d across %d classes"
          % (sum(len(v) for v in app_props.values()), len(app_props)), file=sys.stderr)
    print("decompilable methods: %d -> symbols_map.txt" % len(rows), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())