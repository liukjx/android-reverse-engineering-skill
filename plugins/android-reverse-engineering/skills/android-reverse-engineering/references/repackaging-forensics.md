# Repackaging & Instrumentation Forensics

Companion to **Phase 0c** in SKILL.md.

A large share of APKs found outside official store channels are repackaged, and some carry an
injected instrumentation framework (most commonly Frida Gadget). This matters for *interpretation*:
an injected hooking layer is evidence about the crack, **not** about the app. Attributing its
behaviour to the game is the single easiest way to produce a wrong report.

Everything below was verified on a real repackaged UE4 VR title.

---

## 1. Why you must check this early

- It changes what your findings *mean* (game logic vs. crack logic).
- It changes what you can trust (a hooking layer can alter runtime behaviour, so the shipped binary
  is not necessarily what the developer shipped).
- It is cheap to check: three commands, done in under a minute.

---

## 2. Signal 1 - a native library that does not belong

Start by listing what ships:

    unzip -l app.apk | grep '\.so$'

Then ask two questions about every library that is not obviously engine or vendor SDK:

**(a) Is it even an ELF?**

    python -c "
    import zipfile
    z = zipfile.ZipFile('app.apk')
    for n in z.namelist():
        if n.endswith('.so'):
            head = z.read(n)[:4]
            if head != b'\x7fELF':
                print('NOT ELF:', n, head)
    "

Files named `.so` that are not ELF are payload carriers. Seen in the wild:

| Content | Head bytes | What it really is |
|---|---|---|
| JavaScript | `b'var '` | an injected script (Frida `interaction.type=script`) |
| JSON | `b'{"in'` | a Frida Gadget **config file**, despite the `.so` name |

**(b) Does it link the engine?**

    python -c "
    from elftools.elf.elffile import ELFFile
    import sys
    with open(sys.argv[1],'rb') as f:
        e = ELFFile(f)
        for seg in e.iter_segments():
            if seg.header.p_type == 'PT_DYNAMIC':
                for t in seg.iter_tags():
                    if t.entry.d_tag == 'DT_SONAME':
                        print('SONAME ', t.soname)
                    elif t.entry.d_tag == 'DT_NEEDED':
                        print('NEEDED ', t.needed)
    " lib/arm64-v8a/<suspicious>.so

A 25 MB library whose `DT_SONAME` is `libfrida-gadget-raw.so` and whose only `DT_NEEDED` entries
are `libm`, `liblog`, `libdl`, `libc` is **not a game module**: it never links `libUE4.so`, so it is
an out-of-band injection layer.

Corroborating strings inside such a library point at its origin, e.g. `frida-gum`,
`subprojects/frida-core/...`, `frida:rpc`, `GumV8CallbackTransformer`, plus a bundled JS engine.

---

## 3. Signal 2 - signing identity

    keytool -printcert -jarfile app.apk 2>/dev/null | head -30

Red flags:

- `CN=localhost`, `OU=zz`, `O=zz` - an auto-generated debug identity, not a publisher
- 1024-bit RSA with `SHA1withRSA` - well below what a store submission uses
- a validity window starting at an odd date years after the app's real release

Also inspect the `META-INF/` layout: a `.SF`/`.RSA` pair named after a warez/aggregator brand
instead of the publisher confirms the package was re-signed.

Note what is **not** a signal: `android:debuggable="true"` on the Application node is the **UE4
template default**. Do not present it as tampering evidence.

---

## 4. Signal 3 - assets that do not belong to the app

    unzip -l app.apk | grep -E 'assets/(bin/)?[^/]*$' | head -40

Look for promotional/watermark files dropped alongside legitimate assets. On the reference build a
repacker had added five PNGs (all with an **identical SHA-256**, i.e. one image copied under
several names) plus a README text file, all into `assets/bin/` - a directory an official UE4 build
does not use for that.

    python -c "
    import zipfile, hashlib, collections
    z = zipfile.ZipFile('app.apk')
    h = collections.defaultdict(list)
    for n in z.namelist():
        if n.startswith('assets/bin/'):
            h[hashlib.sha256(z.read(n)).hexdigest()[:16]].append(n)
    for k, v in h.items():
        if len(v) > 1:
            print('duplicate content:', k, v)
    "

Also check `resources.arsc` for a rewritten `app_name` - a store listing string replaced with a
website URL is a giveaway.

---

## 5. Signal 4 - instrumentation config left in place

If a Frida Gadget was injected, its config often ships unencrypted next to it:

    python -c "
    import zipfile
    z = zipfile.ZipFile('app.apk')
    for n in z.namelist():
        if n.endswith('.so'):
            b = z.read(n)
            if b[:1] == b'{' and b'"interaction"' in b:
                print(n)
                print(b.decode('utf-8', 'replace'))
    "

A config listing which vendored SDKs to hook - e.g. `patch_ovrplatformloader`, `patch_vrapi`,
`hijack_responses` - tells you exactly what the crack attempts, without any further analysis.

Cross-reference it against the app's own entitlement code. On the reference build the config hooked
the Oculus platform loader and rewrote IAP responses, which matched the game's own
`GetEntitlementResult` / `HasEntitlementResult` calls: a licensing bypass.

Leftovers from other projects (a different app's package name, a hardcoded offset for a different
engine) prove the tool is generic rather than tailored.

---

## 6. Signal 5 - device-signature blobs

Some VR platforms ship per-device offline launch signatures (e.g. Oculus `oculussig_*`, 256 bytes
each). An official build contains the signature for **the buyer's own device** - typically one.
A repackaged build carrying dozens is provisioning many devices at once.

    unzip -l app.apk | grep -c oculussig

Count them and note the number; on the reference build it was 59, including Quest 1 serial-number
shaped identifiers.

---

## 7. Reporting rule

Keep two clearly separated tables and never blur them:

| Category | Members | How to describe it |
|---|---|---|
| **App / engine** | engine `.so`, vendor SDK `.so`, `classes.dex`, asset containers, signature blobs | normal analysis target |
| **Injected / repackaging** | hooking runtime, its config, its script, replaced signature, added promo files | evidence about the *distribution*, not the app |

Practical consequences to state explicitly in the report:

1. Findings about the injected layer describe the **crack**, and must not be presented as app behaviour.
2. Analysis of app logic should rest on the engine binary and the asset container.
3. If the app's own code was modified by the injection, say so; otherwise note that app code appears
   untouched.
4. Quote the evidence (hashes, `DT_SONAME`, certificate fields, file lists), not just the conclusion.

---

## 8. Quick triage script

    # 1. non-ELF files named .so
    python -c "import zipfile; z=zipfile.ZipFile('app.apk'); [print(n, z.read(n)[:4]) for n in z.namelist() if n.endswith('.so') and z.read(n)[:4]!=b'\x7fELF']"

    # 2. signing identity
    keytool -printcert -jarfile app.apk 2>/dev/null | head -20

    # 3. extra promo assets
    unzip -l app.apk | grep -iE 'vrmoo|\.png$|\.txt$' | head -20

    # 4. dev signatures
    unzip -l app.apk | grep -c oculussig

If (1) reports anything at all, stop and inspect those files before continuing - they will change
how you read every later result.
