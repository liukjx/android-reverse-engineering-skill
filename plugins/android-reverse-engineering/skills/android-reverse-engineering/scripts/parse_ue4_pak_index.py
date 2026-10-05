#!/usr/bin/env python3
"""Parse a UE4/UE5 .pak index WITHOUT needing the AES key.

The pak INDEX is normally plaintext even when the entry DATA is AES-encrypted, so every
asset path / offset / size is recoverable. This is the tool to reach for when repak panics
(repak 0.2.3 can raise "index out of bounds" in entry.rs on some v5 paks).

Layout notes, verified field-by-field against a shipping UE4.20, pak v5 build:

  FOOTER (last 44 bytes of the file -- do NOT rfind the magic; 0x5A6F12E1 also occurs
          inside entry headers and you will read garbage if you scan for it):
      i32 Magic (0x5A6F12E1) | i32 Version | i64 IndexOffset | i64 IndexSize | byte[20] IndexHash
      SHA1(index_bytes) == IndexHash  <=>  index is plaintext

  ENTRY (v5):
      i32 nameLen | name[nameLen] | i64 Offset | i64 CompressedSize | i64 UncompressedSize
      | i32 CompressionMethod (4=LZ4, 0=stored) | byte[20] Hash
      | if CompressionMethod != 0: i32 BlockCount + BlockCount*(i64 CompressedSize, i64 UncompressedSize)
      | byte[5] tail flags
      NOTE: there is NO CompressionBlockSize field in this version.

Usage:
    python3 parse_ue4_pak_index.py <pak> [--out pak-index.json] [--list] [--verify]

Exit codes: 0 ok, 2 index/data encrypted and unreadable.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import struct
import sys

PAK_MAGIC = 0x5A6F12E1
FOOTER_SIZE = 44


def read_footer(fh, size):
    """Read FPakInfo from the last 44 bytes. Returns a dict."""
    if size < FOOTER_SIZE:
        raise SystemExit("file too small to be a pak")
    fh.seek(size - FOOTER_SIZE)
    buf = fh.read(FOOTER_SIZE)
    magic, version, index_offset, index_size = struct.unpack_from("<iiqq", buf, 0)
    if magic != PAK_MAGIC:
        raise SystemExit(
            "footer magic 0x%08X not found at EOF-44 -- not a v4/v5 pak, or a different layout" % magic
        )
    return {
        "magic": magic,
        "version": version,
        "index_offset": index_offset,
        "index_size": index_size,
        "index_hash": buf[24:44].hex(),
    }


def parse_index(idx, footer):
    """Walk the index. Returns (mount_point, entries)."""
    pos = 0
    n = len(idx)

    def i32():
        nonlocal pos
        v = struct.unpack_from("<i", idx, pos)[0]
        pos += 4
        return v

    def i64():
        nonlocal pos
        v = struct.unpack_from("<q", idx, pos)[0]
        pos += 8
        return v

    def fstr():
        nonlocal pos
        ln = i32()
        if ln <= 0:
            return ""
        s = idx[pos:pos + ln - 1].decode("utf-8", errors="replace")
        pos += ln
        return s

    mount = fstr()
    count = i32()

    entries = []
    for k in range(count):
        if pos >= n:
            raise SystemExit("index truncated after %d of %d entries" % (k, count))
        name = fstr()
        offset = i64()
        csize = i64()
        usize = i64()
        comp = i32()
        pos += 20                                  # Hash[20]
        nblocks = 0
        if comp != 0:
            nblocks = i32()
            pos += 16 * nblocks                    # FPakCompressedBlock[]
        pos += 5                                   # tail flags
        entries.append({
            "path": name, "offset": offset,
            "csize": csize, "usize": usize,
            "comp": comp, "nblocks": nblocks,
        })
    return mount, entries, pos


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("pak");
    ap.add_argument("--out", default="pak-index.json")
    ap.add_argument("--list", action="store_true", help="print entry paths to stdout")
    args = ap.parse_args()

    size = os.path.getsize(args.pak)
    with open(args.pak, "rb") as fh:
        footer = read_footer(fh, size)
        fh.seek(footer["index_offset"])
        idx = fh.read(footer["index_size"])

    if len(idx) != footer["index_size"]:
        raise SystemExit("short read on index")

    sha = hashlib.sha1(idx).hexdigest()
    index_plain = (sha == footer["index_hash"])

    print("pak size     : %d" % size, file=sys.stderr)
    print("pak version  : %d (footer @ EOF-%d)" % (footer["version"], FOOTER_SIZE), file=sys.stderr)
    print("index offset : %d" % footer["index_offset"], file=sys.stderr)
    print("index size   : %d" % footer["index_size"], file=sys.stderr)
    print("index SHA1   : %s" % sha, file=sys.stderr)
    print("footer hash  : %s" % footer["index_hash"], file=sys.stderr)
    print("index plaintext: %s" % index_plain, file=sys.stderr)

    if not index_plain:
        print("ERROR: index is ENCRYPTED -- you need the AES key (--aes-key in repak).",
              file=sys.stderr)
        return 2

    try:
        mount, entries, consumed = parse_index(idx, footer)
    except SystemExit as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        print("       the index may be a different revision; try repak list instead.",
              file=sys.stderr)
        return 2

    print("mount point  : %r" % mount, file=sys.stderr)
    print("entries      : %d" % len(entries), file=sys.stderr)
    print("index consumed: %d / %d (delta %d)" % (consumed, len(idx), len(idx) - consumed),
          file=sys.stderr)
    if abs(len(idx) - consumed) > 8:
        print("WARNING: cursor did not land on the index end -- results may be partial",
              file=sys.stderr)

    comp_hist = collections.Counter(e["comp"] for e in entries)
    ext_hist = collections.Counter(os.path.splitext(e["path"])[1].lower() for e in entries)
    total_u = sum(e["usize"] for e in entries)
    total_c = sum(e["csize"] for e in entries)

    print("compression  : %s" % dict(comp_hist), file=sys.stderr)
    print("total usize  : %d (%.1f MB)" % (total_u, total_u / 1048576), file=sys.stderr)
    print("total csize  : %d (%.1f MB)" % (total_c, total_c / 1048576), file=sys.stderr)
    print("top ext      : %s"
          % ", ".join("%s=%d" % (k or "(none)", v) for k, v in ext_hist.most_common(10)),
          file=sys.stderr)

    payload = {
        "pak": args.pak,
        "size": size,
        "footer": footer,
        "index_plaintext": index_plain,
        "mount_point": mount,
        "entry_count": len(entries),
        "compression_histogram": {str(k): v for k, v in comp_hist.items()},
        "extension_histogram": {k: v for k, v in ext_hist.most_common()},
        "total_uncompressed_bytes": total_u,
        "total_compressed_bytes": total_c,
        "entries": entries,
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=1)
    print("wrote %s" % args.out, file=sys.stderr)

    # Reminder: index plaintext does NOT imply payloads are readable.
    print("NOTE: index readability says nothing about DATA. If the payload bytes at an",
          file=sys.stderr)
    print("      entry offset are not the expected format, the data section is encrypted.",
          file=sys.stderr)

    if args.list:
        for e in entries:
            print(e["path"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
