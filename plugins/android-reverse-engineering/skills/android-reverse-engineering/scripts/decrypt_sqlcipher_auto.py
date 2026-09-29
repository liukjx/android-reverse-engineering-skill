#!/usr/bin/env python3
"""
SQLCipher 加密 SQLite 通用解密工具（配合 skill 的 IL2CPP 逆向流程使用）。

方法论（Mondly VR 实战验证，app.db + content.sqlite 双库解密成功）:
  1. 找密钥: 反编译产物里 grep 加密库打开路径（SetKey/SQLiteConnection ctor/Secrets*）。
     密钥若在 Odin SerializedScriptableObject（Unity typetree 不可见），用 UnityPy 导出
     该 MonoBehaviour 的 raw_data，按 UTF-16LE 提取键值对（Odin 二进制串是 UTF-16）。
  2. 定格式: 网格搜索 page_size × KDF(sha512/sha1) × iters × IV 位置。
     验证依据: page1 明文恢复 SQLite 头（偏移 16 起）: 页大小 BE + 64/32/32 payload 字节。
  3. 布局: page1 = [盐 16][CT ...][IV 16][HMAC]; 其余页 = [CT ...][IV 16][HMAC]（v3 型，
     IV 在尾）；v4 型 IV 在头。全页 IV/HMAC 起止一致，CT 区 16 对齐。
     重建: page1 头 16 字节复写为 "SQLite format 3\\0"，尾补零到 page_size。

用法: python decrypt_sqlcipher_auto.py <加密库> <密钥> <输出.sqlite>
"""
import sys, hashlib, sqlite3
from Crypto.Cipher import AES


def header_ok(pt, ps):
    exp = (1, 0) if ps == 65536 else (ps >> 8, ps & 0xFF)
    return pt[0] == exp[0] and pt[1] == exp[1] and pt[5] == 64 and pt[6] == 32 and pt[7] == 32


def find_format(data, passphrase: bytes):
    """返回 (key, ps, iv_page1, iv_off, ct1_start, ct1_len, algo, iters, family)"""
    for ps in (4096, 1024, 2048, 8192, 512):
        page = data[:ps]
        salt = page[:16]
        for algo in ("sha512", "sha1"):
            for iters in (256000, 64000, 4000):
                key = hashlib.pbkdf2_hmac(algo, passphrase, salt, iters, dklen=32)
                cands = []
                # v4 型: IV 在头。page1: [盐16][IV16][CT..]; 其余页: [IV16][CT..]
                for h in (64, 32, 20):
                    end = ((ps - h) // 16) * 16
                    cands.append(("v4", page[16:32], 32, end, ps - end))       # p1 ct=[32:end]
                    cands.append(("v4", page[0:16], 16, end, ps - end))        # 数据页 ct=[16:end]
                # v3 型: IV 在尾。page1: [盐16][CT..ct_end][IV16][HMAC h]; 其余页整体前移16
                for h in (64, 32, 20):
                    iv1 = page[ps-h-16:ps-h]
                    end1 = ps - h - 16                       # page1 CT 终点
                    cands.append((f"v3h{h}", iv1, 16, end1, 0))
                    cands.append((f"v3h{h}", iv1, 0, end1, 0))  # 数据页: CT=[0:end1-16] 实际终点 end1-16
                for fam, iv, c1s, c1e, _ in cands:
                    ct_len = ((c1e - c1s) // 16) * 16
                    if ct_len <= 0:
                        continue
                    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(page[c1s:c1s+ct_len])
                    if header_ok(pt, ps):
                        return key, ps, c1s, c1e, fam, algo, iters
    return None


def decrypt(src, out, passphrase: bytes):
    data = open(src, "rb").read()
    fmt = find_format(data, passphrase)
    if not fmt:
        print("[-] no format/key matched")
        return False
    key, ps, c1s, c1e, fam, algo, iters = fmt
    print(f"[+] format: page={ps} kdf={algo}/{iters} family={fam} "
          f"page1_ct=[{c1s}:{c1e}] ({c1e-c1s}B)")
    with open(out, "wb") as f:
        n = 0
        while (n + 1) * ps <= len(data):
            page = data[n*ps:(n+1)*ps]
            if fam == "v4":
                iv, cs, ce = (page[16:32], 32, c1e) if n == 0 else (page[0:16], 16, c1e)
            else:  # v3 型: IV 在 [c1e : c1e+16]，CT 终点页 1 与数据页一致（数据页无盐，起点前移）
                iv = page[c1e:c1e+16]
                cs, ce = (c1s, c1e) if n == 0 else (0, c1e)
            ct_len = ((ce - cs) // 16) * 16
            plain = AES.new(key, AES.MODE_CBC, iv).decrypt(page[cs:cs+ct_len])
            if n == 0:
                f.write(b"SQLite format 3\x00" + plain + b"\x00" * (ps - 16 - ct_len))
            else:
                f.write(plain + b"\x00" * (ps - ce))
            n += 1
    con = sqlite3.connect(out)
    tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    print(f"[+] decrypted {n} pages, {len(tables)} tables -> {out}")
    for t in tables[:25]:
        try:
            cnt = con.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
            print(f"    {t}: {cnt} rows")
        except Exception as e:
            print(f"    {t}: {e}")
    con.close()
    return True


if __name__ == "__main__":
    decrypt(sys.argv[1], sys.argv[3], sys.argv[2].encode())
