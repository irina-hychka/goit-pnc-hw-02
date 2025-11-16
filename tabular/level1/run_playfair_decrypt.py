#!/usr/bin/env python3
"""
Keyword (tabular) substitution — decryption. Matches level1 encrypt.
Adds optional --report and --verify (path to original plain text).

Usage:
  python tabular/level1/run_decrypt.py \
    --in tabular/level1/output/cipher.txt \
    --out tabular/level1/output/decrypted.txt \
    --key MATRIX \
    --report tabular/level1/output/report.txt \
    --verify data/source.txt
"""
import argparse, os, string, hashlib

EN = string.ascii_uppercase


def read_text(p):
    with open(p, "r", encoding="utf-8") as f:
        return f.read()


def write_text(p, s):
    d = os.path.dirname(p)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(s)


def md5(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def build_cipher_alphabet(key: str) -> str:
    key = "".join(ch for ch in key.upper() if ch in EN)
    seen, out = set(), []
    for ch in key:
        if ch not in seen:
            seen.add(ch)
            out.append(ch)
    for ch in EN:
        if ch not in seen:
            out.append(ch)
    return "".join(out)


def decrypt(cipher: str, key: str) -> str:
    sub = build_cipher_alphabet(key)
    dec_map = {c: p for p, c in zip(EN, sub)}
    out = []
    for ch in cipher:
        u = ch.upper()
        if u in dec_map:
            t = dec_map[u]
            out.append(t.lower() if ch.islower() else t)
        else:
            out.append(ch)
    return "".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", required=True, dest="in_path")
    ap.add_argument("--out", required=True, dest="out_path")
    ap.add_argument("--key", default="MATRIX")
    ap.add_argument("--report", dest="report_path")
    ap.add_argument("--verify", dest="verify_path")
    a = ap.parse_args()

    cipher = read_text(a.in_path)
    plain = decrypt(cipher, a.key)
    write_text(a.out_path, plain)
    print(f"[OK] Decrypted -> {a.out_path}")

    if a.report_path:
        sub = build_cipher_alphabet(a.key)
        lines = []
        lines.append("[Tabular Level1 Report]")
        lines.append(f"Key            : {a.key}")
        lines.append(f"Cipher alphabet: {sub}")
        lines.append(f"Input length   : {len(cipher)}")
        lines.append(f"Output length  : {len(plain)}")
        if a.verify_path and os.path.exists(a.verify_path):
            orig = read_text(a.verify_path)
            same = orig == plain
            lines.append(f"Verify against : {a.verify_path}")
            lines.append(f"MD5(original)  : {md5(orig)}")
            lines.append(f"MD5(decrypted) : {md5(plain)}")
            lines.append(f"Match          : {same}")
        write_text(a.report_path, "\n".join(lines))
        print(f"[OK] Report -> {a.report_path}")


if __name__ == "__main__":
    main()
