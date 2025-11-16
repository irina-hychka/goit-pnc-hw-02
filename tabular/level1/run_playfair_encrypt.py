#!/usr/bin/env python3
"""
Keyword (tabular) substitution — encryption. Keeps original case and non-letters.
Usage:
  python tabular/level1/run_encrypt.py \
    --in data/source.txt \
    --out tabular/level1/output/cipher.txt \
    --key MATRIX
"""
import argparse, os, string

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


def build_cipher_alphabet(key: str) -> str:
    key = "".join(ch for ch in key.upper() if ch in EN)
    seen, uniq = set(), []
    for ch in key:
        if ch not in seen:
            seen.add(ch)
            uniq.append(ch)
    for ch in EN:
        if ch not in seen:
            uniq.append(ch)
    return "".join(uniq)  # 26 letters


def encrypt(plain: str, key: str) -> str:
    sub = build_cipher_alphabet(key)
    enc_map = {p: c for p, c in zip(EN, sub)}
    out = []
    for ch in plain:
        u = ch.upper()
        if u in enc_map:
            t = enc_map[u]
            out.append(t.lower() if ch.islower() else t)
        else:
            out.append(ch)
    return "".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", required=True, dest="in_path")
    ap.add_argument("--out", required=True, dest="out_path")
    ap.add_argument("--key", default="MATRIX")
    a = ap.parse_args()
    write_text(a.out_path, encrypt(read_text(a.in_path), a.key))
    print(f"[OK] Encrypted -> {a.out_path}")


if __name__ == "__main__":
    main()
