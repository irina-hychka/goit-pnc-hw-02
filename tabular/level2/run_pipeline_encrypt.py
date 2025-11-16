#!/usr/bin/env python3
"""
Pipeline: Vigenere then Keyword(tabular) substitution.
Usage:
  python tabular/level2/run_encrypt.py \
    --in data/source.txt \
    --out tabular/level2/output/cipher.txt \
    --vkey CRYPTOGRAPHY \
    --tkey CRYPTO
"""
import argparse, os, string

EN = string.ascii_uppercase
IDX = {ch: i for i, ch in enumerate(EN)}


def read_text(p):
    with open(p, "r", encoding="utf-8") as f:
        return f.read()


def write_text(p, s):
    d = os.path.dirname(p)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(s)


def is_letter(ch):
    return ch.upper() in IDX


def key_shifts(key: str):
    s = [IDX[ch] for ch in key.upper() if ch in IDX]
    if not s:
        raise ValueError("Vigenere key must have A-Z.")
    return s


def vigenere_encrypt(plain: str, key: str) -> str:
    shifts = key_shifts(key)
    out = []
    si = 0
    for ch in plain:
        if is_letter(ch):
            p = IDX[ch.upper()]
            k = shifts[si % len(shifts)]
            c = (p + k) % 26
            t = EN[c]
            out.append(t.lower() if ch.islower() else t)
            si += 1
        else:
            out.append(ch)
    return "".join(out)


def build_tabular(key: str) -> str:
    key = "".join(ch for ch in key.upper() if ch in EN)
    seen = set()
    out = []
    for ch in key:
        if ch not in seen:
            seen.add(ch)
            out.append(ch)
    for ch in EN:
        if ch not in seen:
            out.append(ch)
    return "".join(out)


def tabular_encrypt(text: str, tkey: str) -> str:
    sub = build_tabular(tkey)
    mp = {p: c for p, c in zip(EN, sub)}
    out = []
    for ch in text:
        u = ch.upper()
        if u in mp:
            t = mp[u]
            out.append(t.lower() if ch.islower() else t)
        else:
            out.append(ch)
    return "".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", required=True, dest="in_path")
    ap.add_argument("--out", required=True, dest="out_path")
    ap.add_argument("--vkey", default="CRYPTOGRAPHY")
    ap.add_argument("--tkey", default="CRYPTO")
    a = ap.parse_args()

    p = read_text(a.in_path)
    inter = vigenere_encrypt(p, a.vkey)
    c = tabular_encrypt(inter, a.tkey)
    write_text(a.out_path, c)
    print(f"[OK] Encrypted (Vigenere -> Tabular) -> {a.out_path}")


if __name__ == "__main__":
    main()
