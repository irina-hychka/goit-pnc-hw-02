#!/usr/bin/env python3
"""
Decrypt pipeline for Level 2: Tabular^-1 then Vigenere^-1.
Adds optional --report and --verify (path to original).

Usage:
  python tabular/level2/run_decrypt.py \
    --in tabular/level2/output/cipher.txt \
    --out tabular/level2/output/decrypted.txt \
    --vkey CRYPTOGRAPHY \
    --tkey CRYPTO \
    --report tabular/level2/output/report.txt \
    --verify data/source.txt
"""
import argparse, os, string, hashlib

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


def md5(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def is_letter(ch):
    return ch.upper() in IDX


def key_shifts(key: str):
    s = [IDX[ch] for ch in key.upper() if ch in IDX]
    if not s:
        raise ValueError("Vigenere key must have A-Z.")
    return s


def vigenere_decrypt(cipher: str, key: str) -> str:
    shifts = key_shifts(key)
    out = []
    si = 0
    for ch in cipher:
        if is_letter(ch):
            c = IDX[ch.upper()]
            k = shifts[si % len(shifts)]
            p = (c - k) % 26
            t = EN[p]
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


def tabular_decrypt(text: str, tkey: str) -> str:
    sub = build_tabular(tkey)
    mp = {c: p for p, c in zip(EN, sub)}  # inverse
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
    ap.add_argument("--report", dest="report_path")
    ap.add_argument("--verify", dest="verify_path")
    a = ap.parse_args()

    c = read_text(a.in_path)
    inter = tabular_decrypt(c, a.tkey)
    p = vigenere_decrypt(inter, a.vkey)
    write_text(a.out_path, p)
    print(f"[OK] Decrypted (Tabular -> Vigenere) -> {a.out_path}")

    if a.report_path:
        sub = build_tabular(a.tkey)
        lines = []
        lines.append("[Tabular Level2 Report]")
        lines.append(f"Vigenere key   : {a.vkey}")
        lines.append(f"Tabular key    : {a.tkey}")
        lines.append(f"Tabular alphabet: {sub}")
        lines.append(f"Cipher length  : {len(c)}")
        lines.append(f"Decrypted length: {len(p)}")
        if a.verify_path and os.path.exists(a.verify_path):
            orig = read_text(a.verify_path)
            same = orig == p
            lines.append(f"Verify against : {a.verify_path}")
            lines.append(f"MD5(original)  : {md5(orig)}")
            lines.append(f"MD5(decrypted) : {md5(p)}")
            lines.append(f"Match          : {same}")
        write_text(a.report_path, "\n".join(lines))
        print(f"[OK] Report -> {a.report_path}")


if __name__ == "__main__":
    main()
