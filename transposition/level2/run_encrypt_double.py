#!/usr/bin/env python3
"""
Double Columnar Transposition (encryption): first KEY1 then KEY2.
Usage:
  python transposition/level2/run_encrypt.py \
    --in data/source.txt \
    --out transposition/level2/output/cipher.txt \
    --key1 SECRET --key2 CRYPTO
"""
import argparse, os, math


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def write_text(path: str, data: str) -> None:
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)


def key_order(key: str):
    pairs = [(ch.upper(), i) for i, ch in enumerate(key)]
    return sorted(range(len(pairs)), key=lambda i: (pairs[i][0], pairs[i][1]))


def col_lengths(text_len: int, ncols: int):
    rows = math.ceil(text_len / max(1, ncols))
    if ncols == 0:
        return [], 0
    full_cols = text_len % ncols
    if full_cols == 0:
        return [rows] * ncols, rows
    lens = [rows if i < full_cols else rows - 1 for i in range(ncols)]
    return lens, rows


def col_encrypt(text: str, key: str) -> str:
    n = len(key)
    order = key_order(key)
    L = len(text)
    _, rows = col_lengths(L, n)
    out = []
    for col in order:
        for r in range(rows):
            idx = r * n + col
            if idx < L:
                out.append(text[idx])
    return "".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", required=True)
    ap.add_argument("--out", dest="out_path", required=True)
    ap.add_argument("--key1", default="SECRET")
    ap.add_argument("--key2", default="CRYPTO")
    args = ap.parse_args()

    plain = read_text(args.in_path)
    once = col_encrypt(plain, args.key1)
    twice = col_encrypt(once, args.key2)
    write_text(args.out_path, twice)
    print(f"[OK] Double-encrypted -> {args.out_path}")


if __name__ == "__main__":
    main()
