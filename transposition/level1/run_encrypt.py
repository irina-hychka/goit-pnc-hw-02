#!/usr/bin/env python3
"""
Simple Columnar Transposition (encryption). Keeps ALL characters; no stripping.
Row-wise fill, column-wise read using key order derived from a phrase.

Usage:
  python transposition/level1/run_encrypt.py \
    --in data/source.txt \
    --out transposition/level1/output/cipher.txt \
    --key SECRET
"""
import argparse, os, string, math


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
    """
    Turn key into a permutation of column indices.
    Stable sort by (char_upper, original_index) -> returns list of column idx in read order.
    """
    pairs = [(ch.upper(), i) for i, ch in enumerate(key)]
    order = sorted(range(len(pairs)), key=lambda i: (pairs[i][0], pairs[i][1]))
    return order  # e.g., [2,0,3,1]


def col_lengths(text_len: int, ncols: int):
    """
    For row-wise fill of length L into ncols columns, last row may be short.
    Columns [0..full_cols-1] have 'rows' chars; others have 'rows-1'.
    """
    rows = math.ceil(text_len / max(1, ncols))
    if ncols == 0:
        return [], 0
    full_cols = text_len % ncols
    if full_cols == 0:
        return [rows] * ncols, rows
    lens = [rows if i < full_cols else rows - 1 for i in range(ncols)]
    return lens, rows


def encrypt(text: str, key: str) -> str:
    n = len(key)
    if n == 0:
        raise ValueError("Key must not be empty.")
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
    ap.add_argument("--key", dest="key", default="SECRET")
    args = ap.parse_args()

    plain = read_text(args.in_path)
    cipher = encrypt(plain, args.key)
    write_text(args.out_path, cipher)
    print(f"[OK] Encrypted -> {args.out_path}")


if __name__ == "__main__":
    main()
