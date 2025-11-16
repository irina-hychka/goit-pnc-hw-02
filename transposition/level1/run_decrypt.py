#!/usr/bin/env python3
"""
Simple Columnar Transposition (decryption). Compatible with level1 encrypt.
Usage:
  python transposition/level1/run_decrypt.py \
    --in transposition/level1/output/cipher.txt \
    --out transposition/level1/output/decrypted.txt \
    --key SECRET
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
    order = sorted(range(len(pairs)), key=lambda i: (pairs[i][0], pairs[i][1]))
    return order


def col_lengths(text_len: int, ncols: int):
    rows = math.ceil(text_len / max(1, ncols))
    if ncols == 0:
        return [], 0
    full_cols = text_len % ncols
    if full_cols == 0:
        return [rows] * ncols, rows
    lens = [rows if i < full_cols else rows - 1 for i in range(ncols)]
    return lens, rows


def decrypt(cipher: str, key: str) -> str:
    n = len(key)
    if n == 0:
        raise ValueError("Key must not be empty.")
    order = key_order(key)  # sequence of column indices as read
    L = len(cipher)
    lens, rows = col_lengths(L, n)  # lengths for physical columns 0..n-1

    # slice cipher into columns in the order they were read
    cols = [""] * n
    pos = 0
    for col in order:
        k = lens[col]
        cols[col] = cipher[pos : pos + k]
        pos += k

    # read out row-wise to reconstruct original
    out = []
    for r in range(rows):
        for c in range(n):
            if r < len(cols[c]):
                out.append(cols[c][r])
    return "".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", required=True)
    ap.add_argument("--out", dest="out_path", required=True)
    ap.add_argument("--key", dest="key", default="SECRET")
    args = ap.parse_args()

    cipher = read_text(args.in_path)
    plain = decrypt(cipher, args.key)
    write_text(args.out_path, plain)
    print(f"[OK] Decrypted -> {args.out_path}")


if __name__ == "__main__":
    main()
