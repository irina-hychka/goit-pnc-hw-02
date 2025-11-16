"""
Vigenere encryption — keeps original letter case.
Usage:
  python vigenere/level1/run_encrypt.py --in data/source.txt --out vigenere/level1/output/cipher.txt --key CRYPTOGRAPHY
"""
import argparse, os, string

def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def write_text(path: str, data: str) -> None:
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)

EN = string.ascii_uppercase                 # 'A'..'Z'
IDX = {ch: i for i, ch in enumerate(EN)}    # {'A':0, ... 'Z':25}

def is_letter(ch: str) -> bool:
    return ch.upper() in IDX

def key_shifts(key: str):
    shifts = [IDX[ch] for ch in key.upper() if ch in IDX]
    if not shifts:
        raise ValueError("Key must contain at least one A-Z letter.")
    return shifts

def vigenere_encrypt(plain: str, key: str) -> str:
    shifts = key_shifts(key)
    out = []
    si = 0
    for ch in plain:
        if is_letter(ch):
            p = IDX[ch.upper()]
            k = shifts[si % len(shifts)]
            c = (p + k) % 26
            out_ch = EN[c]
            # preserve original case
            if ch.islower():
                out_ch = out_ch.lower()
            out.append(out_ch)
            si += 1
        else:
            out.append(ch)
    return "".join(out)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", required=True)
    ap.add_argument("--out", dest="out_path", required=True)
    ap.add_argument("--key", dest="key", required=True)
    args = ap.parse_args()

    plain = read_text(args.in_path)
    cipher = vigenere_encrypt(plain, args.key)
    write_text(args.out_path, cipher)
    print(f"[OK] Encrypted -> {args.out_path}")

if __name__ == "__main__":
    main()
