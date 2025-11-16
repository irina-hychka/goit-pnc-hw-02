"""
Vigenere decryption — keeps original letter case of the ciphertext.
Usage:
  python vigenere/level1/run_decrypt.py --in vigenere/level1/output/cipher.txt --out vigenere/level1/output/decrypted.txt --key CRYPTOGRAPHY
"""
import argparse, os, sys, string

def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def write_text(path: str, data: str) -> None:
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)

def file_exists(path: str) -> bool:
    return os.path.exists(path)

EN = string.ascii_uppercase
IDX = {ch: i for i, ch in enumerate(EN)}

def is_letter(ch: str) -> bool:
    return ch.upper() in IDX

def key_shifts(key: str):
    shifts = [IDX[ch] for ch in key.upper() if ch in IDX]
    if not shifts:
        raise ValueError("Key must contain at least one A-Z letter.")
    return shifts

def vigenere_decrypt(cipher: str, key: str) -> str:
    shifts = key_shifts(key)
    out = []
    si = 0
    for ch in cipher:
        if is_letter(ch):
            c = IDX[ch.upper()]
            k = shifts[si % len(shifts)]
            p = (c - k) % 26
            out_ch = EN[p]
            # preserve original case as in cipher char
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

    if not file_exists(args.in_path):
        print(f"[ERROR] Ciphertext not found: {args.in_path}\n"
              f"        Run the encrypt step first to create it.")
        sys.exit(1)

    cipher = read_text(args.in_path)
    plain = vigenere_decrypt(cipher, args.key)
    write_text(args.out_path, plain)
    print(f"[OK] Decrypted -> {args.out_path}")

if __name__ == "__main__":
    main()
