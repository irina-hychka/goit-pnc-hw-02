#!/usr/bin/env python3
"""
Vigenere cryptanalysis (no key): Kasiski + Friedman + chi-square scoring.
Usage:
  python vigenere/level2/run_attack.py \
    --in vigenere/level1/output/cipher.txt \
    --out vigenere/level2/output/decrypted_auto.txt \
    --report vigenere/level2/output/report.txt
Options:
  --max-k  2..40 (default 24) : maximum key length to consider
  --top    N (default 6)      : how many key-length candidates to try
"""

import argparse, os, math, string, collections

EN = string.ascii_uppercase  # 'A'..'Z'
IDX = {ch: i for i, ch in enumerate(EN)}  # {'A':0..}
ENG_FREQ = {
    # English letter frequency (%) normalized to sum=1.0
    "A": 0.08167,
    "B": 0.01492,
    "C": 0.02782,
    "D": 0.04253,
    "E": 0.12702,
    "F": 0.02228,
    "G": 0.02015,
    "H": 0.06094,
    "I": 0.06966,
    "J": 0.00153,
    "K": 0.00772,
    "L": 0.04025,
    "M": 0.02406,
    "N": 0.06749,
    "O": 0.07507,
    "P": 0.01929,
    "Q": 0.00095,
    "R": 0.05987,
    "S": 0.06327,
    "T": 0.09056,
    "U": 0.02758,
    "V": 0.00978,
    "W": 0.02360,
    "X": 0.00150,
    "Y": 0.01974,
    "Z": 0.00074,
}


# ---------- IO helpers ----------
def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def write_text(path: str, data: str) -> None:
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)


def is_letter(ch: str) -> bool:
    return ch.upper() in IDX


# ---------- Level1-compatible encrypt/decrypt (for final decode) ----------
def key_shifts(key: str):
    shifts = [IDX[ch] for ch in key.upper() if ch in IDX]
    if not shifts:
        raise ValueError("Key must contain at least one A-Z letter.")
    return shifts


def vigenere_decrypt(cipher: str, key: str) -> str:
    shifts = key_shifts(key)
    out, si = [], 0
    for ch in cipher:
        if is_letter(ch):
            c = IDX[ch.upper()]
            k = shifts[si % len(shifts)]
            p = (c - k) % 26
            out_ch = EN[p]
            if ch.islower():
                out_ch = out_ch.lower()
            out.append(out_ch)
            si += 1
        else:
            out.append(ch)
    return "".join(out)


# ---------- Friedman test ----------
def friedman_keylen_estimate(txt_only_letters: str, max_k: int) -> int:
    # Index of Coincidence
    N = len(txt_only_letters)
    if N < 2:
        return 1
    counts = collections.Counter(txt_only_letters)
    ic = sum(n * (n - 1) for n in counts.values()) / (N * (N - 1))
    # standard Friedman estimate for English
    # k ≈ (0.027*N) / ((N-1)*IC - 0.038*N + 0.065)
    denom = (N - 1) * ic - 0.038 * N + 0.065
    if denom <= 0:
        return 1
    k = round((0.027 * N) / denom)
    return max(1, min(max_k, k))


# ---------- Kasiski examination ----------
def kasiski_candidates(txt_only_letters: str, max_k: int, min_len=3, max_len_rep=5):
    # find repeated n-grams and their spacings
    spacings = []
    for L in range(min_len, max_len_rep + 1):
        seen = {}
        for i in range(0, len(txt_only_letters) - L + 1):
            g = txt_only_letters[i : i + L]
            if g in seen:
                spacings.append(i - seen[g])
            else:
                seen[g] = i
    # score key lengths by how many spacings are divisible by candidate
    scores = collections.Counter()
    for s in spacings:
        for k in range(2, max_k + 1):
            if s % k == 0:
                scores[k] += 1
    # return sorted candidates (best first)
    return [k for k, _ in scores.most_common()]


# ---------- Chi-square scoring for a Caesar shift ----------
def chi_square_for_shift(col_letters: str, shift: int) -> float:
    # shift the column back by 'shift' (i.e., test that key letter == shift)
    N = len(col_letters)
    if N == 0:
        return float("inf")
    counts = [0] * 26
    for ch in col_letters:
        p = (IDX[ch] - shift) % 26
        counts[p] += 1
    # expected counts by English frequencies
    chi = 0.0
    for i, cnt in enumerate(counts):
        exp = ENG_FREQ[EN[i]] * N
        if exp > 0:
            chi += (cnt - exp) ** 2 / exp
    return chi


def recover_key_for_len(txt_only_letters: str, key_len: int) -> (str, float):
    # split into columns by position mod key_len and solve Caesar per column
    cols = ["" for _ in range(key_len)]
    for i, ch in enumerate(txt_only_letters):
        cols[i % key_len] += ch
    key_shifts_found = []
    chis = []
    for col in cols:
        best_s, best_chi = 0, float("inf")
        for s in range(26):
            val = chi_square_for_shift(col, s)
            if val < best_chi:
                best_chi = val
                best_s = s
        key_shifts_found.append(best_s)
        chis.append(best_chi)
    key = "".join(EN[s] for s in key_shifts_found)
    score = sum(chis) / len(chis)  # lower is better
    return key, score


# ---------- Orchestrator ----------
def attack(cipher: str, max_k: int = 24, top: int = 6):
    # analysis uses uppercase letters only
    letters_only = [ch.upper() for ch in cipher if is_letter(ch)]
    T = "".join(letters_only)

    friedman_k = friedman_keylen_estimate(T, max_k)
    kasiski = kasiski_candidates(T, max_k)

    # build candidate list: Friedman first, then Kasiski, then neighbors
    candidates = []
    # primary from Friedman ±1 neighborhood
    for k in (friedman_k - 1, friedman_k, friedman_k + 1):
        if 1 <= k <= max_k:
            candidates.append(k)
    # add top kasiski
    for k in kasiski:
        candidates.append(k)
    # de-dup, keep order
    seen = set()
    uniq = []
    for k in candidates:
        if k not in seen:
            uniq.append(k)
            seen.add(k)
    candidates = [k for k in uniq if 1 <= k <= max_k]

    # try each candidate length and pick the key with minimal chi-square
    trials = []
    for k in candidates:
        key, score = recover_key_for_len(T, k)
        trials.append((k, key, score))
    trials.sort(key=lambda x: x[2])  # by score asc

    best_k, best_key, best_score = trials[0]
    return {
        "friedman_k": friedman_k,
        "kasiski_top": kasiski[:10],
        "candidates": trials,
        "best_k": best_k,
        "best_key": best_key,
        "best_score": best_score,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", required=True)
    ap.add_argument("--out", dest="out_path", required=True)
    ap.add_argument("--report", dest="report_path", required=False)
    ap.add_argument("--max-k", dest="max_k", type=int, default=24)
    ap.add_argument("--top", dest="top", type=int, default=6)
    args = ap.parse_args()

    cipher = read_text(args.in_path)

    res = attack(cipher, max_k=args.max_k, top=args.top)
    key = res["best_key"]
    plain = vigenere_decrypt(cipher, key)

    write_text(args.out_path, plain)

    # optional report
    lines = []
    lines.append("[Vigenere attack report]")
    lines.append(f"Best key length: {res['best_k']}")
    lines.append(f"Recovered key  : {res['best_key']}")
    lines.append(f"Score (chi²)   : {res['best_score']:.3f}")
    lines.append("")
    lines.append(f"Friedman estimate: k ≈ {res['friedman_k']}")
    lines.append(
        "Kasiski top (by spacing divisibility): "
        + ", ".join(map(str, res["kasiski_top"]))
    )
    lines.append("")
    lines.append("Tried candidates (k, KEY, score):")
    for k, kkey, sc in res["candidates"]:
        lines.append(f"  {k:>2}  {kkey:<20}  {sc:.3f}")
    lines.append("")
    lines.append(f"Output written: {args.out_path}")

    rep = "\n".join(lines)
    if args.report_path:
        write_text(args.report_path, rep)
    print(rep)


if __name__ == "__main__":
    main()
