# Homework: *History and Examples of Classical Cryptographic Transformations*

This project contains implementations of classical ciphers, each organized into separate modules and difficulty levels.

All scripts operate through command-line arguments and use `data/source.txt` as their plaintext source.

---

## Project Structure

GOIT-PNC-HW-02
│
├── data
│   └── source.txt
│
├── vigenere
│   ├── level1
│   │   ├── output
│   │   │   ├── cipher.txt
│   │   │   └── decrypted.txt
│   │   ├── run_encrypt.py
│   │   └── run_decrypt.py
│   │
│   └── level2
│       ├── output
│       │   ├── decrypted_auto.txt
│       │   └── report.txt
│       └── run_attack.py
│
├── transposition
│   ├── level1
│   │   ├── output
│   │   │   ├── cipher.txt
│   │   │   └── decrypted.txt
│   │   ├── run_encrypt.py
│   │   └── run_decrypt.py
│   │
│   └── level2
│       ├── output
│       │   ├── cipher.txt
│       │   └── decrypted.txt
│       ├── run_encrypt_double.py
│       └── run_decrypt_double.py
│
├── tabular
│   ├── level1
│   │   ├── output
│   │   │   ├── cipher.txt
│   │   │   └── decrypted.txt
│   │   ├── run_playfair_encrypt.py
│   │   └── run_playfair_decrypt.py
│   │
│   └── level2
│       ├── output
│       │   ├── cipher.txt
│       │   └── decrypted.txt
│       ├── run_pipeline_encrypt.py
│       └── run_pipeline_decrypt.py
│
└── README.md

---

# Vigenere Cipher

## **Level 1 — Vigenère encryption/decryption (key: “CRYPTOGRAPHY”)**

**Purpose:**

Implement the classical Vigenère cipher while preserving letter case and punctuation.

**Encrypt**

```bash
python vigenere/level1/run_encrypt.py \
  --in data/source.txt \
  --out vigenere/level1/output/cipher.txt \
  --key CRYPTOGRAPHY
```

**Decrypt**

```bash
python vigenere/level1/run_decrypt.py \
  --in vigenere/level1/output/cipher.txt \
  --out vigenere/level1/output/decrypted.txt \
  --key CRYPTOGRAPHY
```
## **Level 2 — Cryptanalysis (Kasiski / Friedman test)**

**Purpose:**

Recover the Vigenère key and decrypt the text without knowing the key by applying classical frequency-based analysis.

```bash
python vigenere/level2/run_attack.py \
  --in vigenere/level1/output/cipher.txt \
  --out vigenere/level2/output/decrypted_auto.txt \
  --report vigenere/level2/output/report.txt
```

---

# **Transposition Cipher**

## **Level 1 — Simple columnar transposition (keyword: “SECRET”)**

**Purpose:**

Implement a basic columnar transposition cipher using a stable column ordering derived from the key.

### **Encrypt**

```bash
python transposition/level1/run_encrypt.py \
  --in data/source.txt \
  --out transposition/level1/output/cipher.txt \
  --key SECRET
```

### **Decrypt**

```bash
python transposition/level1/run_decrypt.py \
  --in transposition/level1/output/cipher.txt \
  --out transposition/level1/output/decrypted.txt \
  --key SECRET
```

## **Level 2 — Double transposition (“SECRET” → “CRYPTO”)**

**Purpose:**

Add a second encryption layer by applying two consecutive transpositions with different keys.

### **Encrypt (SECRET → CRYPTO)**

```bash
python transposition/level2/run_encrypt_double.py \
  --in data/source.txt \
  --out transposition/level2/output/cipher.txt \
  --key1 SECRET \
  --key2 CRYPTO
```
### **Decrypt (reverse order)**

```bash
python transposition/level2/run_decrypt_double.py \
  --in transposition/level2/output/cipher.txt \
  --out transposition/level2/output/decrypted.txt \
  --key1 SECRET \
  --key2 CRYPTO
```

---

# **Tabular Cipher (Keyword Substitution)**

## **Level 1 — Keyword-based substitution (key: “MATRIX”)**

**Purpose:**

Construct a substitution alphabet from the key and perform a monoalphabetic keyword cipher.

### **Encrypt**

```bash
python tabular/level1/run_playfair_encrypt.py \
  --in data/source.txt \
  --out tabular/level1/output/cipher.txt \
  --key MATRIX
```

### **Decrypt**

```bash
python tabular/level1/run_playfair_decrypt.py \
  --in tabular/level1/output/cipher.txt \
  --out tabular/level1/output/decrypted.txt \
  --key MATRIX
```

## **Level 2 — Pipeline: Vigenère → Tabular**

**Purpose:**

Apply a two-stage encryption pipeline:

- encrypt with Vigenère (CRYPTOGRAPHY),
- then apply keyword substitution (CRYPTO). Decryption reverses both steps.

### **Encrypt**

```bash
python tabular/level2/run_pipeline_encrypt.py \
  --in data/source.txt \
  --out tabular/level2/output/cipher.txt \
  --vkey CRYPTOGRAPHY \
  --tkey CRYPTO
```

### **Decrypt**

```bash
python tabular/level2/run_pipeline_decrypt.py \
  --in tabular/level2/output/cipher.txt \
  --out tabular/level2/output/decrypted.txt \
  --vkey CRYPTOGRAPHY \
  --tkey CRYPTO
```

# **Summary**

This project demonstrates:

- classical polyalphabetic encryption (Vigenère)
- classical transposition techniques
- keyword-based monoalphabetic substitution
- cryptanalysis via Kasiski & Friedman tests
- multi-stage encryption pipelines
- consistent file structure & CLI interface

All decryptions restore the original text exactly.