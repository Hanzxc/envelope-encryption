# Envelope Encryption with OpenSSL

> A Python tool that protects a file using **envelope encryption** — the same
> hybrid symmetric-plus-asymmetric scheme used by real cryptographic systems (and
> by file-locking ransomware). It drives OpenSSL under the hood and makes the
> plaintext recoverable **only** with an RSA private key.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![OpenSSL](https://img.shields.io/badge/uses-OpenSSL-721412)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20WSL-lightgrey)
![License](https://img.shields.io/badge/license-MIT-brightgreen)

> [!NOTE]
> This program deliberately **deletes the plaintext** after encrypting it and
> prints a ransom-style message, to illustrate how ransomware uses envelope
> encryption. It is a controlled, reversible teaching demo — nothing leaves your
> machine and `--decrypt` restores the file. See the [disclaimer](#disclaimer).

---

## Overview

RSA is secure but slow and can only encrypt a few bytes at a time; symmetric
ciphers like AES are fast on data of any size but need a shared secret. **Envelope
encryption** combines them to get the best of both:

1. Encrypt the **large file** with a fast, random **symmetric key** (AES).
2. Encrypt the **small symmetric key** with the **RSA public key**.

Now the data is protected, and the only thing needed to recover it is the RSA
**private key**, which unwraps the symmetric key, which decrypts the file.

---

## What it does

Running `python3 genkeys.py` performs six steps:

| Step | Action | Output |
|------|--------|--------|
| 1 | Generate a random 16-byte symmetric key (`openssl rand -base64 16`) | `key.txt` |
| 2 | Generate an RSA key pair | `private_key.pem`, `public_key.pem` |
| 3 | Encrypt `my_secrets.txt` with the symmetric key (AES-128-CBC) | `data_cipher.txt` |
| 4 | Encrypt `key.txt` with the RSA public key (RSA-OAEP) | `key_cipher.txt` |
| 5 | **Verify** both ciphertexts decrypt back to the originals, then delete `key.txt` and `my_secrets.txt` | — |
| 6 | Print the decryption / ransom-style message | — |

Both ciphertext files are stored in **base64**, so they are plain text and safe to
open in any editor.

### The chain of trust

After step 5, the only recovery path is:

```
private_key.pem  unwraps   key_cipher.txt
key_cipher.txt   gives      the symmetric key
symmetric key    decrypts   data_cipher.txt
data_cipher.txt  becomes    my_secrets.txt
```

The **private key is the single point everything depends on.** Lose it and the
data is gone — so back it up before running this on anything important.

---

## Security design highlights

This is more than a wrapper around a few OpenSSL commands — it is written to avoid
the common footguns:

- **Secrets never appear in `argv`.** Keys and passphrases are passed to OpenSSL
  over an inherited file descriptor, not on the command line, so another user
  can't read them with `ps`.
- **Verify-before-delete.** Step 5 refuses to delete the only readable copy unless
  both ciphertexts have been proven to decrypt back to the exact originals,
  byte-for-byte. A silent failure can't destroy your data.
- **RSA-OAEP padding** (SHA-256) instead of the weaker default PKCS#1 v1.5.
- **PBKDF2 + salt** for the symmetric encryption.
- **Restrictive file permissions** (`0600`) on every secret it writes.
- **Optional passphrase-protected private key** at rest (`--encrypt-private`).

---

## Requirements

- **Python 3.10+**
- **OpenSSL** available on your `PATH` (`openssl version`)
- **Linux or macOS.** On Windows, run inside **WSL (Ubuntu)** — the program hands
  the key to OpenSSL over a file descriptor, which is a Unix-only mechanism.

---

## Usage

Put `genkeys.py` and a local `my_secrets.txt` in the same folder. The plaintext
file is deliberately excluded from Git; start from `my_secrets.example.txt` and
replace its demo content with a non-sensitive lab file, then:

```bash
# Encrypt (runs all six steps)
python3 genkeys.py
```

After this you'll have `data_cipher.txt`, `key_cipher.txt`, `private_key.pem` and
`public_key.pem`. The originals `key.txt` and `my_secrets.txt` are gone.

```bash
# Reverse it — restore my_secrets.txt from the ciphertexts
python3 genkeys.py --decrypt
```

The recovered file is identical to the original, byte for byte.

### Options

| Flag | Description |
|------|-------------|
| `--keep-originals`   | Skip step 5 so `key.txt` and `my_secrets.txt` are kept (useful while testing). |
| `--encrypt-private`  | Prompt for a passphrase and encrypt the private key on disk. The same passphrase is required for `--decrypt`. |
| `--bits N`           | RSA key size in bits (default `3072`, minimum `2048`). |
| `--input FILE`       | Use a different plaintext file instead of `my_secrets.txt`. |
| `--output FILE`      | Use a different name for the data ciphertext. |

---

## Example run

```
Author: Ong Jun Han
Date: 17/08/2026
[1] Symmetric key (16 bytes, base64) -> .../key.txt
[2] RSA-3072 private key -> .../private_key.pem
    RSA-3072 public key  -> .../public_key.pem
[3] my_secrets.txt encrypted (aes-128-cbc) -> .../data_cipher.txt
[4] key.txt encrypted (RSA-OAEP) -> .../key_cipher.txt
[5] Deleted key.txt
[5] Deleted my_secrets.txt
[6] <decryption message>
```

---

## Concepts covered

- **Symmetric encryption** — one key locks and unlocks; fast, but the key must
  stay secret.
- **Asymmetric encryption (RSA)** — a public key locks, only the private key
  unlocks; shareable, but slow and size-limited.
- **Envelope / hybrid encryption** — encrypt data with a symmetric key, then
  encrypt that key with RSA.
- **Base64 encoding** — representing raw binary as printable text.
- **How ransomware weaponizes this** — the attacker holds the private key, so the
  victim cannot recover their files without it.

## Notes and limitations

- Deleting a file removes its directory entry but does not always wipe the
  underlying bytes on disk immediately.
- AES-CBC keeps data confidential but does **not** detect tampering. Adding an
  authentication step (HMAC, or an AEAD mode like AES-GCM) would close that gap.

---

## Disclaimer

This project was written for the **CSCI369 Ethical Hacking** course to demonstrate
envelope encryption and the mechanism behind file-locking ransomware. It operates
only on local files you point it at, and every action is reversible with the
private key it generates. It is provided for **educational use only**; the author
accepts no liability for misuse.

## Author

**Ong Jun Han** — CSCI369 Ethical Hacking

## License

Released under the [MIT License](LICENSE).
