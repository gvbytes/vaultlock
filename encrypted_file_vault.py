#!/usr/bin/env python3
"""
================================================================================
  EDUCATIONAL ENCRYPTED FILE VAULT
  Topic: Symmetric Encryption, Password-Based Key Derivation, Secure Deletion
  Library: cryptography (pip install cryptography)
================================================================================

LEARNING OBJECTIVES
-------------------
This script teaches four core concepts used in real-world security tools:

  1. SYMMETRIC ENCRYPTION
     Symmetric encryption means the *same* key is used to both lock (encrypt)
     and unlock (decrypt) data. Think of it like a padlock where the key that
     clicks it shut is the exact same key that opens it again.

     This script uses Fernet, a high-level recipe from the `cryptography`
     library. Under the hood, Fernet uses:
       - AES-128-CBC   : to scramble the data (AES = Advanced Encryption Standard)
       - HMAC-SHA256   : to guarantee the data wasn't tampered with
       - PKCS7 padding : to ensure the data fits AES's 16-byte block size
     You get authenticated encryption for free -- corrupted or tampered vault
     files are detected and rejected before a single byte is decrypted.

  2. PASSWORD-BASED KEY DERIVATION (PBKDF2)
     Encryption algorithms need a *key* -- a fixed-length sequence of random-
     looking bytes (e.g., 32 bytes = 256 bits for Fernet). A human password
     like "MyDog2024!" is too short, too predictable, and the wrong length.

     PBKDF2-HMAC-SHA256 is a *key derivation function* (KDF). It takes a
     password and runs it through SHA-256 tens of thousands of times, producing
     a proper-length key. The massive repetition is intentional: it makes
     brute-force guessing astronomically slow. An attacker trying millions of
     passwords per second is slowed to just a few per second.

     We use 480,000 iterations -- the NIST-recommended minimum as of 2023.

  3. SALT (Prevents Rainbow Table Attacks)
     A *salt* is a random chunk of bytes generated fresh each time you encrypt
     something. It is mixed into the key derivation process before hashing.

     Without a salt: if two people both use the password "hello123", their
     derived keys are identical. An attacker can pre-compute a giant table of
     (password -> key) pairs -- called a *rainbow table* -- and look up any
     hash instantly, like a dictionary attack.

     With a salt: even if 1,000 people use "hello123", each gets a *different*
     random salt, so each produces a *different* key. The attacker must redo
     the entire brute-force computation from scratch for every single file.
     Pre-computed rainbow tables become useless.

     The salt is NOT secret -- we store it openly at the front of the .vault
     file. Its only job is to be unique, not hidden.

  4. SECURE DELETION
     Deleting a file normally just removes the directory entry (the "pointer"
     to the file). The actual data bytes sit on disk until the OS reuses that
     space -- potentially recoverable with forensics tools.

     Secure deletion *overwrites* the file's bytes with random garbage *before*
     deleting it. After overwriting, even if forensics recovers the raw disk
     sectors, they see meaningless noise -- not the original file.

     Note: On SSDs with wear-leveling and on networked/cloud filesystems,
     secure deletion is harder to guarantee at the hardware level. This
     implementation provides best-effort overwrite at the OS level.

================================================================================
USAGE
================================================================================

  Install dependency first:
    pip install cryptography

  Encrypt a file:
    python encrypted_file_vault.py --encrypt secret.pdf

  Decrypt a vault file:
    python encrypted_file_vault.py --decrypt secret.pdf.vault

  List all vault files in the current directory:
    python encrypted_file_vault.py --list

================================================================================
"""

import os
import sys
import glob
import argparse
import secrets
import getpass

# ---------------------------------------------------------------------------
# cryptography library imports
# Fernet     : high-level symmetric encryption (AES-128-CBC + HMAC-SHA256)
# PBKDF2HMAC : Password-Based Key Derivation Function 2, using SHA-256
# hashes     : algorithm catalogue (we pick SHA256)
# base64     : Fernet expects a url-safe base64-encoded key
# ---------------------------------------------------------------------------
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    import base64
except ImportError:
    print("[ERROR] The 'cryptography' library is not installed.")
    print("        Run:  pip install cryptography")
    sys.exit(1)


# ============================================================
#  CONSTANTS
# ============================================================

# Number of PBKDF2 iterations.
# Higher = slower key derivation = harder for attackers to brute-force.
# NIST SP 800-132 (2023) recommends at least 210,000 for SHA-256.
# We use 480,000 for a comfortable safety margin on modern hardware.
PBKDF2_ITERATIONS = 480_000

# Salt length in bytes. 16 bytes = 128 bits of randomness.
# This is more than enough to make rainbow tables impractical.
SALT_LENGTH = 16

# The extension we append to every encrypted file.
VAULT_EXTENSION = ".vault"

# How many times we overwrite the file before deletion (secure delete).
# One pass of random bytes is sufficient against software-level recovery.
OVERWRITE_PASSES = 3


# ============================================================
#  KEY DERIVATION
# ============================================================

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte (256-bit) encryption key from a human password
    using PBKDF2-HMAC-SHA256.

    Parameters
    ----------
    password : str
        The user-supplied password (any length, any characters).
    salt : bytes
        A random 16-byte value stored alongside the ciphertext.

    Returns
    -------
    bytes
        A url-safe base64-encoded 32-byte key suitable for Fernet.

    Why base64?
    -----------
    Fernet's constructor expects the key to be base64url-encoded.
    The raw 32 bytes from PBKDF2 are binary -- we encode them so
    Fernet can accept them without complaint.
    """

    # Build the PBKDF2 configuration object:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),      # Hash function used internally
        length=32,                       # Output key length: 32 bytes for Fernet
        salt=salt,                       # The random salt (unique per file)
        iterations=PBKDF2_ITERATIONS,   # Deliberate slowness to resist brute-force
    )

    # Derive the raw 32-byte key from the UTF-8 encoded password
    raw_key = kdf.derive(password.encode("utf-8"))

    # Fernet requires the key to be base64url-encoded
    return base64.urlsafe_b64encode(raw_key)


# ============================================================
#  SECURE DELETION
# ============================================================

def secure_delete(filepath: str, passes: int = OVERWRITE_PASSES) -> None:
    """
    Overwrite a file with random bytes (multiple passes) then delete it.

    This prevents simple file-recovery tools from reading the original data
    after deletion. Each pass writes a completely fresh set of random bytes,
    then the file is truncated and removed.

    Parameters
    ----------
    filepath : str
        Absolute or relative path to the file to destroy.
    passes : int
        Number of random-overwrite passes. Default is 3.
    """

    file_size = os.path.getsize(filepath)

    with open(filepath, "r+b") as f:
        for pass_num in range(1, passes + 1):
            # Seek back to the beginning of the file for every pass
            f.seek(0)
            # Generate cryptographically random bytes equal to the file size
            # secrets.token_bytes() uses the OS entropy source (e.g., urandom)
            f.write(secrets.token_bytes(file_size))
            # Flush to disk -- we want the OS to actually write these bytes,
            # not just hold them in a buffer
            f.flush()
            os.fsync(f.fileno())
            print(f"    [secure delete] overwrite pass {pass_num}/{passes} done.")

    # After all overwrite passes, remove the directory entry
    os.remove(filepath)
    print(f"    [secure delete] '{filepath}' removed from filesystem.")


# ============================================================
#  ENCRYPT
# ============================================================

def encrypt_file(filepath: str) -> None:
    """
    Encrypt a file and save it as <filepath>.vault.

    Vault file format (binary):
    +-----------+-----------------------+
    | 16 bytes  | N bytes               |
    | SALT      | Fernet ciphertext     |
    +-----------+-----------------------+

    The salt is stored in plaintext -- this is intentional and safe.
    The salt's only job is to be unique per file, not secret.

    After encryption, the original file is securely deleted.

    Parameters
    ----------
    filepath : str
        Path to the plaintext file to encrypt.
    """

    # --- Validate input file ---
    if not os.path.isfile(filepath):
        print(f"[ERROR] File not found: '{filepath}'")
        return

    vault_path = filepath + VAULT_EXTENSION
    if os.path.exists(vault_path):
        print(f"[ERROR] Vault file already exists: '{vault_path}'")
        print("        Delete it manually if you want to re-encrypt.")
        return

    # --- Prompt for password (input hidden, no echo) ---
    password = getpass.getpass("  Enter password for encryption: ")
    password_confirm = getpass.getpass("  Confirm password: ")

    if password != password_confirm:
        print("[ERROR] Passwords do not match. Aborting.")
        return

    if len(password) < 8:
        print("[WARNING] Password is very short (< 8 chars). Consider a stronger one.")

    # --- Generate a fresh random salt ---
    # os.urandom() is cryptographically secure on all major OS platforms.
    # A new salt is generated every time, even if the same password is reused.
    # This is what breaks rainbow tables -- the same password produces a
    # completely different key for every file.
    salt = os.urandom(SALT_LENGTH)
    print(f"  [*] Generated salt: {salt.hex()} (stored in vault, not secret)")

    # --- Derive the encryption key from the password + salt ---
    print(f"  [*] Deriving key with PBKDF2 ({PBKDF2_ITERATIONS:,} iterations)... ", end="", flush=True)
    key = derive_key(password, salt)
    print("done.")

    # --- Read the original file ---
    with open(filepath, "rb") as f:
        plaintext = f.read()
    print(f"  [*] Read {len(plaintext):,} bytes from '{filepath}'.")

    # --- Encrypt with Fernet ---
    # Fernet.encrypt() internally:
    #   1. Generates a random 128-bit IV (Initialization Vector)
    #   2. Pads the plaintext to a multiple of 16 bytes (PKCS7)
    #   3. Encrypts with AES-128-CBC using the derived key
    #   4. Signs the result with HMAC-SHA256 so tampering is detectable
    #   5. Returns all of the above as a single base64-encoded token
    fernet = Fernet(key)
    ciphertext = fernet.encrypt(plaintext)
    print(f"  [*] Encrypted ciphertext is {len(ciphertext):,} bytes.")

    # --- Write vault file: [salt][ciphertext] ---
    with open(vault_path, "wb") as f:
        f.write(salt)        # First 16 bytes = salt
        f.write(ciphertext)  # Remaining bytes = Fernet token
    print(f"  [*] Vault saved to '{vault_path}'.")

    # --- Securely delete the original ---
    print(f"  [*] Securely deleting original file '{filepath}'...")
    secure_delete(filepath)

    print(f"\n[SUCCESS] '{filepath}' encrypted -> '{vault_path}'")
    print("          Original file securely deleted.")


# ============================================================
#  DECRYPT
# ============================================================

def decrypt_file(vault_path: str) -> None:
    """
    Decrypt a .vault file and restore the original file.

    Reads the salt from the first 16 bytes of the vault file,
    re-derives the key using the user's password, then uses
    Fernet to decrypt and verify the ciphertext.

    Parameters
    ----------
    vault_path : str
        Path to the .vault file to decrypt.
    """

    # --- Validate input ---
    if not os.path.isfile(vault_path):
        print(f"[ERROR] Vault file not found: '{vault_path}'")
        return

    if not vault_path.endswith(VAULT_EXTENSION):
        print(f"[WARNING] File does not end with '{VAULT_EXTENSION}'. Proceeding anyway...")

    # Determine the output filename by stripping the .vault extension
    if vault_path.endswith(VAULT_EXTENSION):
        output_path = vault_path[: -len(VAULT_EXTENSION)]
    else:
        output_path = vault_path + ".decrypted"

    if os.path.exists(output_path):
        print(f"[ERROR] Output file already exists: '{output_path}'")
        print("        Move or rename it first.")
        return

    # --- Read vault file ---
    with open(vault_path, "rb") as f:
        raw_data = f.read()

    if len(raw_data) < SALT_LENGTH + 1:
        print("[ERROR] Vault file is too small to be valid. Possibly corrupted.")
        return

    # --- Split salt and ciphertext ---
    # The first SALT_LENGTH bytes are the salt (stored in plaintext).
    # Everything after is the Fernet-encrypted token.
    salt = raw_data[:SALT_LENGTH]
    ciphertext = raw_data[SALT_LENGTH:]
    print(f"  [*] Extracted salt: {salt.hex()}")
    print(f"  [*] Ciphertext length: {len(ciphertext):,} bytes.")

    # --- Prompt for password ---
    password = getpass.getpass("  Enter decryption password: ")

    # --- Re-derive the key using the SAME salt ---
    # The key derivation is deterministic: same password + same salt
    # always produces the same key. That is the whole design.
    print(f"  [*] Deriving key with PBKDF2 ({PBKDF2_ITERATIONS:,} iterations)... ", end="", flush=True)
    key = derive_key(password, salt)
    print("done.")

    # --- Decrypt ---
    fernet = Fernet(key)
    try:
        # Fernet.decrypt() will:
        #   1. Verify the HMAC signature -- if the file was tampered with OR
        #      the wrong password was given, this raises InvalidToken.
        #   2. Decrypt the AES-128-CBC ciphertext.
        #   3. Remove the PKCS7 padding.
        #   4. Return the original plaintext.
        plaintext = fernet.decrypt(ciphertext)
    except InvalidToken:
        # This fires on: wrong password, corrupted file, or tampered data.
        # We don't distinguish between these cases on purpose -- an attacker
        # shouldn't learn *why* decryption failed.
        print("\n[ERROR] Decryption failed.")
        print("        Possible causes:")
        print("          - Wrong password")
        print("          - Corrupted or incomplete vault file")
        print("          - File was tampered with after encryption")
        return

    # --- Write plaintext to disk ---
    with open(output_path, "wb") as f:
        f.write(plaintext)

    print(f"  [*] Wrote {len(plaintext):,} bytes to '{output_path}'.")
    print(f"\n[SUCCESS] '{vault_path}' decrypted -> '{output_path}'")


# ============================================================
#  LIST VAULT FILES
# ============================================================

def list_vaults(directory: str = ".") -> None:
    """
    List all .vault files in the specified directory with their sizes.

    Parameters
    ----------
    directory : str
        Directory to scan. Defaults to the current working directory.
    """

    pattern = os.path.join(directory, f"*{VAULT_EXTENSION}")
    vault_files = sorted(glob.glob(pattern))

    if not vault_files:
        print(f"[INFO] No '{VAULT_EXTENSION}' files found in '{os.path.abspath(directory)}'.")
        return

    print(f"\n{'=' * 60}")
    print(f"  Vault files in: {os.path.abspath(directory)}")
    print(f"{'=' * 60}")
    print(f"  {'Filename':<45} {'Size':>10}")
    print(f"  {'-' * 45} {'-' * 10}")

    total_bytes = 0
    for vf in vault_files:
        size = os.path.getsize(vf)
        total_bytes += size
        name = os.path.basename(vf)
        if size >= 1024:
            size_str = f"{size / 1024:.1f} KB"
        else:
            size_str = f"{size} B"
        print(f"  {name:<45} {size_str:>10}")

    print(f"{'=' * 60}")
    print(f"  {len(vault_files)} vault file(s)   Total: {total_bytes / 1024:.1f} KB")
    print(f"{'=' * 60}")
    print()


# ============================================================
#  COMMAND-LINE INTERFACE
# ============================================================

def build_parser() -> argparse.ArgumentParser:
    """Configure and return the argument parser."""

    parser = argparse.ArgumentParser(
        prog="encrypted_file_vault",
        description=(
            "Educational Encrypted File Vault\n"
            "Demonstrates: symmetric encryption (Fernet/AES-128-CBC),\n"
            "              PBKDF2-HMAC-SHA256 key derivation,\n"
            "              random salting, and secure file deletion.\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python encrypted_file_vault.py --encrypt report.docx\n"
            "  python encrypted_file_vault.py --decrypt report.docx.vault\n"
            "  python encrypted_file_vault.py --list\n"
            "  python encrypted_file_vault.py --list --dir /path/to/folder\n"
        ),
    )

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "--encrypt",
        metavar="FILE",
        help="Encrypt FILE -> FILE.vault, then securely delete FILE.",
    )
    group.add_argument(
        "--decrypt",
        metavar="FILE.vault",
        help="Decrypt FILE.vault -> FILE (original filename restored).",
    )
    group.add_argument(
        "--list",
        action="store_true",
        help="List all .vault files in the current (or --dir) directory.",
    )

    parser.add_argument(
        "--dir",
        metavar="DIRECTORY",
        default=".",
        help="Directory to scan when using --list (default: current directory).",
    )

    return parser


def main() -> None:
    """Entry point: parse arguments and dispatch to the correct operation."""

    parser = build_parser()
    args = parser.parse_args()

    print()

    if args.encrypt:
        print(f"[ENCRYPT] Target: {args.encrypt}")
        encrypt_file(args.encrypt)

    elif args.decrypt:
        print(f"[DECRYPT] Target: {args.decrypt}")
        decrypt_file(args.decrypt)

    elif args.list:
        list_vaults(args.dir)

    print()


# ============================================================
#  ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
