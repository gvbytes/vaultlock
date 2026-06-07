# VaultLock

## What it does
VaultLock turns a local file into a password-protected `.vault` file. It derives an encryption key from your password, encrypts the contents, and removes the original file after the vault is written.

---

## How it works

### Encrypting a file (`--encrypt`):
1. **You type a password.** The script confirms it by asking twice.
2. **A random salt is generated.** A salt is 16 random bytes that make your encryption unique — even if two people use the same password, their vaults look completely different.
3. **Key Derivation with PBKDF2.** Your password is not used directly as a key! Instead it's processed through **PBKDF2-HMAC-SHA256** with 480,000 rounds of hashing. This slows down offline guessing compared with hashing the password once.
4. **Encryption with Fernet (AES).** The derived key is used to encrypt the file with **AES** (Advanced Encryption Standard) — a standard symmetric encryption primitive exposed through Fernet.
5. **Secure deletion.** The original file is overwritten with random garbage 3 times before being deleted, to reduce the chance of simple file recovery.

### Decrypting a vault (`--decrypt`):
The same steps happen in reverse. If the password is wrong, decryption fails with a clear error.

---

## Implementation notes

| Concept | Simple Explanation |
|---|---|
| **AES (Fernet)** | Authenticated symmetric encryption provided by the Fernet recipe. |
| **PBKDF2** | Derives an encryption key from a password and deliberately slows guessing attempts. |
| **Salt** | Random per-file input that prevents reused passwords from producing the same derived key. |
| **Secure Delete** | Best-effort overwrite before deleting the plaintext file. |

---

## Running it

### Install dependency:
```bash
pip install -r requirements.txt
```

### Encrypt a file:
```bash
python encrypted_file_vault.py --encrypt my_secret.pdf
```

### Decrypt a vault:
```bash
python encrypted_file_vault.py --decrypt my_secret.pdf.vault
```

### List all vault files:
```bash
python encrypted_file_vault.py --list
```

---

## 🔐 Real-World Connection
This is how **VeraCrypt**, **BitLocker**, and **Signal** protect your files and messages — symmetric encryption + key derivation + salting.


