# 🔐 Encrypted File Vault (`encrypted_file_vault.py`)

## 💡 What is it?
This tool lets you lock any file inside an encrypted vault using a password. Only someone with the correct password can unlock and read the file. The original file is then securely erased so it cannot be recovered.

---

## 🚪 The Analogy
Imagine putting your diary into a safe with a combination lock. The safe scrambles the pages into random noise when locked, and unscrambles them back when you enter the correct combination. A **File Vault** does the exact same thing for your computer files — but instead of a physical safe, it uses mathematics so powerful that even the world's fastest computers would take billions of years to crack it.

---

## ⚙️ How it Works

### Encrypting a file (`--encrypt`):
1. **You type a password.** The script confirms it by asking twice.
2. **A random salt is generated.** A salt is 16 random bytes that make your encryption unique — even if two people use the same password, their vaults look completely different.
3. **Key Derivation with PBKDF2.** Your password is not used directly as a key! Instead it's processed through **PBKDF2-HMAC-SHA256** with 480,000 rounds of hashing. This deliberately takes half a second — making brute-force attacks 480,000 times harder.
4. **Encryption with Fernet (AES).** The derived key is used to encrypt the file with **AES** (Advanced Encryption Standard) — the same encryption used by banks, governments, and the military.
5. **Secure deletion.** The original file is overwritten with random garbage 3 times before being deleted, so it can't be recovered from disk sectors.

### Decrypting a vault (`--decrypt`):
The same steps happen in reverse. If the password is wrong, decryption fails with a clear error.

---

## 🛠️ Key Code Concepts

| Concept | Simple Explanation |
|---|---|
| **AES (Fernet)** | Military-grade scrambling algorithm. Like a trillion-digit combination lock. |
| **PBKDF2** | Turns your short password into a long encryption key. Adds deliberate slowness to stop brute-force attacks. |
| **Salt** | 16 random bytes mixed with your password. Stops attackers from using pre-computed tables (rainbow tables). |
| **Secure Delete** | Overwrites the original file 3× with random bytes before deleting, so forensic tools can't recover it. |

---

## 🚀 How to Run

### Install dependency:
```bash
pip install cryptography
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
