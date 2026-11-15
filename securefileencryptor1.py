import os, sys, getpass, hashlib, base64
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken

# ── Key Generation ──────────────────────────────────────────
def get_key(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

# ── Encrypt ─────────────────────────────────────────────────
def encrypt(file_path, password):
    path = Path(file_path)
    if not path.exists(): raise FileNotFoundError(f"File not found: '{file_path}'")
    out_dir = Path("encrypted_files"); out_dir.mkdir(exist_ok=True)
    out = out_dir / (path.name + ".enc")
    out.write_bytes(Fernet(get_key(password)).encrypt(path.read_bytes()))
    return str(out)

# ── Decrypt ─────────────────────────────────────────────────
def decrypt(file_path, password):
    path = Path(file_path)
    if not path.exists(): raise FileNotFoundError(f"File not found: '{file_path}'")
    if path.suffix != ".enc": raise ValueError("Not a .enc file.")
    try:
        plaintext = Fernet(get_key(password)).decrypt(path.read_bytes())
    except InvalidToken:
        raise ValueError("Wrong password or corrupted file.")
    out = path.parent / path.stem
    out.write_bytes(plaintext)
    return str(out)

# ── Menu ─────────────────────────────────────────────────────
def main():
    print("\n🔐 SECURE FILE ENCRYPTOR")
    while True:
        print("\n  1. Encrypt\n  2. Decrypt\n  3. Exit")
        choice = input("\n  Choose (1/2/3): ").strip()
        if choice == "3": print("  Goodbye! 🔐"); break
        if choice not in ("1", "2"): print("  Invalid option."); continue

        f = input("  File path: ").strip()
        p = getpass.getpass("  Password: ")
        if not p: print("  [ERROR] Password cannot be empty."); continue

        try:
            out = encrypt(f, p) if choice == "1" else decrypt(f, p)
            print(f"  [SUCCESS] Saved to: {out}")
        except (FileNotFoundError, ValueError, Exception) as e:
            print(f"  [ERROR] {e}")

if __name__ == "__main__":
    main()
