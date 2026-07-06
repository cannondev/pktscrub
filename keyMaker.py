#simple 32 byte key maker, needed to instantiate the Crypto-PAn class in sanitizer.py

import os
from pathlib import Path

KEY_DIR = Path.home() / ".pktscrub"
KEY_FILE = KEY_DIR / "crypto_pan.key"

def generate_key():
    return os.urandom(32)

def write_key_to_file(key: bytes, path: Path = KEY_FILE) -> Path:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True) # 0o700 so only the owner can read/write/execute
    with open(path, "wb") as f:
        f.write(key)
    os.chmod(path, 0o600) # 0o600 so only the owner can read/write
    return path

if __name__ == "__main__":
    key = generate_key()
    key_path = write_key_to_file(key)
    print(f"Generated key (hex): {key.hex()}")
    print(f"Key length: {len(key)} bytes")
    print(f"Key saved to: {key_path}")

