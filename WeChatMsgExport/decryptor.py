"""WeChat v4 database decryption using SQLCipher-compatible crypto.

WeChat v4 uses SQLCipher v3 format:
  - KDF: PBKDF2-HMAC-SHA512, 256000 iterations
  - Cipher: AES-256-CBC
  - Page size: 4096 bytes (default)
  - 16-byte reserved space at end of each page
  - Salt stored in first 16 bytes of file
  - HMAC page-based authentication
"""

import os
import hashlib
import struct
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

PAGE_SIZE = 4096
RESERVED_SIZE = 16
KDF_ITERATIONS = 256000
KEY_LENGTH = 32  # AES-256


def derive_key(raw_key: bytes, salt: bytes) -> bytes:
    """Derive AES-256 key from raw key and salt using PBKDF2-HMAC-SHA512."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(raw_key)


def decrypt_page(encrypted_page: bytes, key: bytes, page_number: int) -> bytes:
    """
    Decrypt a single SQLCipher database page.

    SQLCipher v3 encrypts each page with AES-256-CBC.
    IV is derived from page number and salt.
    """
    # IV for SQLCipher: last 16 bytes of previous page's ciphertext
    # For page 0: IV = 16 zero bytes
    # For page N: IV = last 16 bytes of encrypted page N-1

    # Actually, SQLCipher v3 uses:
    # IV = <page_number as 4-byte big-endian> + <12 zero bytes>
    # But different implementations vary.
    # The common approach: each page treated independently with its own IV.

    iv = struct.pack(">I", page_number) + b"\x00" * 12

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend(),
    )
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_page) + decryptor.finalize()


def decrypt_database(encrypted_path: str, key: bytes, output_path: str) -> bool:
    """
    Decrypt a WeChat SQLCipher-encrypted database.

    Args:
        encrypted_path: Path to encrypted .db file
        key: Raw encryption key (before PBKDF2)
        output_path: Path to write decrypted database

    Returns:
        True if successful, False otherwise
    """
    if not os.path.exists(encrypted_path):
        return False

    file_size = os.path.getsize(encrypted_path)
    if file_size < PAGE_SIZE:
        return False

    with open(encrypted_path, "rb") as f:
        encrypted_data = f.read()

    # First 16 bytes = salt
    salt = encrypted_data[:16]

    # Derive the actual encryption key
    derived_key = derive_key(key, salt)

    decrypted_data = bytearray()
    num_pages = (file_size + PAGE_SIZE - 1) // PAGE_SIZE

    for page_num in range(num_pages):
        start = page_num * PAGE_SIZE
        end = min(start + PAGE_SIZE, file_size)
        page_data = encrypted_data[start:end]

        if len(page_data) < PAGE_SIZE:
            page_data = page_data + b"\x00" * (PAGE_SIZE - len(page_data))

        decrypted_page = decrypt_page(page_data, derived_key, page_num)
        decrypted_data.extend(decrypted_page[: (end - start)])

    # Verify SQLite header
    header = bytes(decrypted_data[:16])
    if header != b"SQLite format 3\x00":
        return False

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(decrypted_data)

    return True


def decrypt_all_databases(
    db_dir: str, keys: dict, output_dir: str
) -> dict:
    """
    Decrypt all WeChat databases in a directory.

    Args:
        db_dir: Path to encrypted db_storage directory
        keys: Dict mapping DB name -> raw key bytes
        output_dir: Directory to write decrypted files

    Returns:
        Dict with {db_name: success_bool}
    """
    results = {}
    os.makedirs(output_dir, exist_ok=True)

    for root, dirs, files in os.walk(db_dir):
        for f in files:
            if f.endswith(".db"):
                rel_path = os.path.relpath(
                    os.path.join(root, f), db_dir
                )
                db_name = os.path.splitext(rel_path)[0].replace(
                    os.sep, "/"
                )
                encrypted_path = os.path.join(root, f)
                decrypted_path = os.path.join(output_dir, rel_path)

                # Try matching key
                key = keys.get(db_name) or keys.get(
                    os.path.basename(db_name)
                )
                # Fallback key
                if not key and len(keys) == 1:
                    key = list(keys.values())[0]

                if key:
                    ok = decrypt_database(encrypted_path, key, decrypted_path)
                    results[db_name] = ok
                else:
                    results[db_name] = False

    return results
