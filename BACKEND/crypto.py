# BACKEND/crypto.py

import base64
import hashlib
import secrets
import string
import random
from cryptography.fernet import Fernet
# from passlib.context import CryptContext
from passlib.hash import bcrypt_sha256  # use bcrypt+SHA256 to avoid 72-byte limit [web:51]

from .config import KEY_SALT, BCRYPT_ROUNDS, PASSPHRASE_SALT

# 1. --- MASTER PASSWORD HASHING ---

# Remove CryptContext config for raw bcrypt; bcrypt_sha256 exposes rounds via 'rounds' kw.
# If a global cost is desired, define it here from BCRYPT_ROUNDS.
_BCRYPT_ROUNDS = BCRYPT_ROUNDS  # e.g., 12

def _utf8_len_bytes(s: str) -> int:
    return len(s.encode("utf-8"))  # count bytes, not characters [web:36]

def hash_master_password(password: str) -> str:
    """
    Hash master password using bcrypt_sha256 to bypass bcrypt's 72-byte input limit safely.
    """
    # Optional: quick diagnostic log (remove in production)
    # print("hash bytes:", _utf8_len_bytes(password))
    return bcrypt_sha256.using(rounds=_BCRYPT_ROUNDS).hash(password)  # [web:51]

def verify_master_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify using bcrypt_sha256.
    """
    return bcrypt_sha256.verify(plain_password, hashed_password)  # [web:51]

# 2. --- ENCRYPTION KEY DERIVATION ---
def derive_key(master_password: str) -> bytes:
    """Derives a 32-byte encryption key from the master password and a salt."""
    kdf = hashlib.pbkdf2_hmac(
        'sha256',
        master_password.encode('utf-8'),
        KEY_SALT,
        100000,
        dklen=32
    )
    return base64.urlsafe_b64encode(kdf)

# 3. --- CREDENTIAL PASSWORD ENCRYPTION/DECRYPTION ---
def encrypt_password(password_to_encrypt: str, encryption_key: bytes) -> bytes:
    """Encrypts a password using the derived key."""
    fernet = Fernet(encryption_key)
    encrypted_pass = fernet.encrypt(password_to_encrypt.encode('utf-8'))
    return encrypted_pass

def decrypt_password(encrypted_password: bytes, encryption_key: bytes) -> str:
    """Decrypts a password using the derived key."""
    fernet = Fernet(encryption_key)
    decrypted_pass = fernet.decrypt(encrypted_password).decode('utf-8')
    return decrypted_pass

# 4. --- PASSPHRASE RECOVERY & GENERATION ---
WORDLIST = [
    'apple', 'banana', 'carrot', 'diamond', 'eagle', 'forest', 'galaxy', 'harbor',
    'island', 'jacket', 'king', 'lemon', 'mountain', 'ninja', 'ocean', 'planet',
    'queen', 'river', 'shadow', 'tiger', 'unicorn', 'volcano', 'window', 'xenon',
    'yellow', 'zebra', 'anchor', 'bridge', 'candle', 'desert'
]

def generate_recovery_passphrase(num_words: int = 4) -> str:
    """Generates a simple, memorable, hyphen-separated passphrase for recovery."""
    selected_words = [secrets.choice(WORDLIST) for _ in range(num_words)]
    return "-".join(selected_words)

# --- Configurable Passphrase Generator ---
def generate_passphrase(num_words: int, separator: str, capitalize: bool, include_number: bool) -> str:
    """Generates a configurable, memorable passphrase based on user settings."""
    selected_words = [secrets.choice(WORDLIST) for _ in range(num_words)]

    if capitalize:
        selected_words = [word.capitalize() for word in selected_words]

    if include_number and num_words > 0:
        word_to_change_idx = secrets.randbelow(num_words)
        word = selected_words[word_to_change_idx]

        replacements = {'e': '3', 'a': '4', 'o': '0', 'l': '1', 's': '5'}
        possible_chars = list(replacements.keys())
        random.shuffle(possible_chars)

        for char in possible_chars:
            if char in word.lower():
                new_word = word.replace(char, replacements[char], 1)
                if capitalize:
                    new_word = new_word.capitalize()
                selected_words[word_to_change_idx] = new_word
                break

    return separator.join(selected_words)

def _derive_key_from_passphrase(passphrase: str) -> bytes:
    """
    Derives an encryption key from the recovery passphrase.
    Uses a different salt than the main key derivation.
    """
    kdf = hashlib.pbkdf2_hmac(
        'sha256',
        passphrase.encode('utf-8'),
        PASSPHRASE_SALT,
        100000,
        dklen=32
    )
    return base64.urlsafe_b64encode(kdf)

def encrypt_with_passphrase(master_password: str, passphrase: str) -> bytes:
    """Encrypts the master password using the recovery passphrase."""
    key = _derive_key_from_passphrase(passphrase)
    fernet = Fernet(key)
    return fernet.encrypt(master_password.encode('utf-8'))

def decrypt_with_passphrase(encrypted_master_pass: bytes, passphrase: str) -> str:
    """Decrypts the master password using the recovery passphrase."""
    key = _derive_key_from_passphrase(passphrase)
    fernet = Fernet(key)
    try:
        decrypted_pass = fernet.decrypt(encrypted_master_pass).decode('utf-8')
        return decrypted_pass
    except Exception:
        return ""
