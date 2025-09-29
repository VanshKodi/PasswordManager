# BACKEND/crypto.py

import base64
import hashlib
import secrets 
import string  
import random # --- NEW: Import random for smart number substitution
from cryptography.fernet import Fernet
from passlib.context import CryptContext

from .config import KEY_SALT, BCRYPT_ROUNDS, PASSPHRASE_SALT

# 1. --- MASTER PASSWORD HASHING ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=BCRYPT_ROUNDS)

def hash_master_password(password: str) -> str:
    """Hashes the master password using bcrypt."""
    return pwd_context.hash(password)

def verify_master_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies the plain master password against its stored hash."""
    return pwd_context.verify(plain_password, hashed_password)


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

# --- NEW: Configurable Passphrase Generator ---
def generate_passphrase(num_words: int, separator: str, capitalize: bool, include_number: bool) -> str:
    """Generates a configurable, memorable passphrase based on user settings."""
    selected_words = [secrets.choice(WORDLIST) for _ in range(num_words)]
    
    if capitalize:
        selected_words = [word.capitalize() for word in selected_words]

    if include_number and num_words > 0:
        word_to_change_idx = secrets.randbelow(num_words)
        word = selected_words[word_to_change_idx]
        
        # Leetspeak-style replacements for a more natural feel
        replacements = {'e': '3', 'a': '4', 'o': '0', 'l': '1', 's': '5'}
        possible_chars = list(replacements.keys())
        random.shuffle(possible_chars) # Randomize to avoid predictable substitutions
        
        for char in possible_chars:
            if char in word.lower():
                # Replace the first occurrence of the character
                new_word = word.replace(char, replacements[char], 1)
                if capitalize:
                    # Attempt to preserve capitalization
                    new_word = new_word.capitalize()
                selected_words[word_to_change_idx] = new_word
                break # Only make one substitution per passphrase
                
    return separator.join(selected_words)

def _derive_key_from_passphrase(passphrase: str) -> bytes:
    """
    Derives an encryption key from the recovery passphrase.
    Uses a different salt than the main key derivation.
    """
    kdf = hashlib.pbkdf2_hmac(
        'sha256',
        passphrase.encode('utf-8'),
        PASSPHRASE_SALT, # Using the new, dedicated salt
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
        # This will catch errors if the wrong passphrase is used
        return ""