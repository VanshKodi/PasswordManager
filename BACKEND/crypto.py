# BACKEND/crypto.py

import base64
import hashlib
from cryptography.fernet import Fernet
from passlib.context import CryptContext

# Import constants from our config file
from .config import KEY_SALT, BCRYPT_ROUNDS

# 1. --- MASTER PASSWORD HASHING ---
# Use passlib for robust password hashing (bcrypt)
# This is for securely storing the master password itself.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=BCRYPT_ROUNDS)

def hash_master_password(password: str) -> str:
    """Hashes the master password using bcrypt."""
    return pwd_context.hash(password)

def verify_master_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies the plain master password against its stored hash."""
    return pwd_context.verify(plain_password, hashed_password)


# 2. --- ENCRYPTION KEY DERIVATION ---
# This function turns the master password into a usable encryption key.
# This key is never stored; it's generated on-the-fly when the user logs in.
def derive_key(master_password: str) -> bytes:
    """Derives a 32-byte encryption key from the master password and a salt."""
    # We use PBKDF2HMAC, a standard key derivation function.
    # 100,000 iterations is a common recommendation.
    kdf = hashlib.pbkdf2_hmac(
        'sha256',  # The hash algorithm
        master_password.encode('utf-8'),  # Convert the password to bytes
        KEY_SALT,  # Use the salt from our config
        100000,    # Number of iterations
        dklen=32   # Desired key length in bytes
    )
    # Return the key in a URL-safe base64 format, required by Fernet
    return base64.urlsafe_b64encode(kdf)


# 3. --- CREDENTIAL PASSWORD ENCRYPTION/DECRYPTION ---
# These functions use the derived key to encrypt and decrypt the user's
# stored passwords (e.g., their Google, Netflix, etc. passwords).
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