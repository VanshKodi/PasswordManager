# BACKEND/config.py

import os

# Define the absolute path to the project's root directory
# This helps ensure file paths work correctly regardless of where the script is run from
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Database configuration
DATABASE_FILE = os.path.join(ROOT_DIR, "password_manager.db")

# Cryptography constants
# In a real-world scenario, this SALT should be stored securely, not hardcoded.
# For this project, we'll define it here for simplicity.
KEY_SALT = b'some_random_salt_for_key_derivation'

# Hashing work factor for Passlib (higher is more secure but slower)
BCRYPT_ROUNDS = 12