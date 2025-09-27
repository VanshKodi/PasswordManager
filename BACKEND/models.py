# BACKEND/models.py

from dataclasses import dataclass
from typing import Optional

# (The User class is unchanged)
@dataclass
class User:
    """Represents a user of the password manager."""
    id: Optional[int]
    username: str
    hashed_master_password: str
    password_hint: Optional[str] = None
    recovery_passphrase_protected_master: Optional[bytes] = None


# --- UPDATED Credential Class ---
@dataclass
class Credential:
    """Represents a single credential entry stored for a user."""
    id: Optional[int]
    user_id: int
    service_name: str
    username: str
    encrypted_password: bytes
    # --- NEW FIELDS ---
    description: Optional[str] = None
    date_created: Optional[str] = None
    date_modified: Optional[str] = None


# (The Setting class is unchanged)
@dataclass
class Setting:
    """Represents a single key-value setting."""
    setting_name: str
    setting_value: str