# BACKEND/models.py

from dataclasses import dataclass
from typing import Optional

# Optional[int] is used for the id because a new object won't have an id
# until it's been saved to the database.

@dataclass
class User:
    """Represents a user of the password manager."""
    id: Optional[int]
    username: str
    hashed_master_password: str


@dataclass
class Credential:
    """Represents a single credential entry stored for a user."""
    id: Optional[int]
    user_id: int
    service_name: str
    username: str
    encrypted_password: bytes


@dataclass
class Setting:
    """Represents a single key-value setting."""
    setting_name: str
    setting_value: str