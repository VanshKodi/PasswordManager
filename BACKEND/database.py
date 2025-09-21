# BACKEND/database.py

import sqlite3
from contextlib import contextmanager
from typing import List, Optional

# Import our project's modules
from .config import DATABASE_FILE
from .models import User, Credential

@contextmanager
def get_db_connection():
    """A context manager to handle database connections safely."""
    conn = sqlite3.connect(DATABASE_FILE)
    # This allows us to access columns by name
    conn.row_factory = sqlite3.Row
    try:
        # Enable foreign key support
        conn.execute("PRAGMA foreign_keys = ON")
        yield conn
    finally:
        conn.close()

def initialize_database():
    """
    Creates all necessary tables if they don't exist and populates
    default settings.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # --- Create 'users' table ---
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                hashed_master_password TEXT NOT NULL
            )
        """)
        
        # --- Create 'credentials' table ---
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                service_name TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password BLOB NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        """)
        
        # --- Create 'settings' table ---
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                setting_name TEXT PRIMARY KEY NOT NULL,
                setting_value TEXT
            )
        """)
        
        # --- Populate default settings (only if they don't exist) ---
        default_settings = {
            'autosave_interval': '5',
            'autosave_directory': 'default',
            'hide_on_copy': 'True'
        }
        for name, value in default_settings.items():
            cursor.execute("INSERT OR IGNORE INTO settings (setting_name, setting_value) VALUES (?, ?)", (name, value))
        
        conn.commit()

# --- User Functions ---

def create_user(user: User) -> None:
    """Creates a new user in the database."""
    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO users (username, hashed_master_password) VALUES (?, ?)",
            (user.username, user.hashed_master_password)
        )
        conn.commit()

def get_user_by_username(username: str) -> Optional[User]:
    """Retrieves a user by their username."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row:
            return User(id=row['id'], username=row['username'], hashed_master_password=row['hashed_master_password'])
        return None

# --- Credential Functions ---

def add_credential(credential: Credential) -> None:
    """Adds a new credential to the database."""
    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO credentials (user_id, service_name, username, encrypted_password) VALUES (?, ?, ?, ?)",
            (credential.user_id, credential.service_name, credential.username, credential.encrypted_password)
        )
        conn.commit()

def get_credentials_for_user(user_id: int) -> List[Credential]:
    """Retrieves all credentials for a given user."""
    credentials = []
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM credentials WHERE user_id = ?", (user_id,))
        rows = cursor.fetchall()
        for row in rows:
            credentials.append(Credential(
                id=row['id'],
                user_id=row['user_id'],
                service_name=row['service_name'],
                username=row['username'],
                encrypted_password=row['encrypted_password']
            ))
    return credentials

def delete_credential(credential_id: int) -> None:
    """Deletes a credential by its ID."""
    with get_db_connection() as conn:
        conn.execute("DELETE FROM credentials WHERE id = ?", (credential_id,))
        conn.commit()

# --- Settings Functions ---

def get_setting(setting_name: str) -> Optional[str]:
    """Retrieves a setting's value from the database."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT setting_value FROM settings WHERE setting_name = ?", (setting_name,))
        row = cursor.fetchone()
        return row['setting_value'] if row else None

def update_setting(setting_name: str, setting_value: str) -> None:
    """Updates or creates a new setting."""
    with get_db_connection() as conn:
        # "INSERT OR REPLACE" will insert if the key doesn't exist, or replace if it does.
        conn.execute(
            "INSERT OR REPLACE INTO settings (setting_name, setting_value) VALUES (?, ?)",
            (setting_name, setting_value)
        )
        conn.commit()