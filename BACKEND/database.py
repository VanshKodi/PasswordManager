# BACKEND/database.py

import sqlite3
import datetime 
import os
from contextlib import contextmanager
from typing import List, Optional

from .config import DATABASE_FILE, ROOT_DIR
from .models import User, Credential
# Add this import at the top of BACKEND/database.py if it's missing
from contextlib import contextmanager


# Ensure the @contextmanager decorator is directly above the function
@contextmanager
def get_db_connection():
    """A context manager to handle database connections safely."""
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        yield conn
    finally:
        conn.close()

def execute_raw_query(query_string: str):
    """
    Executes a raw SQL query string against the database.
    Returns results for SELECT queries and status for other queries.
    Handles errors safely.
    """
    if not query_string.strip():
        return (None, None, "Query cannot be empty.", None)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(query_string)
            
            # If it's a query that modifies data (not a SELECT)
            if query_string.strip().upper().startswith(('INSERT', 'UPDATE', 'DELETE', 'REPLACE')):
                conn.commit()
                return (None, None, f"{cursor.rowcount} row(s) affected.", None)

            # If it was a SELECT query that returned no rows
            if cursor.description is None:
                return ([], [], "Query executed successfully with no results.", None)
                
            # If it was a SELECT that returned rows
            columns = [description[0] for description in cursor.description]
            rows = cursor.fetchall()
            return (columns, rows, f"{len(rows)} row(s) returned.", None)

        except sqlite3.Error as e:
            conn.rollback()
            return (None, None, None, f"Error: {e}")

def initialize_database():
    """Creates all necessary tables and default settings if they don't exist."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                hashed_master_password TEXT NOT NULL,
                password_hint TEXT,
                recovery_passphrase_protected_master BLOB
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                service_name TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password BLOB NOT NULL,
                description TEXT,
                date_created TEXT,
                date_modified TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                setting_name TEXT PRIMARY KEY NOT NULL,
                setting_value TEXT
            )
        """)
        
        
        # --- NEW: Add all default settings for the application ---
        default_settings = {
        'autotype_hotkey': '<ctrl>+.',
        'autofilter_length': '8',
        # New Password Settings
        'password_length': '16',
        'password_include_uppercase': '1', # 1 for True, 0 for False
        'password_include_lowercase': '1',
        'password_include_numbers': '1',
        'password_include_symbols': '1',
        # New Passphrase Settings
        'passphrase_num_words': '4',
        'passphrase_separator': '-',
        'passphrase_capitalize': '1',
        'passphrase_include_number': '1'
    }
        for name, value in default_settings.items():
            cursor.execute("INSERT OR IGNORE INTO settings (setting_name, setting_value) VALUES (?, ?)", (name, value))
        
        conn.commit()

# --- User Functions (unchanged) ---

def create_user(user: User) -> int:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, hashed_master_password) VALUES (?, ?)", (user.username, user.hashed_master_password))
        conn.commit()
        return cursor.lastrowid

def get_user_by_username(username: str) -> Optional[User]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row:
            return User(id=row['id'], username=row['username'], hashed_master_password=row['hashed_master_password'],
                        password_hint=row['password_hint'], recovery_passphrase_protected_master=row['recovery_passphrase_protected_master'])
        return None

def update_user_recovery_info(user_id: int, hint: Optional[str], passphrase_blob: Optional[bytes]):
    with get_db_connection() as conn:
        conn.execute("UPDATE users SET password_hint = ?, recovery_passphrase_protected_master = ? WHERE id = ?",
                     (hint, passphrase_blob, user_id))
        conn.commit()

# --- Credential Functions ---

def add_credential(credential: Credential) -> None:
    """Adds a new credential, including description and timestamps."""
    now = datetime.datetime.now().isoformat()
    with get_db_connection() as conn:
        conn.execute(
            """INSERT INTO credentials 
               (user_id, service_name, username, encrypted_password, description, date_created, date_modified) 
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (credential.user_id, credential.service_name, credential.username, credential.encrypted_password,
             credential.description, now, now)
        )
        conn.commit()

def get_credentials_for_user(user_id: int) -> List[Credential]:
    """Retrieves all credentials for a user, including new fields."""
    credentials = []
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM credentials WHERE user_id = ? ORDER BY service_name", (user_id,))
        rows = cursor.fetchall()
        for row in rows:
            credentials.append(Credential(
                id=row['id'], user_id=row['user_id'], service_name=row['service_name'],
                username=row['username'], encrypted_password=row['encrypted_password'],
                description=row['description'], date_created=row['date_created'], date_modified=row['date_modified']
            ))
    return credentials

def delete_credential(credential_id: int) -> None:
    """Deletes a credential by its ID."""
    with get_db_connection() as conn:
        conn.execute("DELETE FROM credentials WHERE id = ?", (credential_id,))
        conn.commit()

def update_credential(cred_id: int, service: str, username: str, enc_pass: bytes, desc: str) -> None:
    """Updates an existing credential."""
    now = datetime.datetime.now().isoformat()
    with get_db_connection() as conn:
        conn.execute(
            """UPDATE credentials SET
               service_name = ?, username = ?, encrypted_password = ?, description = ?, date_modified = ?
               WHERE id = ?""",
            (service, username, enc_pass, desc, now, cred_id)
        )
        conn.commit()

# --- MODIFIED FUNCTION ---
def search_credentials(user_id: int, search_term: str, filter_scope: str = "all") -> List[Credential]:
    """Searches credentials for a user based on a search term and a filter scope."""
    credentials = []
    query_term = f"%{search_term}%" # Add wildcards for LIKE query
    
    # Base query
    query = "SELECT * FROM credentials WHERE user_id = ?"
    params = [user_id]

    # Dynamically build the rest of the query based on the scope
    if search_term: # Only add search conditions if there is a search term
        if filter_scope == "sitename":
            query += " AND service_name LIKE ?"
            params.append(query_term)
        elif filter_scope == "username":
            query += " AND username LIKE ?"
            params.append(query_term)
        elif filter_scope == "description":
            query += " AND description LIKE ?"
            params.append(query_term)
        else: # Default to "all"
            query += " AND (service_name LIKE ? OR username LIKE ? OR description LIKE ?)"
            params.extend([query_term, query_term, query_term])

    query += " ORDER BY service_name"

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()
        for row in rows:
            credentials.append(Credential(
                id=row['id'], user_id=row['user_id'], service_name=row['service_name'],
                username=row['username'], encrypted_password=row['encrypted_password'],
                description=row['description'], date_created=row['date_created'], date_modified=row['date_modified']
            ))
    return credentials

# --- Settings Functions ---

def get_setting(setting_name: str) -> Optional[str]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT setting_value FROM settings WHERE setting_name = ?", (setting_name,))
        row = cursor.fetchone()
        return row['setting_value'] if row else None

def update_setting(setting_name: str, setting_value: str) -> None:
    with get_db_connection() as conn:
        conn.execute("INSERT OR REPLACE INTO settings (setting_name, setting_value) VALUES (?, ?)", (setting_name, setting_value))
        conn.commit()