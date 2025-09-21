import sqlite3

conn = sqlite3.connect('password_manager.db')
cursor = conn.cursor()
NHASHES=1000
from CRYPTO import hash_n_times
def login(username, password):
    cursor.execute("""SELECT * FROM users WHERE 
                   name = ? AND password = ?""", (username, hash_n_times(password, NHASHES)))
    return cursor.fetchone() is not None
def signup(username, password):
    try:
        cursor.execute("""INSERT INTO users (name, password) 
                       VALUES (?, ?)""", (username, hash_n_times(password, NHASHES)))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

print(signup("testadmin", "testpass"))



