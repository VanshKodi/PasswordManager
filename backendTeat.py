# backendTest.py

import os
from BACKEND import database, crypto, models, config

def cleanup_database():
    """Removes all entries from the database tables for a clean slate."""
    print("\n--- Running Cleanup ---")
    try:
        with database.get_db_connection() as conn:
            # The order matters due to foreign key constraints (delete credentials before users)
            conn.execute("DELETE FROM credentials")
            conn.execute("DELETE FROM users")
            # We can leave settings as they are, or reset them
            # conn.execute("DELETE FROM settings") 
            conn.commit()
            print("SUCCESS: All user and credential entries removed from the database.")
    except Exception as e:
        print(f"ERROR during cleanup: {e}")

def run_tests():
    """Executes a series of tests on the backend modules."""

    # --- Test Data ---
    TEST_USERNAME = "testuser"
    TEST_MASTER_PASS = "S3cureP@ssw0rd!"
    TEST_CREDENTIAL_PASS = "my_super_secret_gmail_password"
    
    # 1. --- Initialization Test ---
    print("--- 1. Initializing Database ---")
    # Clean up any previous test runs by deleting the old DB file
    if os.path.exists(config.DATABASE_FILE):
        os.remove(config.DATABASE_FILE)
        print("Removed old database file.")
    database.initialize_database()
    print("SUCCESS: Database initialized.")
    
    # 2. --- Crypto Module Tests ---
    print("\n--- 2. Testing Crypto Module ---")
    # Hashing
    hashed_pass = crypto.hash_master_password(TEST_MASTER_PASS)
    assert len(hashed_pass) > 0
    print("SUCCESS: Master password hashed.")
    
    # Verification
    assert crypto.verify_master_password(TEST_MASTER_PASS, hashed_pass)
    assert not crypto.verify_master_password("wrongpassword", hashed_pass)
    print("SUCCESS: Master password verification works.")
    
    # Key Derivation
    encryption_key = crypto.derive_key(TEST_MASTER_PASS)
    assert len(encryption_key) > 0
    print("SUCCESS: Encryption key derived.")
    
    # Encryption / Decryption
    encrypted_data = crypto.encrypt_password(TEST_CREDENTIAL_PASS, encryption_key)
    decrypted_data = crypto.decrypt_password(encrypted_data, encryption_key)
    assert decrypted_data == TEST_CREDENTIAL_PASS
    print("SUCCESS: Password encryption and decryption work.")
    
    # 3. --- Database Module Tests ---
    print("\n--- 3. Testing Database Module ---")
    # User creation
    test_user = models.User(id=None, username=TEST_USERNAME, hashed_master_password=hashed_pass)
    database.create_user(test_user)
    print("SUCCESS: User created.")
    
    # User retrieval
    retrieved_user = database.get_user_by_username(TEST_USERNAME)
    assert retrieved_user is not None
    assert retrieved_user.username == TEST_USERNAME
    print("SUCCESS: User retrieved.")
    
    # Settings
    autosave_setting = database.get_setting('autosave_interval')
    assert autosave_setting == '5' # Default value
    database.update_setting('autosave_interval', '10')
    new_autosave_setting = database.get_setting('autosave_interval')
    assert new_autosave_setting == '10'
    print("SUCCESS: Settings can be retrieved and updated.")
    
    # Credential creation
    test_credential = models.Credential(
        id=None, 
        user_id=retrieved_user.id, 
        service_name="Test Service",
        username="test@email.com",
        encrypted_password=encrypted_data
    )
    database.add_credential(test_credential)
    print("SUCCESS: Credential added.")
    
    # Credential retrieval
    user_credentials = database.get_credentials_for_user(retrieved_user.id)
    assert len(user_credentials) == 1
    assert user_credentials[0].service_name == "Test Service"
    print("SUCCESS: Credentials retrieved for user.")
    
    # Credential deletion
    database.delete_credential(user_credentials[0].id)
    user_credentials_after_delete = database.get_credentials_for_user(retrieved_user.id)
    assert len(user_credentials_after_delete) == 0
    print("SUCCESS: Credential deleted.")

    print("\n--------------------------")
    print("✅ ALL TESTS PASSED ✅")
    print("--------------------------")

if __name__ == "__main__":
    try:
        run_tests()
    except Exception as e:
        print(f"\n❌ A TEST FAILED: {e} ❌")
    finally:
        # This block ensures that cleanup runs even if a test fails
        cleanup_database()