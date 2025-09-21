# FRONTEND/utils.py

import string
import secrets
import pyperclip
import threading

def generate_password(length: int, use_uppercase: bool, use_lowercase: bool, use_numbers: bool, use_symbols: bool) -> str:
    """
    Generates a cryptographically strong password.
    
    This function ensures that if a character set is selected, at least one
    character from that set will be included in the final password.
    """
    
    char_pool = []
    password = []

    if use_uppercase:
        char_pool.extend(string.ascii_uppercase)
        password.append(secrets.choice(string.ascii_uppercase))
    
    if use_lowercase:
        char_pool.extend(string.ascii_lowercase)
        password.append(secrets.choice(string.ascii_lowercase))
        
    if use_numbers:
        char_pool.extend(string.digits)
        password.append(secrets.choice(string.digits))
        
    if use_symbols:
        char_pool.extend(string.punctuation)
        password.append(secrets.choice(string.punctuation))

    # If no character sets are selected, return an empty string.
    if not char_pool:
        return ""
    
    # Fill the rest of the password length with random choices from the full pool
    remaining_length = length - len(password)
    for _ in range(remaining_length):
        password.append(secrets.choice(char_pool))
        
    # Shuffle the list to ensure the guaranteed characters aren't predictable
    secrets.SystemRandom().shuffle(password)
    
    return "".join(password)


def copy_to_clipboard(text_to_copy: str, root_window, clear_after_ms: int = 30000):
    """
    Copies text to the clipboard and clears it after a specified time.

    Args:
        text_to_copy (str): The text to be copied.
        root_window: The main Tkinter window, needed to schedule the clear operation.
        clear_after_ms (int): Time in milliseconds to wait before clearing.
    """
    try:
        pyperclip.copy(text_to_copy)
        # Schedule the clipboard to be cleared using Tkinter's 'after' method
        root_window.after(clear_after_ms, lambda: pyperclip.copy(""))
    except pyperclip.PyperclipException:
        # Handle cases where a clipboard mechanism isn't available
        print("Error: Pyperclip could not find a copy/paste mechanism on your system.")