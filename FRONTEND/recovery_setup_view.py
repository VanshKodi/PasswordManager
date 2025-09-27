# FRONTEND/recovery_setup_view.py

import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox

# Import backend modules
from BACKEND import database, crypto, models

class RecoverySetupView(ttk.Toplevel):
    """A modal window for setting up recovery options after signup."""
    
    def __init__(self, master, username, plain_text_password):
        super().__init__(master)
        self.title("Setup Recovery Options")
        
        # Store the data passed from the signup form
        self.username = username
        self.plain_text_password = plain_text_password
        
        # --- Instance Variables ---
        self.hint_var = tk.StringVar()
        self.passphrase_var = tk.StringVar(value="Click 'Generate' to create a passphrase.")
        self.passphrase_saved_var = tk.BooleanVar(value=False)
        self.generated_passphrase = None
        
        self.create_widgets()
        
        # Make the window modal
        self.transient(master)
        self.grab_set()
        self.master.wait_window(self)

    def create_widgets(self):
        """Creates and lays out the widgets for the recovery setup form."""
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill=BOTH, expand=True)

        info_label = ttk.Label(main_frame, text="Setup your recovery options. These are optional but highly recommended.", wraplength=400)
        info_label.pack(pady=(0, 20))
        
        # --- Notebook for different recovery options ---
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=BOTH, expand=True)

        # Tab 1: Password Hint
        hint_tab = ttk.Frame(notebook, padding=10)
        notebook.add(hint_tab, text="Password Hint")
        
        ttk.Label(hint_tab, text="Enter a hint for your password:").pack(anchor=W, pady=(0, 5))
        ttk.Entry(hint_tab, textvariable=self.hint_var).pack(fill=X)

        # Tab 2: Recovery Passphrase
        passphrase_tab = ttk.Frame(notebook, padding=10)
        notebook.add(passphrase_tab, text="Recovery Passphrase")
        
        ttk.Label(passphrase_tab, text="Generate and save this passphrase. It can be used to recover your master password if you forget it.").pack(anchor=W)
        ttk.Button(passphrase_tab, text="Generate Passphrase", command=self.generate_and_show_passphrase, bootstyle=INFO).pack(pady=10)
        
        passphrase_entry = ttk.Entry(passphrase_tab, textvariable=self.passphrase_var, state=READONLY)
        passphrase_entry.pack(fill=X, pady=5)
        
        ttk.Checkbutton(passphrase_tab, text="I have securely saved this passphrase.", variable=self.passphrase_saved_var).pack(anchor=W, pady=10)

        # --- Save Button ---
        save_button = ttk.Button(main_frame, text="Save and Complete Signup", command=self.save_options, bootstyle=SUCCESS)
        save_button.pack(pady=20)

    def generate_and_show_passphrase(self):
        """Generates a passphrase and displays it."""
        self.generated_passphrase = crypto.generate_recovery_passphrase()
        self.passphrase_var.set(self.generated_passphrase)
        
    def save_options(self):
        """
        Completes the signup process by saving the user and their selected recovery options.
        """
        # --- 1. Prepare Recovery Data ---
        hint = self.hint_var.get() or None # Store None if empty
        passphrase_blob = None
        
        if self.generated_passphrase:
            if not self.passphrase_saved_var.get():
                messagebox.showwarning("Confirmation Needed", "Please check the box to confirm you have saved your passphrase.", parent=self)
                return
            # Encrypt the master password with the generated passphrase
            passphrase_blob = crypto.encrypt_with_passphrase(self.plain_text_password, self.generated_passphrase)

        # --- 2. Create the User in the Database ---
        try:
            hashed_password = crypto.hash_master_password(self.plain_text_password)
            new_user = models.User(id=None, username=self.username, hashed_master_password=hashed_password)
            new_user_id = database.create_user(new_user)
            
            # --- 3. Save the Recovery Info for the New User ---
            database.update_user_recovery_info(new_user_id, hint, passphrase_blob)
            
            messagebox.showinfo("Success", "Signup and recovery setup complete! You can now log in.", parent=self.master)
            self.destroy() # Close the recovery setup window
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during signup: {e}", parent=self)