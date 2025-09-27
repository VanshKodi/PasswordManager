# FRONTEND/forgot_password_view.py

import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox

# Import backend modules
from BACKEND import database, crypto

class ForgotPasswordView(ttk.Toplevel):
    """A modal window for recovering the master password."""
    
    def __init__(self, master):
        super().__init__(master)
        self.title("Recover Master Password")
        
        # --- Instance Variables ---
        self.username_var = tk.StringVar()
        self.passphrase_var = tk.StringVar()
        
        self.create_widgets()
        
        # Make the window modal
        self.transient(master)
        self.grab_set()
        self.master.wait_window(self)

    def create_widgets(self):
        """Creates and lays out the widgets for the recovery form."""
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill=BOTH, expand=True)

        info_label = ttk.Label(main_frame, text="Use your recovery passphrase to retrieve your master password.", wraplength=400)
        info_label.pack(pady=(0, 20))
        
        # --- Form ---
        form_frame = ttk.Frame(main_frame)
        form_frame.pack(fill=X)
        
        ttk.Label(form_frame, text="Username:").grid(row=0, column=0, sticky=W, pady=5)
        ttk.Entry(form_frame, textvariable=self.username_var).grid(row=0, column=1, sticky=EW, padx=5)
        
        ttk.Label(form_frame, text="Recovery Passphrase:").grid(row=1, column=0, sticky=W, pady=5)
        ttk.Entry(form_frame, textvariable=self.passphrase_var).grid(row=1, column=1, sticky=EW, padx=5)
        
        form_frame.grid_columnconfigure(1, weight=1)

        # --- Recover Button ---
        recover_button = ttk.Button(main_frame, text="Recover Password", command=self.handle_passphrase_recovery, bootstyle=SUCCESS)
        recover_button.pack(pady=20)

    def handle_passphrase_recovery(self):
        """Handles the logic for recovering a password with a passphrase."""
        username = self.username_var.get()
        passphrase = self.passphrase_var.get()

        if not username or not passphrase:
            messagebox.showerror("Error", "Username and passphrase cannot be empty.", parent=self)
            return

        user = database.get_user_by_username(username)
        
        if not user or not user.recovery_passphrase_protected_master:
            messagebox.showerror("Error", "No passphrase recovery is set up for this user.", parent=self)
            return
            
        # Attempt to decrypt the master password
        decrypted_pass = crypto.decrypt_with_passphrase(user.recovery_passphrase_protected_master, passphrase)

        if decrypted_pass:
            # Success!
            messagebox.showinfo(
                "Success!", 
                f"Your recovered master password is:\n\n{decrypted_pass}\n\nPlease change your password as soon as you log in.",
                parent=self.master
            )
            self.destroy() # Close the recovery window
        else:
            # Failure
            messagebox.showerror("Recovery Failed", "The recovery passphrase was incorrect.", parent=self)