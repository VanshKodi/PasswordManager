# FRONTEND/recovery_setup_view.py

import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox
import base64
from datetime import datetime

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
        # Passphrase recovery
        self.hint_var = tk.StringVar()
        self.passphrase_var = tk.StringVar(value="Click 'Generate' to create a passphrase.")
        self.passphrase_saved_var = tk.BooleanVar(value=False)
        self.generated_passphrase = None

        # SSS recovery
        self.enable_sss_var = tk.BooleanVar(value=False)
        self.k_var = tk.IntVar(value=3)
        self.n_var = tk.IntVar(value=5)
        self.generated_shares = None  # list of (idx:int, share:bytes)

        self.create_widgets()

        # Make the window modal
        self.transient(master)
        self.grab_set()
        self.master.wait_window(self)

    def create_widgets(self):
        """Creates and lays out the widgets for the recovery setup form."""
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill=BOTH, expand=True)

        info_label = ttk.Label(
            main_frame,
            text="Setup optional recovery methods. Keep any shares or passphrases safe and separate.",
            wraplength=420
        )
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

        ttk.Label(
            passphrase_tab,
            text="Generate and save this passphrase to recover your master password."
        ).pack(anchor=W)
        ttk.Button(
            passphrase_tab, text="Generate Passphrase",
            command=self.generate_and_show_passphrase, bootstyle=INFO
        ).pack(pady=10)

        passphrase_entry = ttk.Entry(passphrase_tab, textvariable=self.passphrase_var, state=READONLY)
        passphrase_entry.pack(fill=X, pady=5)
        ttk.Checkbutton(
            passphrase_tab,
            text="I have securely saved this passphrase.",
            variable=self.passphrase_saved_var
        ).pack(anchor=W, pady=10)

        # Tab 3: Threshold Recovery (SSS)
        sss_tab = ttk.Frame(notebook, padding=10)
        notebook.add(sss_tab, text="Threshold Recovery (SSS)")

        ttk.Checkbutton(
            sss_tab,
            text="Enable threshold recovery using Shamir's Secret Sharing",
            variable=self.enable_sss_var
        ).pack(anchor=W, pady=(0, 8))

        grid = ttk.Frame(sss_tab)
        grid.pack(fill=X, pady=4)

        ttk.Label(grid, text="k (required shares):").grid(row=0, column=0, sticky=W, padx=(0, 8))
        ttk.Entry(grid, textvariable=self.k_var, width=6).grid(row=0, column=1, sticky=W)
        ttk.Label(grid, text="n (total shares):").grid(row=0, column=2, sticky=W, padx=(16, 8))
        ttk.Entry(grid, textvariable=self.n_var, width=6).grid(row=0, column=3, sticky=W)

        ttk.Button(
            sss_tab, text="Generate Shares",
            command=self._generate_shares, bootstyle=INFO
        ).pack(pady=10)

        self._shares_preview = tk.Text(sss_tab, height=6, wrap="none", state="disabled")
        self._shares_preview.pack(fill=BOTH, expand=True)

        # --- Save Button ---
        save_button = ttk.Button(main_frame, text="Save and Complete Signup", command=self.save_options, bootstyle=SUCCESS)
        save_button.pack(pady=20)

    def _set_shares_preview(self, lines):
        self._shares_preview.configure(state="normal")
        self._shares_preview.delete("1.0", "end")
        self._shares_preview.insert("end", "\n".join(lines))
        self._shares_preview.configure(state="disabled")

    def _generate_shares(self):
        """Create SSS shares preview without saving to DB yet."""
        if not self.enable_sss_var.get():
            messagebox.showwarning("Threshold Recovery", "Enable SSS first.", parent=self)
            return

        k = self.k_var.get()
        n = self.n_var.get()
        try:
            shares, recovery_blob = crypto.make_recovery_bundle(self.plain_text_password, k, n)  # returns list[(idx, bytes)], blob
            # Hold in memory; DB write occurs on save_options
            self.generated_shares = shares
            # Show preview as index:base64
            lines = [f"{idx}:{base64.urlsafe_b64encode(share).decode('ascii')}" for idx, share in shares]
            self._set_shares_preview(lines)
            messagebox.showinfo(
                "Shares Generated",
                "Shares generated. They will be finalized on Save.\nEnsure to export/share them securely.",
                parent=self
            )
            # Stash the blob temporarily for final save
            self._pending_recovery_blob = recovery_blob
        except Exception as e:
            messagebox.showerror("SSS Error", f"Failed to generate shares: {e}", parent=self)

    def generate_and_show_passphrase(self):
        """Generates a passphrase and displays it."""
        self.generated_passphrase = crypto.generate_recovery_passphrase()
        self.passphrase_var.set(self.generated_passphrase)

    def save_options(self):
        """
        Completes the signup process by saving the user and their selected recovery options.
        """
        # --- 1. Prepare Recovery Data ---
        hint = self.hint_var.get() or None  # Store None if empty
        passphrase_blob = None

        if self.generated_passphrase:
            if not self.passphrase_saved_var.get():
                messagebox.showwarning(
                    "Confirmation Needed",
                    "Please check the box to confirm you have saved your passphrase.",
                    parent=self
                )
                return
            # Encrypt the master password with the generated passphrase
            passphrase_blob = crypto.encrypt_with_passphrase(self.plain_text_password, self.generated_passphrase)

        # Validate SSS parameters if enabled
        sss_enabled = bool(self.enable_sss_var.get())
        if sss_enabled:
            k = self.k_var.get()
            n = self.n_var.get()
            if not (1 <= k <= n <= 255):
                messagebox.showerror("SSS Error", "Invalid threshold: require 1 <= k <= n <= 255.", parent=self)
                return
            if not hasattr(self, "_pending_recovery_blob") or self.generated_shares is None:
                messagebox.showwarning("SSS", "Generate shares before saving.", parent=self)
                return

        # --- 2. Create the User in the Database ---
        try:
            hashed_password = crypto.hash_master_password(self.plain_text_password)
            new_user = models.User(id=None, username=self.username, hashed_master_password=hashed_password)
            new_user_id = database.create_user(new_user)

            # --- 3a. Save the passphrase-based recovery info ---
            database.update_user_recovery_info(new_user_id, hint, passphrase_blob)

            # --- 3b. Save the SSS recovery bundle metadata and blob (but NOT shares) ---
            if sss_enabled:
                created_at = datetime.utcnow().isoformat()
                database.update_user_recovery_bundle(
                    new_user_id,
                    self._pending_recovery_blob,
                    k,
                    n,
                    created_at=created_at
                )

            # --- 4. Present shares for export if generated ---
            if sss_enabled and self.generated_shares:
                lines = [f"{idx}:{base64.urlsafe_b64encode(share).decode('ascii')}" for idx, share in self.generated_shares]
                preview = "\n".join(lines)
                messagebox.showinfo(
                    "Save Your Shares",
                    "Write down or export these shares now.\nThey are not stored by the app:\n\n" + preview,
                    parent=self
                )

            messagebox.showinfo("Success", "Signup and recovery setup complete! You can now log in.", parent=self.master)
            self.destroy()  # Close the recovery setup window

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during signup: {e}", parent=self)
