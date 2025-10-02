# FRONTEND/forgot_password_view.py

import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox
import base64

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

        # SSS fields
        self.k_display = tk.StringVar(value="-")
        self.n_display = tk.StringVar(value="-")
        self.shares_text = None  # Text widget reference

        self.create_widgets()

        # Make the window modal
        self.transient(master)
        self.grab_set()
        self.master.wait_window(self)

    def create_widgets(self):
        """Creates and lays out the widgets for the recovery form."""
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill=BOTH, expand=True)

        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=BOTH, expand=True)

        # Tab 1: Passphrase recovery
        passphrase_tab = ttk.Frame(notebook, padding=10)
        notebook.add(passphrase_tab, text="Passphrase")

        info_label = ttk.Label(
            passphrase_tab,
            text="Use your recovery passphrase to retrieve your master password.",
            wraplength=420
        )
        info_label.pack(pady=(0, 10))

        form_frame = ttk.Frame(passphrase_tab)
        form_frame.pack(fill=X)

        ttk.Label(form_frame, text="Username:").grid(row=0, column=0, sticky=W, pady=5)
        ttk.Entry(form_frame, textvariable=self.username_var).grid(row=0, column=1, sticky=EW, padx=5)

        ttk.Label(form_frame, text="Recovery Passphrase:").grid(row=1, column=0, sticky=W, pady=5)
        ttk.Entry(form_frame, textvariable=self.passphrase_var).grid(row=1, column=1, sticky=EW, padx=5)

        form_frame.grid_columnconfigure(1, weight=1)

        ttk.Button(
            passphrase_tab, text="Recover with Passphrase",
            command=self.handle_passphrase_recovery, bootstyle=SUCCESS
        ).pack(pady=12)

        # Tab 2: Threshold recovery (SSS)
        sss_tab = ttk.Frame(notebook, padding=10)
        notebook.add(sss_tab, text="Threshold (SSS)")

        ttk.Label(
            sss_tab,
            text="Enter your username, then paste any k shares below as 'index:base64' per line.\n"
                 "The app will fetch the stored recovery blob and reconstruct your master password.",
            wraplength=420
        ).pack(anchor=W)

        sss_form = ttk.Frame(sss_tab)
        sss_form.pack(fill=X, pady=(8, 4))

        ttk.Label(sss_form, text="Username:").grid(row=0, column=0, sticky=W, pady=5)
        ttk.Entry(sss_form, textvariable=self.username_var).grid(row=0, column=1, sticky=EW, padx=5)

        meta = ttk.Frame(sss_tab)
        meta.pack(fill=X, pady=(2, 8))
        ttk.Label(meta, text="Threshold k:").grid(row=0, column=0, sticky=W)
        ttk.Label(meta, textvariable=self.k_display).grid(row=0, column=1, sticky=W, padx=(4, 16))
        ttk.Label(meta, text="Total n:").grid(row=0, column=2, sticky=W)
        ttk.Label(meta, textvariable=self.n_display).grid(row=0, column=3, sticky=W, padx=4)

        # Multiline shares input
        self.shares_text = tk.Text(sss_tab, height=8, wrap="none")
        self.shares_text.pack(fill=BOTH, expand=True, pady=(4, 8))

        # Buttons for SSS
        sss_btns = ttk.Frame(sss_tab)
        sss_btns.pack(fill=X)
        ttk.Button(sss_btns, text="Load Threshold From DB", command=self._load_threshold_meta, bootstyle=INFO).pack(side=LEFT, padx=(0, 8))
        ttk.Button(sss_btns, text="Recover with Shares", command=self.handle_sss_recovery, bootstyle=SUCCESS).pack(side=LEFT)

    # --- Existing passphrase flow ---

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
            messagebox.showinfo(
                "Success!",
                f"Your recovered master password is:\n\n{decrypted_pass}\n\nPlease change your password after login.",
                parent=self.master
            )
            self.destroy()
        else:
            messagebox.showerror("Recovery Failed", "The recovery passphrase was incorrect.", parent=self)

    # --- New SSS flow ---

    def _load_threshold_meta(self):
        """Fetch k/n from DB to guide how many shares are needed."""
        username = self.username_var.get()
        if not username:
            messagebox.showwarning("SSS", "Enter username first.", parent=self)
            return

        user = database.get_user_by_username(username)
        if not user:
            messagebox.showerror("SSS", "User not found.", parent=self)
            return

        # Pull recovery bundle metadata
        blob, k, n, created_at = database.get_user_recovery_bundle(user.id)
        if not blob:
            messagebox.showerror("SSS", "No SSS recovery bundle configured for this user.", parent=self)
            return

        self.k_display.set(str(k) if k is not None else "-")
        self.n_display.set(str(n) if n is not None else "-")
        messagebox.showinfo("SSS", f"Threshold loaded: k={k}, n={n}. Enter at least {k} shares.", parent=self)

    def handle_sss_recovery(self):
        """Recover using Shamir shares."""
        username = self.username_var.get()
        if not username:
            messagebox.showerror("SSS", "Username cannot be empty.", parent=self)
            return

        user = database.get_user_by_username(username)
        if not user:
            messagebox.showerror("SSS", "User not found.", parent=self)
            return

        recovery_blob, k, n, created_at = database.get_user_recovery_bundle(user.id)
        if not recovery_blob:
            messagebox.showerror("SSS", "No SSS recovery bundle configured for this user.", parent=self)
            return

        # Parse shares: one per line as "index:base64"
        raw = self.shares_text.get("1.0", "end").strip()
        if not raw:
            messagebox.showerror("SSS", "Paste your shares (one per line: index:base64).", parent=self)
            return

        shares = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                idx_str, b64 = line.split(":", 1)
                idx = int(idx_str)
                share_bytes = base64.urlsafe_b64decode(b64.encode("ascii"))
                shares.append((idx, share_bytes))
            except Exception:
                messagebox.showerror("SSS", f"Invalid share format: {line}", parent=self)
                return

        if k is None or n is None or not (1 <= k <= n <= 255):
            messagebox.showerror("SSS", "Stored threshold parameters are invalid.", parent=self)
            return
        if len(shares) < k:
            messagebox.showwarning("SSS", f"At least {k} shares are required; provided {len(shares)}.", parent=self)
            return

        try:
            recovered = crypto.recover_master_from_shares(shares, recovery_blob)
            messagebox.showinfo(
                "Success!",
                f"Your recovered master password is:\n\n{recovered}\n\nPlease change your password after login.",
                parent=self.master
            )
            self.destroy()
        except Exception as e:
            messagebox.showerror("SSS Recovery Failed", f"Could not recover master password: {e}", parent=self)
