# FRONTEND/entry_form_view.py

import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox

# --- NEW: Import backend and utils to access settings and generators ---
from BACKEND import database, crypto
from FRONTEND import utils

class EntryFormWindow(ttk.Toplevel):
    """A pop-up window for adding or editing a credential, with an integrated generator."""
    def __init__(self, master, title, initial_data=None):
        super().__init__(master)
        self.title(title)
        self.geometry("600x650") # Make window larger for the new generator UI
        self.result = None # This will hold the form data on success
        
        # --- Standard form variables ---
        self.site_var = tk.StringVar()
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.description_var = tk.StringVar()
        
        if initial_data:
            self.site_var.set(initial_data.get("site", ""))
            self.username_var.set(initial_data.get("username", ""))
            self.password_var.set(initial_data.get("password", ""))
            self.description_var.set(initial_data.get("description", ""))

        # --- NEW: Load generator settings from DB and create tk variables ---
        self._load_generator_defaults()
        self._create_widgets()
        
        # Make the window modal
        self.transient(master)
        self.grab_set()
        self.master.wait_window(self)

    def _load_generator_defaults(self):
        """Loads generator settings from the database to populate the form's default values."""
        # Password generator variables
        self.pw_length_var = tk.IntVar(value=int(database.get_setting('password_length')))
        self.pw_uc_var = tk.BooleanVar(value=bool(int(database.get_setting('password_include_uppercase'))))
        self.pw_lc_var = tk.BooleanVar(value=bool(int(database.get_setting('password_include_lowercase'))))
        self.pw_num_var = tk.BooleanVar(value=bool(int(database.get_setting('password_include_numbers'))))
        self.pw_sym_var = tk.BooleanVar(value=bool(int(database.get_setting('password_include_symbols'))))
        
        # Passphrase generator variables
        self.pp_words_var = tk.IntVar(value=int(database.get_setting('passphrase_num_words')))
        self.pp_sep_var = tk.StringVar(value=database.get_setting('passphrase_separator'))
        self.pp_cap_var = tk.BooleanVar(value=bool(int(database.get_setting('passphrase_capitalize'))))
        self.pp_num_var = tk.BooleanVar(value=bool(int(database.get_setting('passphrase_include_number'))))

    def _create_widgets(self):
        """Creates and arranges all widgets, including the new integrated generator."""
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill=BOTH, expand=True)

        # --- Standard Entry Fields ---
        entry_fields_frame = ttk.Frame(main_frame)
        entry_fields_frame.pack(fill=X, pady=(0, 15))
        entry_fields_frame.grid_columnconfigure(1, weight=1)

        ttk.Label(entry_fields_frame, text="Site:").grid(row=0, column=0, sticky=W, pady=5)
        ttk.Entry(entry_fields_frame, textvariable=self.site_var).grid(row=0, column=1, sticky=EW, padx=5)
        
        ttk.Label(entry_fields_frame, text="Username:").grid(row=1, column=0, sticky=W, pady=5)
        ttk.Entry(entry_fields_frame, textvariable=self.username_var).grid(row=1, column=1, sticky=EW, padx=5)

        ttk.Label(entry_fields_frame, text="Password:").grid(row=2, column=0, sticky=W, pady=5)
        ttk.Entry(entry_fields_frame, textvariable=self.password_var).grid(row=2, column=1, sticky=EW, padx=5)

        ttk.Label(entry_fields_frame, text="Description:").grid(row=3, column=0, sticky=W, pady=5)
        ttk.Entry(entry_fields_frame, textvariable=self.description_var).grid(row=3, column=1, sticky=EW, padx=5)

        # --- Integrated Generator Section ---
        gen_frame = ttk.Labelframe(main_frame, text="Generator", padding=15)
        gen_frame.pack(fill=BOTH, expand=True)
        
        notebook = ttk.Notebook(gen_frame)
        notebook.pack(fill=BOTH, expand=True, pady=5)

        # Password Tab
        pw_tab = ttk.Frame(notebook, padding=10)
        notebook.add(pw_tab, text="Password")
        
        ttk.Label(pw_tab, text="Length:").grid(row=0, column=0, sticky=W, padx=5, pady=5)
        ttk.Spinbox(pw_tab, from_=8, to=128, textvariable=self.pw_length_var, width=5).grid(row=0, column=1, sticky=W, padx=5)
        ttk.Checkbutton(pw_tab, text="Uppercase (A-Z)", variable=self.pw_uc_var, bootstyle="round-toggle").grid(row=1, column=0, columnspan=2, sticky=W, padx=5, pady=2)
        ttk.Checkbutton(pw_tab, text="Lowercase (a-z)", variable=self.pw_lc_var, bootstyle="round-toggle").grid(row=2, column=0, columnspan=2, sticky=W, padx=5, pady=2)
        ttk.Checkbutton(pw_tab, text="Numbers (0-9)", variable=self.pw_num_var, bootstyle="round-toggle").grid(row=3, column=0, columnspan=2, sticky=W, padx=5, pady=2)
        ttk.Checkbutton(pw_tab, text="Symbols (!@#$)", variable=self.pw_sym_var, bootstyle="round-toggle").grid(row=4, column=0, columnspan=2, sticky=W, padx=5, pady=2)
        ttk.Button(pw_tab, text="Generate Password", command=self.generate_password, bootstyle=INFO).grid(row=5, column=0, columnspan=2, pady=10)

        # Passphrase Tab
        pp_tab = ttk.Frame(notebook, padding=10)
        notebook.add(pp_tab, text="Passphrase")
        
        ttk.Label(pp_tab, text="Number of Words:").grid(row=0, column=0, sticky=W, padx=5, pady=5)
        ttk.Spinbox(pp_tab, from_=3, to=10, textvariable=self.pp_words_var, width=5).grid(row=0, column=1, sticky=W, padx=5)
        ttk.Label(pp_tab, text="Separator:").grid(row=1, column=0, sticky=W, padx=5, pady=5)
        ttk.Entry(pp_tab, textvariable=self.pp_sep_var, width=5).grid(row=1, column=1, sticky=W, padx=5)
        ttk.Checkbutton(pp_tab, text="Capitalize Words", variable=self.pp_cap_var, bootstyle="round-toggle").grid(row=2, column=0, columnspan=2, sticky=W, padx=5, pady=2)
        ttk.Checkbutton(pp_tab, text="Include a Number", variable=self.pp_num_var, bootstyle="round-toggle").grid(row=3, column=0, columnspan=2, sticky=W, padx=5, pady=2)
        ttk.Button(pp_tab, text="Generate Passphrase", command=self.generate_passphrase, bootstyle=INFO).grid(row=4, column=0, columnspan=2, pady=10)

        # --- Action Buttons ---
        button_frame = ttk.Frame(main_frame, padding=(0, 15, 0, 0))
        button_frame.pack(fill=X, side=BOTTOM)
        
        ttk.Button(button_frame, text="Save", command=self.on_save, bootstyle=SUCCESS).pack(side=RIGHT, padx=10)
        ttk.Button(button_frame, text="Cancel", command=self.destroy, bootstyle=DANGER).pack(side=RIGHT)

    def generate_password(self):
        """Generates a password using the options and puts it in the password field."""
        generated = utils.generate_password(
            length=self.pw_length_var.get(),
            use_uppercase=self.pw_uc_var.get(),
            use_lowercase=self.pw_lc_var.get(),
            use_numbers=self.pw_num_var.get(),
            use_symbols=self.pw_sym_var.get()
        )
        self.password_var.set(generated)

    def generate_passphrase(self):
        """Generates a passphrase using the options and puts it in the password field."""
        generated = crypto.generate_passphrase(
            num_words=self.pp_words_var.get(),
            separator=self.pp_sep_var.get(),
            capitalize=self.pp_cap_var.get(),
            include_number=self.pp_num_var.get()
        )
        self.password_var.set(generated)
        
    def on_save(self):
        """Validates input and sets the result dictionary upon success."""
        if not self.site_var.get() or not self.password_var.get():
            messagebox.showerror("Input Error", "Site and Password fields cannot be empty.", parent=self)
            return

        self.result = {
            "site": self.site_var.get(),
            "username": self.username_var.get(),
            "password": self.password_var.get(),
            "description": self.description_var.get()
        }
        self.destroy()