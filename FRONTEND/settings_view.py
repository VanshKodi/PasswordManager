# FRONTEND/settings_view.py

import tkinter as tk
from tkinter import messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

from BACKEND import database

class SettingsView(ttk.Toplevel):
    """A modal window for configuring application settings."""
    
    def __init__(self, master):
        super().__init__(master)
        self.title("Settings")
        self.transient(master)
        self.grab_set()
        self.settings_changed = False

        # --- NEW: Helper method to load all settings and create tk variables ---
        self._load_and_init_vars()
        self._create_widgets()
        
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.master.wait_window(self)

    def _load_and_init_vars(self):
        """Loads all settings from the database and creates tk variables."""
        # Existing Feature Vars
        self.autotype_hotkey_var = tk.StringVar(value=database.get_setting('autotype_hotkey'))
        self.length_var = tk.StringVar(value=database.get_setting('autofilter_length'))
        
        # New Generator Default Vars
        self.pw_length_var = tk.IntVar(value=int(database.get_setting('password_length')))
        self.pw_uc_var = tk.BooleanVar(value=bool(int(database.get_setting('password_include_uppercase'))))
        self.pw_lc_var = tk.BooleanVar(value=bool(int(database.get_setting('password_include_lowercase'))))
        self.pw_num_var = tk.BooleanVar(value=bool(int(database.get_setting('password_include_numbers'))))
        self.pw_sym_var = tk.BooleanVar(value=bool(int(database.get_setting('password_include_symbols'))))
        self.pp_words_var = tk.IntVar(value=int(database.get_setting('passphrase_num_words')))
        self.pp_sep_var = tk.StringVar(value=database.get_setting('passphrase_separator'))
        self.pp_cap_var = tk.BooleanVar(value=bool(int(database.get_setting('passphrase_capitalize'))))
        self.pp_num_var = tk.BooleanVar(value=bool(int(database.get_setting('passphrase_include_number'))))

    def _create_widgets(self):
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill=BOTH, expand=True)
        
        features_frame = ttk.Labelframe(main_frame, text="Features", padding=15)
        features_frame.pack(fill=X, pady=(0, 15))
        features_frame.grid_columnconfigure(1, weight=1)

        # Auto-Type Hotkey Display
        ttk.Label(features_frame, text="Auto-Type Hotkey:").grid(row=0, column=0, sticky=W, pady=5)
        hotkey_entry = ttk.Entry(features_frame, textvariable=self.autotype_hotkey_var, state=READONLY)
        hotkey_entry.grid(row=0, column=1, sticky=EW, padx=5)
        ttk.Label(features_frame, text="(Change via Query Panel)", bootstyle="secondary").grid(row=0, column=2, sticky=W, padx=5)

        # Auto-Filter Length
        ttk.Label(features_frame, text="Auto-Filter Length (chars):").grid(row=2, column=0, sticky=W, pady=5)
        length_entry = ttk.Entry(features_frame, textvariable=self.length_var, width=10)
        length_entry.grid(row=2, column=1, sticky=W, padx=5)

        # --- NEW: Generator Defaults Section ---
        gen_frame = ttk.Labelframe(main_frame, text="Generator Defaults", padding=15)
        gen_frame.pack(fill=X, anchor=N)
        
        gen_notebook = ttk.Notebook(gen_frame)
        gen_notebook.pack(fill=X, expand=True, padx=5, pady=5)
        
        # Password Defaults Tab
        pw_tab = ttk.Frame(gen_notebook, padding=10)
        gen_notebook.add(pw_tab, text="Password")
        ttk.Label(pw_tab, text="Default Length:").grid(row=0, column=0, sticky=W, pady=5)
        ttk.Spinbox(pw_tab, from_=8, to=128, textvariable=self.pw_length_var, width=5).grid(row=0, column=1, sticky=W, padx=5)
        ttk.Checkbutton(pw_tab, text="Include Uppercase", variable=self.pw_uc_var, bootstyle="round-toggle").grid(row=1, column=0, columnspan=2, sticky=W, pady=2)
        ttk.Checkbutton(pw_tab, text="Include Lowercase", variable=self.pw_lc_var, bootstyle="round-toggle").grid(row=2, column=0, columnspan=2, sticky=W, pady=2)
        ttk.Checkbutton(pw_tab, text="Include Numbers", variable=self.pw_num_var, bootstyle="round-toggle").grid(row=3, column=0, columnspan=2, sticky=W, pady=2)
        ttk.Checkbutton(pw_tab, text="Include Symbols", variable=self.pw_sym_var, bootstyle="round-toggle").grid(row=4, column=0, columnspan=2, sticky=W, pady=2)

        # Passphrase Defaults Tab
        pp_tab = ttk.Frame(gen_notebook, padding=10)
        gen_notebook.add(pp_tab, text="Passphrase")
        ttk.Label(pp_tab, text="Default Word Count:").grid(row=0, column=0, sticky=W, pady=5)
        ttk.Spinbox(pp_tab, from_=3, to=10, textvariable=self.pp_words_var, width=5).grid(row=0, column=1, sticky=W, padx=5)
        ttk.Label(pp_tab, text="Default Separator:").grid(row=1, column=0, sticky=W, pady=5)
        ttk.Entry(pp_tab, textvariable=self.pp_sep_var, width=5).grid(row=1, column=1, sticky=W, padx=5)
        ttk.Checkbutton(pp_tab, text="Capitalize Words", variable=self.pp_cap_var, bootstyle="round-toggle").grid(row=2, column=0, columnspan=2, sticky=W, pady=2)
        ttk.Checkbutton(pp_tab, text="Include a Number", variable=self.pp_num_var, bootstyle="round-toggle").grid(row=3, column=0, columnspan=2, sticky=W, pady=2)

        # Action Buttons
        button_frame = ttk.Frame(main_frame, padding=(0, 20, 0, 0))
        button_frame.pack(fill=X, side=BOTTOM)
        ttk.Button(button_frame, text="Save", command=self._save_settings, bootstyle=SUCCESS).pack(side=RIGHT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.destroy, bootstyle=DANGER).pack(side=RIGHT)
    
    def _save_settings(self):
        """Validates and saves all settings to the database."""
        try:
            length = int(self.length_var.get())
            if not length > 0:
                raise ValueError("Value must be a positive integer.")
        except ValueError:
            messagebox.showerror("Invalid Input", "Auto-Filter Length must be a positive whole number.", parent=self)
            return

        # Save existing settings
        database.update_setting('autofilter_length', self.length_var.get())
        
        # Save new generator settings (converting booleans to '1' or '0')
        database.update_setting('password_length', str(self.pw_length_var.get()))
        database.update_setting('password_include_uppercase', '1' if self.pw_uc_var.get() else '0')
        database.update_setting('password_include_lowercase', '1' if self.pw_lc_var.get() else '0')
        database.update_setting('password_include_numbers', '1' if self.pw_num_var.get() else '0')
        database.update_setting('password_include_symbols', '1' if self.pw_sym_var.get() else '0')
        database.update_setting('passphrase_num_words', str(self.pp_words_var.get()))
        database.update_setting('passphrase_separator', self.pp_sep_var.get())
        database.update_setting('passphrase_capitalize', '1' if self.pp_cap_var.get() else '0')
        database.update_setting('passphrase_include_number', '1' if self.pp_num_var.get() else '0')
        
        self.settings_changed = True
        messagebox.showinfo("Success", "Settings have been saved.", parent=self)
        self.destroy()