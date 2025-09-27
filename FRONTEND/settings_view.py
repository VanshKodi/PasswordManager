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

        # Variables for configurable settings
        self.length_var = tk.StringVar()
        self.autotype_hotkey_var = tk.StringVar()
        self.hide_hotkey_var = tk.StringVar() # <-- New variable

        self._load_settings()
        self._create_widgets()
        
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.master.wait_window(self)
    
    def _load_settings(self):
        """Loads all settings from the database."""
        self.autotype_hotkey_var.set(database.get_setting('autotype_hotkey'))
        self.hide_hotkey_var.set(database.get_setting('hide_hotkey')) # <-- Load new setting
        self.length_var.set(database.get_setting('autofilter_length'))

    def _create_widgets(self):
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill=BOTH, expand=True)
        
        features_frame = ttk.Labelframe(main_frame, text="Features", padding=15)
        features_frame.pack(fill=X)
        features_frame.grid_columnconfigure(1, weight=1)

        # Auto-Type Hotkey Display
        ttk.Label(features_frame, text="Auto-Type Hotkey:").grid(row=0, column=0, sticky=W, pady=5)
        hotkey_entry = ttk.Entry(features_frame, textvariable=self.autotype_hotkey_var, state=READONLY)
        hotkey_entry.grid(row=0, column=1, sticky=EW, padx=5)
        ttk.Label(features_frame, text="(Change via Query Panel)", bootstyle="secondary").grid(row=0, column=2, sticky=W, padx=5)
        
        # --- NEW: Hide Window Hotkey Display ---
        ttk.Label(features_frame, text="Hide Window Hotkey:").grid(row=1, column=0, sticky=W, pady=5)
        hide_hotkey_entry = ttk.Entry(features_frame, textvariable=self.hide_hotkey_var, state=READONLY)
        hide_hotkey_entry.grid(row=1, column=1, sticky=EW, padx=5)
        ttk.Label(features_frame, text="(Change via Query Panel)", bootstyle="secondary").grid(row=1, column=2, sticky=W, padx=5)

        # Auto-Filter Length
        ttk.Label(features_frame, text="Auto-Filter Length (chars):").grid(row=2, column=0, sticky=W, pady=5)
        length_entry = ttk.Entry(features_frame, textvariable=self.length_var, width=10)
        length_entry.grid(row=2, column=1, sticky=W, padx=5)

        # Buttons
        button_frame = ttk.Frame(main_frame, padding=(0, 20, 0, 0))
        button_frame.pack(fill=X, side=BOTTOM)
        ttk.Button(button_frame, text="Save", command=self._save_settings, bootstyle=SUCCESS).pack(side=RIGHT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.destroy, bootstyle=DANGER).pack(side=RIGHT)

    def _save_settings(self):
        try:
            length = int(self.length_var.get())
            if not length > 0:
                raise ValueError("Value must be a positive integer.")
        except ValueError:
            messagebox.showerror("Invalid Input", "Auto-Filter Length must be a positive whole number.", parent=self)
            return

        # Only save settings that are currently editable in this window
        database.update_setting('autofilter_length', self.length_var.get())
        
        self.settings_changed = True
        messagebox.showinfo("Success", "Settings have been saved.", parent=self)
        self.destroy()