# FRONTEND/settings_view.py

import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from pynput import keyboard

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
        self.dir_var = tk.StringVar()
        self.interval_var = tk.StringVar()
        self.limit_var = tk.StringVar()
        self.length_var = tk.StringVar()
        # Variable for the read-only hotkey display
        self.hotkey_var = tk.StringVar()

        self._load_settings()
        self._create_widgets()
        
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.master.wait_window(self)
    
    def _load_settings(self):
        """Loads all settings from the database."""
        self.hotkey_var.set(database.get_setting('autotype_hotkey')) # Fetches the hotkey
        self.length_var.set(database.get_setting('autofilter_length'))

    def _create_widgets(self):
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill=BOTH, expand=True)

        features_frame = ttk.Labelframe(main_frame, text="Features", padding=15)
        features_frame.pack(fill=X)
        features_frame.grid_columnconfigure(1, weight=1)

        ttk.Label(features_frame, text="Auto-Type Hotkey:").grid(row=0, column=0, sticky=W, pady=5)
        hotkey_entry = ttk.Entry(features_frame, textvariable=self.hotkey_var, state=READONLY)
        hotkey_entry.grid(row=0, column=1, sticky=EW, padx=5)
        ttk.Label(features_frame, text="(Change via Query Panel)", bootstyle="secondary").grid(row=0, column=2, sticky=W, padx=5)

        ttk.Label(features_frame, text="Auto-Filter Length (chars):").grid(row=1, column=0, sticky=W, pady=5)
        length_entry = ttk.Entry(features_frame, textvariable=self.length_var, width=10)
        length_entry.grid(row=1, column=1, sticky=W, padx=5)
        button_frame = ttk.Frame(main_frame, padding=(0, 20, 0, 0))
        button_frame.pack(fill=X, side=BOTTOM)
        ttk.Button(button_frame, text="Save", command=self._save_settings, bootstyle=SUCCESS).pack(side=RIGHT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.destroy, bootstyle=DANGER).pack(side=RIGHT)

    def _capture_hotkey(self):
        """Opens a window and captures a key combination using Tkinter event binding."""
        capture_window = ttk.Toplevel(self)
        capture_window.title("Set Hotkey")
        capture_window.geometry("350x100")
        capture_window.transient(self)
        capture_window.grab_set()
        
        ttk.Label(capture_window, text="Press your desired key combination...\n(e.g., Ctrl + Alt + H)", 
                  bootstyle=INVERSE, justify=CENTER).pack(fill=BOTH, expand=True)

        def on_key_press(event):
            # Do not capture lone modifier keys
            if event.keysym in ('Control_L', 'Control_R', 'Alt_L', 'Alt_R', 'Shift_L', 'Shift_R'):
                return

            modifiers = []
            # Check the state bitmask for modifiers
            if event.state & 0x4: modifiers.append("<ctrl>")
            if event.state & 0x8 or event.state & 0x1: modifiers.append("<alt>") # Alt can be state 1 or 8
            if event.state & 0x1: modifiers.append("<shift>")

            # Format the main key
            key = event.keysym.lower()
            
            # Combine and set the hotkey string
            hotkey_parts = sorted(modifiers) + [key]
            hotkey_str = "+".join(hotkey_parts)
            self.hotkey_var.set(hotkey_str)
            
            capture_window.destroy()

        capture_window.bind("<KeyPress>", on_key_press)
        # Focus is required for the window to receive key events
        capture_window.focus_force()

    def _test_hotkey_listener(self):
        self.test_label.config(text="Listening...", bootstyle=INFO)
        self.test_button.config(state=DISABLED)
        
        def on_activate_test():
            self.test_label.config(text="Success!", bootstyle=SUCCESS)
            if listener.running:
                listener.stop()

        hotkey_to_test_str = self.hotkey_var.get().replace('<alt>', '<alt_l>')
        hotkey_to_test = keyboard.HotKey(
            keyboard.HotKey.parse(hotkey_to_test_str),
            on_activate=on_activate_test
        )

        def on_press(key): hotkey_to_test.press(listener.canonical(key))
        def on_release(key): hotkey_to_test.release(listener.canonical(key))
            
        listener = keyboard.Listener(on_press=on_press, on_release=on_release)
        listener.start()
        
        def stop_test():
            if listener.running:
                listener.stop()
                self.test_label.config(text="Test timed out.", bootstyle=DANGER)
            self.test_button.config(state=NORMAL)
            
        self.after(5000, stop_test)

    def _save_settings(self):
        try:
            interval = int(self.interval_var.get())
            limit = int(self.limit_var.get())
            length = int(self.length_var.get())
            if not all(x > 0 for x in [interval, limit, length]):
                raise ValueError("Values must be positive integers.")
        except ValueError:
            messagebox.showerror("Invalid Input", "Interval, Limit, and Auto-Filter Length must be positive whole numbers.", parent=self)
            return

        database.update_setting('autofilter_length', self.length_var.get())
        
        self.settings_changed = True
        messagebox.showinfo("Success", "Settings have been saved.", parent=self)
        self.destroy()