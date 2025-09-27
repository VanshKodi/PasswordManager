# FRONTEND/entry_form_view.py

import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

class EntryFormWindow(ttk.Toplevel):
    """A pop-up window for adding or editing a credential."""
    def __init__(self, master, title, initial_data=None):
        super().__init__(master)
        self.title(title)
        self.result = None # This will hold the form data on success
        
        self.site_var = tk.StringVar()
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.description_var = tk.StringVar()
        
        if initial_data:
            self.site_var.set(initial_data.get("site", ""))
            self.username_var.set(initial_data.get("username", ""))
            self.password_var.set(initial_data.get("password", ""))
            self.description_var.set(initial_data.get("description", ""))

        self.create_form_widgets()
        
        # Make the window modal
        self.transient(master)
        self.grab_set()
        self.master.wait_window(self)

    def create_form_widgets(self):
        form_frame = ttk.Frame(self, padding=20)
        form_frame.pack(fill=BOTH, expand=True)
        
        ttk.Label(form_frame, text="Site:").grid(row=0, column=0, sticky=W, pady=5)
        ttk.Entry(form_frame, textvariable=self.site_var, width=40).grid(row=0, column=1, sticky=EW, padx=5)
        
        ttk.Label(form_frame, text="Username:").grid(row=1, column=0, sticky=W, pady=5)
        ttk.Entry(form_frame, textvariable=self.username_var).grid(row=1, column=1, sticky=EW, padx=5)

        ttk.Label(form_frame, text="Password:").grid(row=2, column=0, sticky=W, pady=5)
        ttk.Entry(form_frame, textvariable=self.password_var).grid(row=2, column=1, sticky=EW, padx=5)

        ttk.Label(form_frame, text="Description:").grid(row=3, column=0, sticky=W, pady=5)
        ttk.Entry(form_frame, textvariable=self.description_var).grid(row=3, column=1, sticky=EW, padx=5)
        
        form_frame.grid_columnconfigure(1, weight=1)

        button_frame = ttk.Frame(self, padding=(0, 10))
        button_frame.pack(fill=X)
        
        ttk.Button(button_frame, text="Save", command=self.on_save, bootstyle=SUCCESS).pack(side=RIGHT, padx=10)
        ttk.Button(button_frame, text="Cancel", command=self.destroy, bootstyle=DANGER).pack(side=RIGHT)

    def on_save(self):
        # Basic validation
        if not self.site_var.get() or not self.password_var.get():
            # In a real app, show a messagebox error
            print("Error: Site and password cannot be empty.")
            return

        self.result = {
            "site": self.site_var.get(),
            "username": self.username_var.get(),
            "password": self.password_var.get(),
            "description": self.description_var.get()
        }
        self.destroy()