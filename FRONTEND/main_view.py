# FRONTEND/main_view.py

import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox
import datetime

from BACKEND import database, crypto, models
from FRONTEND import utils
from .settings_view import SettingsView
from .entry_form_view import EntryFormWindow 
from .query_view import QueryView

class MainView(ttk.Frame):
    """The main view of the application, based on the new UI design."""
    
    def __init__(self, master, app_controller):
        super().__init__(master)
        self.app_controller = app_controller
        
        self.user = self.app_controller.current_user
        self.key = self.app_controller.encryption_key
        
        self.credentials_cache = []

        self.search_var = tk.StringVar()
        self.filter_var = tk.StringVar(value="all")
        self.autofilter_enabled_var = tk.BooleanVar(value=False)

        self.create_widgets()
        self.refresh_credentials_list()
    def _open_query_panel(self):
        """Opens the raw SQL query panel."""
        QueryView(self)

    def create_widgets(self):
        """Creates and arranges all widgets in the main view."""
        top_bar = ttk.Frame(self, padding=(10, 5))
        top_bar.pack(fill=X, side=TOP)
        
        welcome_label = ttk.Label(top_bar, text=f"User: {self.user.username}", font=("Helvetica", 10, "bold"))
        welcome_label.pack(side=LEFT, padx=5)

        logout_button = ttk.Button(top_bar, text="Logout", command=self.app_controller.logout, bootstyle=(DANGER, OUTLINE), width=8)
        logout_button.pack(side=RIGHT, padx=5)

        actions_frame = ttk.Frame(self, padding=(10, 5))
        actions_frame.pack(fill=X, side=TOP)

        ttk.Button(actions_frame, text="Add Entry", command=self.add_entry, bootstyle=SUCCESS).pack(side=LEFT, padx=2)
        ttk.Button(actions_frame, text="Edit Entry", command=self.edit_entry, bootstyle=(INFO, OUTLINE)).pack(side=LEFT, padx=2)
        ttk.Button(actions_frame, text="Copy Username", command=self.copy_username, bootstyle=(INFO, OUTLINE)).pack(side=LEFT, padx=2)
        ttk.Button(actions_frame, text="Copy Password", command=self.copy_password, bootstyle=(INFO, OUTLINE)).pack(side=LEFT, padx=2)
        ttk.Button(actions_frame, text="Copy Username & Password", command=self._copy_user_and_pass).pack(side=LEFT, padx=2)
        ttk.Button(actions_frame, text="Delete Entry", command=self.delete_entry, bootstyle=DANGER).pack(side=LEFT, padx=2)
        
        ttk.Button(actions_frame, text="Settings", command=self._open_settings_panel, bootstyle=SECONDARY).pack(side=RIGHT, padx=2)
        ttk.Button(actions_frame, text="Import/Export Vault", command=self.placeholder_action, bootstyle=SECONDARY).pack(side=RIGHT, padx=(2,2))
        ttk.Button(actions_frame, text="Import/Export Vault", command=self.placeholder_action, bootstyle=SECONDARY).pack(side=RIGHT, padx=(2,2))
        ttk.Button(actions_frame, text="Query Panel", command=self._open_query_panel, bootstyle=SECONDARY).pack(side=RIGHT, padx=2)
        # --- MODIFIED: Storing the button as an instance variable to change it later ---
        self.autofilter_button = ttk.Checkbutton(
            actions_frame, 
            text="Enable Auto Filter", 
            variable=self.autofilter_enabled_var, 
            bootstyle=(DANGER, TOOLBUTTON), # Start with red (DANGER)
            command=self._on_autofilter_toggle
        )
        self.autofilter_button.pack(side=RIGHT, padx=2)
        
        search_frame = ttk.Frame(self, padding=(10, 10))
        search_frame.pack(fill=X, side=TOP)
        
        ttk.Label(search_frame, text="Search:").pack(side=LEFT, padx=(5, 5))
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        self.search_entry.pack(side=LEFT, fill=X, expand=True, padx=5)
        self.search_entry.bind("<KeyRelease>", self.filter_treeview)

        ttk.Label(search_frame, text="Filter:").pack(side=LEFT, padx=(10, 5))
        filter_options = ["all", "sitename", "username", "description"]
        filter_menu = ttk.Combobox(search_frame, textvariable=self.filter_var, values=filter_options, state="readonly", width=12)
        filter_menu.pack(side=LEFT, padx=5)
        filter_menu.bind("<<ComboboxSelected>>", self.filter_treeview)
        
        ttk.Button(search_frame, text="Clear", command=self._clear_filters).pack(side=LEFT, padx=5)

        tree_frame = ttk.Frame(self, padding=(10, 0))
        tree_frame.pack(fill=BOTH, expand=True)

        columns = ("site", "username", "description", "date_created", "date_modified")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")
        
        self.tree.heading("site", text="Site")
        self.tree.heading("username", text="Username")
        self.tree.heading("description", text="Description")
        self.tree.heading("date_created", text="Date Created")
        self.tree.heading("date_modified", text="Date Modified")
        
        self.tree.column("site", width=150)
        self.tree.column("username", width=150)
        self.tree.column("description", width=250)
        self.tree.column("date_created", width=120, anchor=CENTER)
        self.tree.column("date_modified", width=120, anchor=CENTER)
        
        self.tree.pack(side=LEFT, fill=BOTH, expand=True)

        scrollbar = ttk.Scrollbar(tree_frame, orient=VERTICAL, command=self.tree.yview)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.tree.configure(yscrollcommand=scrollbar.set)
    
    def filter_treeview(self, event=None):
        search_term = self.search_var.get()
        filter_scope = self.filter_var.get()
        
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.credentials_cache = database.search_credentials(self.user.id, search_term, filter_scope)
        
        for cred in self.credentials_cache:
            created = datetime.datetime.fromisoformat(cred.date_created).strftime('%Y-%m-%d %H:%M') if cred.date_created else ""
            modified = datetime.datetime.fromisoformat(cred.date_modified).strftime('%Y-%m-%d %H:%M') if cred.date_modified else ""
            values = (cred.service_name, cred.username, cred.description or "", created, modified)
            self.tree.insert("", END, iid=cred.id, values=values)

    def get_selected_credential(self):
        selected_items = self.tree.selection()
        if not selected_items:
            return None
        selected_id = int(selected_items[0])
        return next((c for c in self.credentials_cache if c.id == selected_id), None)

    def add_entry(self):
        form = EntryFormWindow(self, title="Add New Entry")
        if form.result:
            encrypted_pass = crypto.encrypt_password(form.result["password"], self.key)
            new_cred = models.Credential(id=None, user_id=self.user.id, service_name=form.result["site"],
                                          username=form.result["username"], encrypted_password=encrypted_pass,
                                          description=form.result["description"])
            database.add_credential(new_cred)
            self.filter_treeview()

    def edit_entry(self):
        selected_cred = self.get_selected_credential()
        if not selected_cred:
            messagebox.showwarning("No Selection", "Please select an entry from the list first.", parent=self)
            return
        plain_password = crypto.decrypt_password(selected_cred.encrypted_password, self.key)
        initial_data = {
            "site": selected_cred.service_name, "username": selected_cred.username,
            "password": plain_password, "description": selected_cred.description or ""
        }
        form = EntryFormWindow(self, title="Edit Entry", initial_data=initial_data)
        if form.result:
            encrypted_pass = crypto.encrypt_password(form.result["password"], self.key)
            database.update_credential(
                cred_id=selected_cred.id, service=form.result["site"], username=form.result["username"],
                enc_pass=encrypted_pass, desc=form.result["description"]
            )
            self.filter_treeview()

    def delete_entry(self):
        selected_cred = self.get_selected_credential()
        if not selected_cred:
            messagebox.showwarning("No Selection", "Please select an entry from the list first.", parent=self)
            return
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the entry for '{selected_cred.service_name}'?"):
            database.delete_credential(selected_cred.id)
            self.filter_treeview()

    def copy_username(self):
        selected_cred = self.get_selected_credential()
        if selected_cred:
            utils.copy_to_clipboard(selected_cred.username, self)
            messagebox.showinfo("Copied", "Username copied to clipboard.", parent=self)
        else:
            messagebox.showwarning("No Selection", "Please select an entry to copy.", parent=self)

    def copy_password(self):
        selected_cred = self.get_selected_credential()
        if selected_cred:
            plain_password = crypto.decrypt_password(selected_cred.encrypted_password, self.key)
            utils.copy_to_clipboard(plain_password, self)
            messagebox.showinfo("Copied", "Password copied to clipboard.", parent=self)
        else:
            messagebox.showwarning("No Selection", "Please select an entry to copy.", parent=self)

    # In FRONTEND/main_view.py, find this method and REPLACE it:

    def _copy_user_and_pass(self):
        """Tells the app controller to ARM the selected credential for auto-typing."""
        selected_cred = self.get_selected_credential()
        if selected_cred:
            self.app_controller.arm_credential_for_autotype(selected_cred)
        else:
            messagebox.showwarning("No Selection", "Please select an entry to arm for auto-typing.", parent=self)

    def _open_settings_panel(self):
        settings_window = SettingsView(self)
        if settings_window.settings_changed:
            self.app_controller.on_settings_changed()

    def _clear_filters(self):
        self.search_var.set("")
        self.filter_var.set("all")
        self.filter_treeview()

    # --- MODIFIED: This function now updates the button's appearance ---
    def _on_autofilter_toggle(self):
        is_enabled = self.autofilter_enabled_var.get()
        self.app_controller.set_autofilter_state(is_enabled)
        
        if is_enabled:
            self.autofilter_button.config(text="Disable Auto Filter", bootstyle=(SUCCESS, TOOLBUTTON))
        else:
            self.autofilter_button.config(text="Enable Auto Filter", bootstyle=(DANGER, TOOLBUTTON))
            self.search_var.set("")
            self.filter_treeview()

    def refresh_credentials_list(self):
        self.filter_treeview()

    def placeholder_action(self):
        messagebox.showinfo("Coming Soon", "This feature is not yet implemented.", parent=self)
