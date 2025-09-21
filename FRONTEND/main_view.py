# FRONTEND/main_view.py

import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox

# Import our backend and utility modules
from BACKEND import database, crypto, models
from FRONTEND import utils

class MainView(ttk.Frame):
    """The main view of the application, shown after successful login."""
    def __init__(self, master, app_controller):
        super().__init__(master, padding=(20, 20))
        self.app_controller = app_controller
        
        # Get the current user and their derived encryption key from the controller
        self.user = self.app_controller.current_user
        self.key = self.app_controller.encryption_key
        
        # This will hold the ID of the currently selected credential in the list
        self.selected_credential_id = None

        # --- Instance Variables for Widgets ---
        self.service_var = tk.StringVar()
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        
        # Generator variables
        self.gen_length_var = tk.IntVar(value=16)
        self.gen_upper_var = tk.BooleanVar(value=True)
        self.gen_lower_var = tk.BooleanVar(value=True)
        self.gen_digits_var = tk.BooleanVar(value=True)
        self.gen_symbols_var = tk.BooleanVar(value=True)
        self.gen_result_var = tk.StringVar()

        # --- Create and layout the main widgets ---
        self.create_widgets()
        # Populate the list with the user's credentials
        self.refresh_credentials_list()

    def create_widgets(self):
        """Creates and arranges all widgets in the main view."""
        # --- Top Bar: Welcome Message and Logout Button ---
        top_frame = ttk.Frame(self)
        top_frame.pack(fill=X, pady=(0, 20))
        
        welcome_text = f"Welcome, {self.user.username}!"
        welcome_label = ttk.Label(top_frame, text=welcome_text, font=("Helvetica", 14))
        welcome_label.pack(side=LEFT)
        
        logout_button = ttk.Button(top_frame, text="Logout", command=self.app_controller.logout, bootstyle=DANGER)
        logout_button.pack(side=RIGHT)
        
        # --- Main Content Area using a PanedWindow for resizable panes ---
        paned_window = ttk.PanedWindow(self, orient=HORIZONTAL)
        paned_window.pack(fill=BOTH, expand=True)

        # --- Pane 1: Credentials List ---
        list_frame = ttk.Frame(paned_window, padding=5)
        self.create_credentials_list_pane(list_frame)
        paned_window.add(list_frame, weight=1)

        # --- Pane 2: Credential Details & Actions ---
        details_frame = ttk.Frame(paned_window, padding=5)
        self.create_details_and_actions_pane(details_frame)
        paned_window.add(details_frame, weight=3)

    def create_credentials_list_pane(self, parent_frame):
        """Creates the Treeview for listing credentials."""
        list_label = ttk.Label(parent_frame, text="Saved Credentials", font=("Helvetica", 12, "bold"))
        list_label.pack(pady=(0, 10))

        # Create a Treeview to display credentials
        self.tree = ttk.Treeview(parent_frame, columns=("service"), show="headings", selectmode="browse")
        self.tree.heading("service", text="Service")
        self.tree.pack(side=LEFT, fill=BOTH, expand=True)

        # Add a scrollbar
        scrollbar = ttk.Scrollbar(parent_frame, orient=VERTICAL, command=self.tree.yview)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Bind the selection event to a handler function
        self.tree.bind("<<TreeviewSelect>>", self.on_credential_select)

    def create_details_and_actions_pane(self, parent_frame):
        """Creates the form for credential details and the action buttons."""
        # --- Details Form ---
        form_notebook = ttk.Notebook(parent_frame)
        form_notebook.pack(fill=BOTH, expand=True, pady=(0, 20))
        
        details_tab = ttk.Frame(form_notebook, padding=10)
        generator_tab = ttk.Frame(form_notebook, padding=10)
        
        form_notebook.add(details_tab, text="Credential Details")
        form_notebook.add(generator_tab, text="Password Generator")
        
        # --- Details Tab Content ---
        ttk.Label(details_tab, text="Service Name:").grid(row=0, column=0, sticky=W, pady=5)
        self.service_entry = ttk.Entry(details_tab, textvariable=self.service_var, state=DISABLED)
        self.service_entry.grid(row=0, column=1, sticky=EW, padx=5)
        
        ttk.Label(details_tab, text="Username / Email:").grid(row=1, column=0, sticky=W, pady=5)
        self.username_entry = ttk.Entry(details_tab, textvariable=self.username_var, state=DISABLED)
        self.username_entry.grid(row=1, column=1, sticky=EW, padx=5)

        ttk.Label(details_tab, text="Password:").grid(row=2, column=0, sticky=W, pady=5)
        self.password_entry = ttk.Entry(details_tab, textvariable=self.password_var, state=DISABLED)
        self.password_entry.grid(row=2, column=1, sticky=EW, padx=5)

        details_tab.grid_columnconfigure(1, weight=1) # Makes entries expand
        
        self.copy_password_button = ttk.Button(details_tab, text="Copy Password", command=self.copy_password, state=DISABLED)
        self.copy_password_button.grid(row=3, column=1, sticky=E, pady=10)

        # --- Generator Tab Content ---
        self.create_generator_pane(generator_tab)
        
        # --- Action Buttons (Add, Save, Delete) ---
        action_frame = ttk.Frame(parent_frame)
        action_frame.pack(fill=X)
        
        self.add_button = ttk.Button(action_frame, text="Add New", command=self.prepare_for_add, bootstyle=SUCCESS)
        self.add_button.pack(side=LEFT, padx=5)
        
        self.save_button = ttk.Button(action_frame, text="Save New", command=self.save_new_credential, state=DISABLED)
        self.save_button.pack(side=LEFT, padx=5)
        
        self.delete_button = ttk.Button(action_frame, text="Delete", command=self.delete_credential, bootstyle=DANGER, state=DISABLED)
        self.delete_button.pack(side=RIGHT, padx=5)

    def create_generator_pane(self, parent_frame):
        """Creates the password generator UI elements."""
        ttk.Label(parent_frame, text="Length:").grid(row=0, column=0, sticky=W, pady=2)
        ttk.Entry(parent_frame, textvariable=self.gen_length_var, width=5).grid(row=0, column=1, sticky=W, pady=2)

        ttk.Checkbutton(parent_frame, text="Uppercase (A-Z)", variable=self.gen_upper_var, bootstyle=PRIMARY).grid(row=1, column=0, columnspan=2, sticky=W, pady=2)
        ttk.Checkbutton(parent_frame, text="Lowercase (a-z)", variable=self.gen_lower_var, bootstyle=PRIMARY).grid(row=2, column=0, columnspan=2, sticky=W, pady=2)
        ttk.Checkbutton(parent_frame, text="Numbers (0-9)", variable=self.gen_digits_var, bootstyle=PRIMARY).grid(row=3, column=0, columnspan=2, sticky=W, pady=2)
        ttk.Checkbutton(parent_frame, text="Symbols (!@#$)", variable=self.gen_symbols_var, bootstyle=PRIMARY).grid(row=4, column=0, columnspan=2, sticky=W, pady=2)

        generate_button = ttk.Button(parent_frame, text="Generate", command=self.generate_and_display_password, bootstyle=INFO)
        generate_button.grid(row=5, column=0, columnspan=2, pady=10)

        ttk.Entry(parent_frame, textvariable=self.gen_result_var, state=READONLY).grid(row=6, column=0, columnspan=2, sticky=EW, pady=5)
        
        copy_gen_button = ttk.Button(parent_frame, text="Copy & Use", command=self.copy_generated_password)
        copy_gen_button.grid(row=7, column=0, columnspan=2)
    
    # --- Data and Event Handling Methods ---

    def refresh_credentials_list(self):
        """Clears and re-populates the credentials list from the database."""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        # Fetch and insert new items
        self.credentials_data = database.get_credentials_for_user(self.user.id)
        for cred in self.credentials_data:
            # The 'iid' is the unique ID for the tree item, which we set to the DB id.
            self.tree.insert("", END, iid=cred.id, values=(cred.service_name,))
    
    def on_credential_select(self, event):
        """Handles when a user clicks on an item in the credentials list."""
        selected_items = self.tree.selection()
        if not selected_items:
            return
            
        self.selected_credential_id = int(selected_items[0])
        
        # Find the full credential data from our stored list
        selected_cred = next((c for c in self.credentials_data if c.id == self.selected_credential_id), None)
        
        if selected_cred:
            # Decrypt the password
            decrypted_password = crypto.decrypt_password(selected_cred.encrypted_password, self.key)
            
            # Populate the form
            self.service_var.set(selected_cred.service_name)
            self.username_var.set(selected_cred.username)
            self.password_var.set(decrypted_password)

            # Update widget states
            self.service_entry.config(state=DISABLED)
            self.username_entry.config(state=DISABLED)
            self.password_entry.config(state=DISABLED)
            self.save_button.config(state=DISABLED)
            self.delete_button.config(state=NORMAL)
            self.copy_password_button.config(state=NORMAL)

    def prepare_for_add(self):
        """Clears the form and prepares it for adding a new credential."""
        self.tree.selection_set("") # Deselect any item in the list
        self.selected_credential_id = None
        
        self.service_var.set("")
        self.username_var.set("")
        self.password_var.set("")
        
        self.service_entry.config(state=NORMAL)
        self.username_entry.config(state=NORMAL)
        self.password_entry.config(state=NORMAL)
        
        self.save_button.config(state=NORMAL)
        self.delete_button.config(state=DISABLED)
        self.copy_password_button.config(state=DISABLED)
        
        self.service_entry.focus() # Set focus to the first field

    def save_new_credential(self):
        """Saves a new credential to the database."""
        service = self.service_var.get()
        username = self.username_var.get()
        password = self.password_var.get()
        
        if not all([service, username, password]):
            messagebox.showerror("Error", "All fields must be filled.")
            return

        # Encrypt the new password
        encrypted_pass = crypto.encrypt_password(password, self.key)
        
        # Create a model instance and save to DB
        new_cred = models.Credential(
            id=None,
            user_id=self.user.id,
            service_name=service,
            username=username,
            encrypted_password=encrypted_pass
        )
        database.add_credential(new_cred)
        
        messagebox.showinfo("Success", "Credential saved successfully.")
        
        self.refresh_credentials_list()
        self.prepare_for_add() # Reset form after saving
        self.service_entry.config(state=DISABLED)
        self.username_entry.config(state=DISABLED)
        self.password_entry.config(state=DISABLED)
        self.save_button.config(state=DISABLED)
        
    def delete_credential(self):
        """Deletes the selected credential from the database."""
        if not self.selected_credential_id:
            return
            
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this credential?"):
            database.delete_credential(self.selected_credential_id)
            self.refresh_credentials_list()
            self.prepare_for_add() # Reset form
            self.service_entry.config(state=DISABLED)
            self.username_entry.config(state=DISABLED)
            self.password_entry.config(state=DISABLED)
            self.save_button.config(state=DISABLED)
            messagebox.showinfo("Success", "Credential deleted.")

    def copy_password(self):
        """Copies the currently displayed password to the clipboard."""
        password = self.password_var.get()
        if password:
            utils.copy_to_clipboard(password, self.winfo_toplevel())
            messagebox.showinfo("Copied", "Password copied to clipboard for 30 seconds.", parent=self)

    def generate_and_display_password(self):
        """Generates a password based on selected criteria."""
        generated_pass = utils.generate_password(
            length=self.gen_length_var.get(),
            use_uppercase=self.gen_upper_var.get(),
            use_lowercase=self.gen_lower_var.get(),
            use_numbers=self.gen_digits_var.get(),
            use_symbols=self.gen_symbols_var.get()
        )
        self.gen_result_var.set(generated_pass)
        
    def copy_generated_password(self):
        """Copies the generated password and also places it in the main password field."""
        password = self.gen_result_var.get()
        if password:
            self.password_var.set(password)
            utils.copy_to_clipboard(password, self.winfo_toplevel())
            messagebox.showinfo("Copied", "Generated password copied and set as current password.", parent=self)