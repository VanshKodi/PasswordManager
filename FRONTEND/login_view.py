# FRONTEND/login_view.py

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox

# Import backend modules
from BACKEND import database, crypto, models

class LoginView(ttk.Frame):
    """The view for handling user login and signup."""
    def __init__(self, master, app_controller):
        super().__init__(master, padding=(20, 20))
        self.app_controller = app_controller

        # --- Instance Variables ---
        self.username_var = ttk.StringVar()
        self.password_var = ttk.StringVar()
        self.message_var = ttk.StringVar()

        # --- Widget Creation ---
        self.create_widgets()

    def create_widgets(self):
        """Creates and lays out the widgets for the login form."""
        # Main frame to center the content
        form_frame = ttk.Frame(self)
        form_frame.place(relx=0.5, rely=0.5, anchor=CENTER)
        
        # --- Title ---
        title_label = ttk.Label(form_frame, text="Password Manager", font=("Helvetica", 24, "bold"))
        title_label.pack(pady=(0, 20))
        
        # --- Form Entries ---
        username_label = ttk.Label(form_frame, text="Username:")
        username_label.pack(fill=X, pady=(0, 5))
        username_entry = ttk.Entry(form_frame, textvariable=self.username_var, width=40)
        username_entry.pack(fill=X, pady=(0, 10))
        
        password_label = ttk.Label(form_frame, text="Master Password:")
        password_label.pack(fill=X, pady=(0, 5))
        password_entry = ttk.Entry(form_frame, textvariable=self.password_var, show="*", width=40)
        password_entry.pack(fill=X, pady=(0, 20))

        # --- Buttons ---
        button_frame = ttk.Frame(form_frame)
        button_frame.pack(fill=X, pady=(10, 10))
        
        login_button = ttk.Button(button_frame, text="Login", command=self.handle_login, bootstyle=SUCCESS)
        login_button.pack(side=LEFT, fill=X, expand=True, padx=(0, 5))

        signup_button = ttk.Button(button_frame, text="Sign Up", command=self.handle_signup, bootstyle=INFO)
        signup_button.pack(side=RIGHT, fill=X, expand=True, padx=(5, 0))
        
        # --- Message Label ---
        message_label = ttk.Label(form_frame, textvariable=self.message_var, foreground="red")
        message_label.pack(pady=(10, 0))

    def handle_login(self):
        """Handles the logic for when the Login button is clicked."""
        username = self.username_var.get()
        password = self.password_var.get()

        if not username or not password:
            self.message_var.set("Username and password cannot be empty.")
            return

        user = database.get_user_by_username(username)

        if user and crypto.verify_master_password(password, user.hashed_master_password):
            self.message_var.set("") # Clear any error messages
            # Derive the key needed for this session
            encryption_key = crypto.derive_key(password)
            # Tell the main app to switch to the main view
            self.app_controller.show_main_view(user, encryption_key)
        else:
            self.message_var.set("Invalid username or password.")

    def handle_signup(self):
        """Handles the logic for when the Sign Up button is clicked."""
        username = self.username_var.get()
        password = self.password_var.get()

        if not username or not password:
            self.message_var.set("Username and password cannot be empty.")
            return
        
        if len(password) < 8:
            self.message_var.set("Password must be at least 8 characters.")
            return

        if database.get_user_by_username(username):
            self.message_var.set("Username already exists.")
            return
            
        try:
            hashed_password = crypto.hash_master_password(password)
            new_user = models.User(id=None, username=username, hashed_master_password=hashed_password)
            database.create_user(new_user)
            self.message_var.set("") # Clear any error messages
            messagebox.showinfo("Success", "Signup successful! You can now log in.")
        except Exception as e:
            self.message_var.set(f"An error occurred: {e}")