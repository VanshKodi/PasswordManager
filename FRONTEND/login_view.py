# FRONTEND/login_view.py

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox

# Import backend modules
from BACKEND import database, crypto, models
# --- NEW --- Import the new recovery setup view
from .recovery_setup_view import RecoverySetupView
# Add this with your other imports
from .forgot_password_view import ForgotPasswordView

class LoginView(ttk.Frame):
    """The view for handling user login and signup."""
    def __init__(self, master, app_controller):
        super().__init__(master, padding=(20, 20))
        self.app_controller = app_controller

        # --- Instance Variables ---
        self.username_var = ttk.StringVar()
        self.password_var = ttk.StringVar()
        self.message_var = ttk.StringVar()
        # --- NEW --- Dictionary to track failed login attempts per user
        self.failed_attempts = {}

        # --- Widget Creation ---
        self.create_widgets()

    def create_widgets(self):
        """Creates and lays out the widgets for the login form."""
        form_frame = ttk.Frame(self)
        form_frame.place(relx=0.5, rely=0.5, anchor=CENTER)
        
        title_label = ttk.Label(form_frame, text="Password Manager", font=("Helvetica", 24, "bold"))
        title_label.pack(pady=(0, 20))
        
        username_label = ttk.Label(form_frame, text="Username:")
        username_label.pack(fill=X, pady=(0, 5))
        username_entry = ttk.Entry(form_frame, textvariable=self.username_var, width=40)
        username_entry.pack(fill=X, pady=(0, 10))
        
        password_label = ttk.Label(form_frame, text="Master Password:")
        password_label.pack(fill=X, pady=(0, 5))
        password_entry = ttk.Entry(form_frame, textvariable=self.password_var, show="*", width=40)
        password_entry.pack(fill=X, pady=(0, 20))

        button_frame = ttk.Frame(form_frame)
        button_frame.pack(fill=X, pady=(10, 10))
        
        login_button = ttk.Button(button_frame, text="Login", command=self.handle_login, bootstyle=SUCCESS)
        login_button.pack(side=LEFT, fill=X, expand=True, padx=(0, 5))

        signup_button = ttk.Button(button_frame, text="Sign Up", command=self.handle_signup, bootstyle=INFO)
        signup_button.pack(side=RIGHT, fill=X, expand=True, padx=(5, 0))
        
        message_label = ttk.Label(form_frame, textvariable=self.message_var, foreground="red")
        message_label.pack(pady=(10, 0))

        # --- NEW --- "Forgot Password?" button
        forgot_pass_button = ttk.Button(form_frame, text="Forgot Password?", command=self.open_forgot_password_window, bootstyle=(LINK, PRIMARY))
        forgot_pass_button.pack(pady=(10, 0))

    def handle_login(self):
        """Handles the logic for when the Login button is clicked."""
        username = self.username_var.get()
        password = self.password_var.get()

        if not username or not password:
            self.message_var.set("Username and password cannot be empty.")
            return

        user = database.get_user_by_username(username)
        login_successful = user and crypto.verify_master_password(password, user.hashed_master_password)

        if login_successful:
            self.message_var.set("")
            if username in self.failed_attempts:
                del self.failed_attempts[username] # Reset counter on success
            
            encryption_key = crypto.derive_key(password)
            self.app_controller.show_main_view(user, encryption_key)
        else:
            # --- MODIFIED --- Handle failed attempts and hints
            self.failed_attempts[username] = self.failed_attempts.get(username, 0) + 1
            
            error_message = "Invalid username or password."
            if self.failed_attempts.get(username, 0) >= 2 and user and user.password_hint:
                error_message += f"\nHint: {user.password_hint}"
            
            self.message_var.set(error_message)
    def open_forgot_password_window(self):
        """Opens the password recovery window."""
        ForgotPasswordView(self)

    def handle_signup(self):
        """
        --- MODIFIED ---
        Handles the initial validation for signup and then opens the recovery setup window.
        """
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
            
        # If initial validation passes, open the recovery setup window
        self.message_var.set("") # Clear any previous errors
        RecoverySetupView(self, username, password)
        # The RecoverySetupView window will now handle the rest of the signup process.
        # After it closes, we can clear the fields here.
        self.username_var.set("")
        self.password_var.set("")
    
    # Replace the old placeholder function with this
def open_forgot_password_window(self):
    """Opens the password recovery window."""
    ForgotPasswordView(self)