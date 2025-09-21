# FRONTEND/app.py

import ttkbootstrap as ttk
from ttkbootstrap.constants import *

# We will create these view files next
from .login_view import LoginView
from .main_view import MainView

# Import the database initialization function from our backend
from BACKEND import database

class App(ttk.Window):
    """The main application window and controller."""
    def __init__(self):
        # Initialize the main window with a theme
        super().__init__(themename="darkly")
        self.title("Password Manager")
        self.geometry("800x600")

        # --- One-time database setup ---
        # Ensure the database and tables are created before the UI starts
        database.initialize_database()

        self.current_user = None
        self.encryption_key = None
        
        # This frame will hold the current view (Login or Main)
        self.container = ttk.Frame(self)
        self.container.pack(side=TOP, fill=BOTH, expand=True)

        # Show the login view initially
        self.show_login_view()

    def show_login_view(self):
        """Clears the container and displays the LoginView."""
        # Destroy the previous view if it exists
        for widget in self.container.winfo_children():
            widget.destroy()
        
        # Create and display the login view
        # We pass 'self' so the login view can call back to the App
        login_frame = LoginView(master=self.container, app_controller=self)
        login_frame.pack(fill=BOTH, expand=True)

    def show_main_view(self, user, key):
        """
        Clears the container and displays the MainView after a successful login.
        
        Args:
            user (User): The authenticated user object from the database.
            key (bytes): The encryption key derived from the user's master password.
        """
        self.current_user = user
        self.encryption_key = key
        
        # Destroy the previous view (the login frame)
        for widget in self.container.winfo_children():
            widget.destroy()
        
        # Create and display the main application view
        main_frame = MainView(master=self.container, app_controller=self)
        main_frame.pack(fill=BOTH, expand=True)

    def logout(self):
        """Logs the current user out and returns to the login view."""
        self.current_user = None
        self.encryption_key = None
        self.show_login_view()

if __name__ == '__main__':
    # This block is for testing this file directly, but the final app
    # will be launched from the root main.py file.
    app = App()
    app.mainloop()