# main.py

from FRONTEND.app import App

if __name__ == "__main__":
    """
    This is the main entry point for the entire application.
    Running this script will launch the graphical user interface.
    """
    app = App()
    app.mainloop()