# FRONTEND/app.py

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import queue
import time
from pynput import keyboard

from .login_view import LoginView
from .main_view import MainView
from BACKEND import database, crypto
from BACKEND.key_listener import KeyListenerThread

class App(ttk.Window):
    """The main application window and controller."""
    def __init__(self):
        super().__init__(themename="darkly")
        self.title("Password Manager")
        self.geometry("900x600")

        database.initialize_database()

        self.current_user = None
        self.encryption_key = None
        self.is_window_visible = True

        # --- Background Services & Communication ---
        self.key_listener_thread = None
        self.hotkey_queue = queue.Queue()
        self.buffer_queue = queue.Queue()
        self.hide_queue = queue.Queue()
        self.pynput_controller = keyboard.Controller()
        self.autofilter_enabled = False
        
        self.autotype_queue = queue.Queue()
        
        self.container = ttk.Frame(self)
        self.container.pack(side=TOP, fill=BOTH, expand=True)

        self.show_login_view()

    # <-- 1. THIS IS THE METHOD THAT HIDES/SHOWS THE WINDOW
    def _toggle_window_visibility(self):
        """Hides or shows the main window."""
        if self.is_window_visible:
            self.withdraw() # This is the tkinter method to hide the window
            self.is_window_visible = False
            print("Window hidden.")
        else:
            self.deiconify() # This is the tkinter method to show the window
            self.is_window_visible = True
            print("Window shown.")

    def show_login_view(self):
        for widget in self.container.winfo_children():
            widget.destroy()
        login_frame = LoginView(master=self.container, app_controller=self)
        login_frame.pack(fill=BOTH, expand=True)

    def show_main_view(self, user, key):
        self.current_user = user
        self.encryption_key = key
        
        for widget in self.container.winfo_children():
            widget.destroy()
        
        self.main_view_frame = MainView(master=self.container, app_controller=self)
        self.main_view_frame.pack(fill=BOTH, expand=True)
        
        self._start_background_services()

    def logout(self):
        self._stop_background_services()
        self.current_user = None
        self.encryption_key = None
        self.show_login_view()

    def _start_background_services(self):
        print("Starting background services...")
        autotype_hotkey_str = database.get_setting('autotype_hotkey')
        hide_hotkey_str = database.get_setting('hide_hotkey') 
        buffer_size = int(database.get_setting('autofilter_length'))
        
        self.key_listener_thread = KeyListenerThread(
            hotkey_queue=self.hotkey_queue, 
            buffer_queue=self.buffer_queue, 
            hide_queue=self.hide_queue, 
            autotype_hotkey_str=autotype_hotkey_str, 
            hide_hotkey_str=hide_hotkey_str,
            buffer_size=buffer_size
        )
        self.key_listener_thread.start()
        self._process_queues()

    def _stop_background_services(self):
        print("Stopping background services...")
        if self.key_listener_thread and self.key_listener_thread.is_alive():
            self.key_listener_thread.stop()
            self.key_listener_thread.join()
    
    def _process_queues(self):
        try:
            # Check for Auto-Type Hotkey
            if not self.hotkey_queue.empty():
                message = self.hotkey_queue.get_nowait()
                if message == "HOTKEY_PRESSED":
                    if not self.autotype_queue.empty():
                        string_to_type = self.autotype_queue.get()
                        print(f"Hotkey pressed, typing next item from queue.")
                        self._autotype_string(string_to_type)
                        if self.autotype_queue.empty():
                            self.disarm_credential("auto-type queue empty")
                with self.hotkey_queue.mutex:
                    self.hotkey_queue.queue.clear()

            # <-- 2. THIS BLOCK CHECKS THE QUEUE AND CALLS THE HIDE METHOD
            if not self.hide_queue.empty():
                message = self.hide_queue.get_nowait()
                if message == "TOGGLE_HIDE":
                    self._toggle_window_visibility()
                with self.hide_queue.mutex:
                    self.hide_queue.queue.clear()

            # Check for Auto-Filter Buffer
            if not self.buffer_queue.empty() and self.autofilter_enabled:
                buffer_str = self.buffer_queue.get_nowait()
                self.main_view_frame.search_var.set(buffer_str)
                self.main_view_frame.filter_treeview()

        except queue.Empty:
            pass
        finally:
            self.after(100, self._process_queues)

    def on_settings_changed(self):
        print("Settings changed, restarting background services...")
        self._stop_background_services()
        self._start_background_services()

    def _autotype_string(self, string_to_type: str):
        time.sleep(0.05) 
        modifiers = [
            keyboard.Key.ctrl_l, keyboard.Key.ctrl_r,
            keyboard.Key.alt_l, keyboard.Key.alt_r,
            keyboard.Key.shift_l, keyboard.Key.shift_r
        ]
        for key in modifiers:
            self.pynput_controller.release(key)
        self.pynput_controller.type(string_to_type)

    def arm_credential_for_autotype(self, credential):
        with self.autotype_queue.mutex:
            self.autotype_queue.queue.clear()
        password = crypto.decrypt_password(credential.encrypted_password, self.encryption_key)
        self.autotype_queue.put(credential.username)
        self.autotype_queue.put(password)
        self.title(f"Password Manager (ARMED: {credential.service_name})")
        print("Credential armed. Queue populated with username and password.")

    def disarm_credential(self, reason=""):
        with self.autotype_queue.mutex:
            self.autotype_queue.queue.clear()
        self.title("Password Manager")
        print(f"Credential disarmed. Reason: {reason}")
        
    def set_autofilter_state(self, is_enabled: bool):
        self.autofilter_enabled = is_enabled
        print(f"Auto-filter {'enabled' if is_enabled else 'disabled'}.")
        self.main_view_frame.search_var.set("")