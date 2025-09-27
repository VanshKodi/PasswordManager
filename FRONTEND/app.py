# FRONTEND/app.py

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import queue
import time
import shutil
import datetime
import os
from pynput import keyboard

from .login_view import LoginView
from .main_view import MainView
from BACKEND import database, crypto
from BACKEND.key_listener import KeyListenerThread
from BACKEND.config import ROOT_DIR

class App(ttk.Window):
    """The main application window and controller."""
    def __init__(self):
        super().__init__(themename="darkly")
        self.title("Password Manager")
        self.geometry("900x600")

        database.initialize_database()

        self.current_user = None
        self.encryption_key = None
        
        # --- Background Services & Communication ---
        self.key_listener_thread = None
        self.autosave_timer_id = None
        self.hotkey_queue = queue.Queue()
        self.buffer_queue = queue.Queue()
        self.pynput_controller = keyboard.Controller()
        self.autofilter_enabled = False
        
        # A dedicated queue to hold the strings for the two-press auto-type
        self.autotype_queue = queue.Queue()
        
        self.container = ttk.Frame(self)
        self.container.pack(side=TOP, fill=BOTH, expand=True)

        self.show_login_view()

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
        hotkey_str = database.get_setting('autotype_hotkey')
        buffer_size = int(database.get_setting('autofilter_length'))
        self.key_listener_thread = KeyListenerThread(self.hotkey_queue, self.buffer_queue, hotkey_str, buffer_size)
        self.key_listener_thread.start()
        self._schedule_autosave()
        self._process_queues()

    def _stop_background_services(self):
        print("Stopping background services...")
        if self.key_listener_thread:
            self.key_listener_thread.stop()
            self.key_listener_thread.join()
        if self.autosave_timer_id:
            self.after_cancel(self.autosave_timer_id)

    def _schedule_autosave(self):
        if self.autosave_timer_id:
            self.after_cancel(self.autosave_timer_id)
        interval_min = int(database.get_setting('autosave_interval'))
        interval_ms = interval_min * 60 * 1000
        self.autosave_timer_id = self.after(interval_ms, self._perform_autosave)
        print(f"Next autosave scheduled in {interval_min} minutes.")

    def _perform_autosave(self):
        try:
            db_path = os.path.join(ROOT_DIR, "password_manager.db")
            backup_dir = database.get_setting('autosave_directory')
            limit = int(database.get_setting('autosave_limit'))
            if not os.path.exists(backup_dir): os.makedirs(backup_dir)
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            backup_path = os.path.join(backup_dir, f"backup_{timestamp}.db")
            shutil.copy2(db_path, backup_path)
            print(f"Database backed up to {backup_path}")
            backups = sorted([f for f in os.listdir(backup_dir) if f.startswith('backup_') and f.endswith('.db')],
                             key=lambda f: os.path.getmtime(os.path.join(backup_dir, f)))
            while len(backups) > limit:
                os.remove(os.path.join(backup_dir, backups[0]))
                print(f"Removed old backup: {backups[0]}")
                backups.pop(0)
        except Exception as e:
            print(f"Error during autosave: {e}")
        finally:
            self._schedule_autosave()

    def _process_queues(self):
        try:
            if not self.hotkey_queue.empty():
                message = self.hotkey_queue.get_nowait()
                if message == "HOTKEY_PRESSED":
                    
                    # If the queue has items, type the next one.
                    if not self.autotype_queue.empty():
                        string_to_type = self.autotype_queue.get()
                        print(f"Hotkey pressed, typing next item from queue.")
                        self._autotype_string(string_to_type)
                        
                        # If the queue is now empty, the sequence is over.
                        if self.autotype_queue.empty():
                            self.disarm_credential("auto-type queue empty")
                
                # Clear any lingering hotkey signals to prevent repeats.
                with self.hotkey_queue.mutex:
                    self.hotkey_queue.queue.clear()

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
        """Releases modifiers and simulates typing of a given string."""
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
        """Clears the queue and populates it with username and password for two-press typing."""
        with self.autotype_queue.mutex:
            self.autotype_queue.queue.clear()
            
        password = crypto.decrypt_password(credential.encrypted_password, self.encryption_key)
        self.autotype_queue.put(credential.username)
        self.autotype_queue.put(password)
        
        self.title(f"Password Manager (ARMED: {credential.service_name})")
        print("Credential armed. Queue populated with username and password.")

    def disarm_credential(self, reason=""):
        """Disarms the credential by clearing the queue, title, and selection."""
        with self.autotype_queue.mutex:
            self.autotype_queue.queue.clear()
        self.title("Password Manager")
        
        if self.main_view_frame:
            self.main_view_frame.clear_selection()
            
        print(f"Credential disarmed. Reason: {reason}")
        
    def set_autofilter_state(self, is_enabled: bool):
        self.autofilter_enabled = is_enabled
        print(f"Auto-filter {'enabled' if is_enabled else 'disabled'}.")
        self.main_view_frame.search_var.set("")  # Clear search box when toggling