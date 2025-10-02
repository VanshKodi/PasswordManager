# BACKEND/key_listener.py

import threading
from pynput import keyboard
from collections import deque
import time

class KeyListenerThread(threading.Thread):
    """
    A background thread that listens for multiple global hotkeys and general keyboard input.
    """
    def __init__(self, hotkey_queue, buffer_queue, hide_queue, autotype_hotkey_str, hide_hotkey_str, buffer_size):
        super().__init__(daemon=True)
        self._stop_event = threading.Event()
    
        # Communication queues
        self.hotkey_queue = hotkey_queue
        self.buffer_queue = buffer_queue
        self.hide_queue = hide_queue
    
        # Hotkey configurations with defaults
        self.autotype_hotkey_str = autotype_hotkey_str or "<ctrl>+."
        self.hide_hotkey_str = hide_hotkey_str or "<ctrl>+["
    
        # Buffer for auto-filter
        self.buffer_size = buffer_size
        self._buffer = deque(maxlen=self.buffer_size)
        self._last_key_time = time.time()

    def _on_autotype_activate(self):
        """Callback when the auto-type hotkey is pressed."""
        print("Auto-type hotkey detected!")
        self.hotkey_queue.put("HOTKEY_PRESSED")

    def _on_hide_activate(self):
        """Callback when the hide/show hotkey is pressed."""
        print("Hide/Show hotkey detected!")
        self.hide_queue.put("TOGGLE_HIDE")

    def on_press_wrapper(self, key):
        """
        Handles regular key presses for the auto-filter buffer.
        Returns False if the listener should stop.
        """
        if self._stop_event.is_set():
            return False # Stop the listener

        # Auto-filter buffer logic
        current_time = time.time()
        # Clear buffer if user pauses typing for more than a second
        if current_time - self._last_key_time > 1.0:
            self._buffer.clear()
        
        try:
            # Add character to buffer if it's alphanumeric/symbol
            if hasattr(key, 'char') and key.char is not None:
                self._buffer.append(key.char)
            # Handle backspace
            elif key == keyboard.Key.backspace:
                if self._buffer:
                    self._buffer.pop()
        except Exception:
            # Ignore special keys that don't have a 'char' attribute
            pass
        finally:
            self._last_key_time = current_time
        
        # Send updated buffer to the main thread
        self.buffer_queue.put("".join(self._buffer))
        return True

    def run(self):
        """The main loop for the listener thread."""
        print("Key listener thread started...")
        
        # pynput's recommended way of handling multiple, specific hotkeys
        hotkeys = {
            self.autotype_hotkey_str: self._on_autotype_activate,
            self.hide_hotkey_str: self._on_hide_activate
        }

        # This structure runs the hotkey listener and general key listener concurrently
        with keyboard.GlobalHotKeys(hotkeys) as h:
            with keyboard.Listener(on_press=self.on_press_wrapper) as listener:
                h.join()
                listener.join()
        
        print("Key listener thread stopped.")

    def stop(self):
        """Signals the thread to stop."""
        print("Key listener thread stopping...")
        self._stop_event.set()
        
        # This is a trick to unblock the listener.join() call in run()
        # It simulates a key press to wake the listener up so it can exit
        controller = keyboard.Controller()
        controller.press(keyboard.Key.f12)
        controller.release(keyboard.Key.f12)