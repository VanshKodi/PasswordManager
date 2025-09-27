# BACKEND/key_listener.py

import threading
from collections import deque
from pynput import keyboard

class KeyListenerThread(threading.Thread):
    """
    A background thread that listens for global keyboard events.
    It detects a specific hotkey and maintains a rolling buffer of key presses.
    """

    def __init__(self, hotkey_queue, buffer_queue, hotkey_str, buffer_size):
        super().__init__(daemon=True)
        self.hotkey_queue = hotkey_queue
        self.buffer_queue = buffer_queue
        self.buffer_size = buffer_size
        
        self.hotkey = keyboard.HotKey(
            keyboard.HotKey.parse(hotkey_str),
            self._on_hotkey_activate
        )
        self._buffer = deque(maxlen=self.buffer_size)
        self.listener = None

    def _on_press(self, key):
        """Callback for general key presses to update the buffer."""
        if key == keyboard.Key.backspace:
            if self._buffer:
                self._buffer.pop()
        elif hasattr(key, 'char') and key.char:
            self._buffer.append(key.char)

        current_buffer_str = "".join(self._buffer)
        self.buffer_queue.put(current_buffer_str)

    def _on_hotkey_activate(self):
        """Callback for when the registered hotkey is pressed."""
        self.hotkey_queue.put("HOTKEY_PRESSED")

    def run(self):
        """The main loop for the thread."""
        def on_press_wrapper(key):
            self._on_press(key)
            self.hotkey.press(self.listener.canonical(key))

        def on_release_wrapper(key):
            self.hotkey.release(self.listener.canonical(key))
            
        self.listener = keyboard.Listener(
            on_press=on_press_wrapper,
            on_release=on_release_wrapper,
            # Use supress=False to avoid blocking hotkeys like media keys
            suppress=False 
        )
        
        print("Key listener thread started...")
        self.listener.start()
        self.listener.join() # This keeps the thread alive
        print("Key listener thread stopped.")


    def stop(self):
        """Signals the listener to stop."""
        if self.listener:
            self.listener.stop()