# BACKEND/key_listener.py

import threading
from pynput import keyboard
from collections import deque
import time

class KeyListenerThread(threading.Thread):
    """
    Global hotkeys continue to work.
    Auto-filter buffer only receives alphabetic characters [a-zA-Z].
    """
    def __init__(self, hotkey_queue, buffer_queue, hide_queue, autotype_hotkey_str, hide_hotkey_str, buffer_size):
        super().__init__(daemon=True)
        self._stop_event = threading.Event()

        # Queues
        self.hotkey_queue = hotkey_queue
        self.buffer_queue = buffer_queue
        self.hide_queue = hide_queue

        # Hotkey strings for GlobalHotKeys
        self.autotype_hotkey_str = autotype_hotkey_str or "<ctrl>+."
        self.hide_hotkey_str = hide_hotkey_str or "<ctrl>+["

        # Auto-filter state
        self.buffer_size = buffer_size
        self._buffer = deque(maxlen=self.buffer_size)
        self._last_key_time = time.time()

    # Hotkey callbacks
    def _on_autotype_activate(self):
        self.hotkey_queue.put("HOTKEY_PRESSED")

    def _on_hide_activate(self):
        self.hide_queue.put("TOGGLE_HIDE")

    # Only letters go into buffer
    def on_press_wrapper(self, key):
        if self._stop_event.is_set():
            return False

        now = time.time()
        if now - self._last_key_time > 1.0:
            self._buffer.clear()

        try:
            # Accept only alphanumeric KeyCode chars (Unicode letters and numbers) [a-zA-Z0-9] by default keyboards
            if isinstance(key, keyboard.KeyCode) and key.char is not None and key.char.isalnum():  # [web:246][web:251]
                self._buffer.append(key.char)
            elif key == keyboard.Key.backspace:
                if self._buffer:
                    self._buffer.pop()
            # All other keys (modifiers, punctuation, brackets, function keys) are ignored for the buffer.
        except Exception:
            pass
        finally:
            self._last_key_time = now

        self.buffer_queue.put("".join(self._buffer))
        return True

    def run(self):
        hotkeys = {
            self.autotype_hotkey_str: self._on_autotype_activate,
            self.hide_hotkey_str: self._on_hide_activate,
        }
        with keyboard.GlobalHotKeys(hotkeys) as h:
            with keyboard.Listener(on_press=self.on_press_wrapper) as listener:
                h.join()
                listener.join()

    def stop(self):
        self._stop_event.set()
        controller = keyboard.Controller()
        controller.press(keyboard.Key.f12)
        controller.release(keyboard.Key.f12)
