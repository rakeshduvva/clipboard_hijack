# clipboardguard/user_intent.py
"""
Detect user-initiated copy events (Ctrl+C / Ctrl+Insert) using pynput.
Expose a tiny API: record recent copy times and query whether a clipboard
change likely came from a user copy.
"""

import time
from threading import Thread
from pynput import keyboard

# how long after a keypress (seconds) we consider a clipboard change as user-initiated
USER_COPY_WINDOW = 1.0

# last timestamp we saw a user copy key combo
_last_user_copy_ts = 0.0
_listener = None

def _on_press(key):
    global _last_user_copy_ts
    try:
        # Key combinations to detect: Ctrl+C, Ctrl+Insert
        # pynput gives Key.ctrl_l/Key.ctrl_r and 'c' char; check modifiers externally
        pass
    except Exception:
        pass

# Instead of low-level detection: use on_release and check modifiers in context
_current_modifiers = set()

def _on_press_inner(key):
    try:
        if key == keyboard.Key.ctrl_l or key == keyboard.Key.ctrl_r:
            _current_modifiers.add('ctrl')
        elif key == keyboard.Key.insert:
            # ctrl+insert is another copy combo variant; we'll check modifiers on release
            _current_modifiers.add('insert')
        elif hasattr(key, 'char') and key.char and key.char.lower() == 'c':
            _current_modifiers.add('c')
    except Exception:
        pass

def _on_release_inner(key):
    global _last_user_copy_ts
    try:
        # if we have ctrl + c pressed together (order independent), mark copy event
        if 'ctrl' in _current_modifiers and 'c' in _current_modifiers:
            _last_user_copy_ts = time.time()
        # ctrl+insert: ctrl + insert
        if 'ctrl' in _current_modifiers and 'insert' in _current_modifiers:
            _last_user_copy_ts = time.time()
    except Exception:
        pass
    # clean modifiers set when keys are released
    try:
        if key == keyboard.Key.ctrl_l or key == keyboard.Key.ctrl_r:
            _current_modifiers.discard('ctrl')
        elif key == keyboard.Key.insert:
            _current_modifiers.discard('insert')
        elif hasattr(key, 'char') and key.char and key.char.lower() == 'c':
            _current_modifiers.discard('c')
    except Exception:
        pass

def start_listener(daemon=True):
    """
    Start the keyboard listener in a background thread. Safe to call multiple times.
    """
    global _listener
    if _listener is not None:
        return
    _listener = keyboard.Listener(on_press=_on_press_inner, on_release=_on_release_inner)
    _listener.daemon = daemon
    _listener.start()

def stop_listener():
    global _listener
    if _listener:
        _listener.stop()
        _listener = None

def was_recent_user_copy(window_seconds=USER_COPY_WINDOW) -> bool:
    """
    Return True if a user copy event (Ctrl+C or Ctrl+Insert) occurred within window_seconds.
    """
    if _last_user_copy_ts == 0.0:
        return False
    return (time.time() - _last_user_copy_ts) <= window_seconds
