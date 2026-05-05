# launcher.py
# This is the entry point PyInstaller will use.
# It starts Flask in a background thread and opens the browser.

import sys
import os
import threading
import webbrowser

# Ensure the bundled app can find its files
if getattr(sys, 'frozen', False):
    base_dir = sys._MEIPASS
    os.chdir(os.path.dirname(sys.executable))
else:
    base_dir = os.path.dirname(os.path.abspath(__file__))

# Add base_dir to path so local modules are found
sys.path.insert(0, os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else base_dir)

from flask_app import app

def open_browser():
    webbrowser.open("http://127.0.0.1:5000")

if __name__ == "__main__":
    threading.Timer(1.5, open_browser).start()
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
