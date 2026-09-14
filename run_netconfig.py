"""Desktop launch target for PyInstaller; opens no external services."""

import threading
import webbrowser

import uvicorn


def open_browser() -> None:
    webbrowser.open("http://127.0.0.1:8765")


if __name__ == "__main__":
    threading.Timer(0.8, open_browser).start()
    uvicorn.run("app.main:app", host="127.0.0.1", port=8765, log_level="warning")
