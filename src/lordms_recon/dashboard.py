"""Optional local report server."""

from __future__ import annotations

from pathlib import Path


def launch_dashboard(folder: Path) -> None:
    try:
        from flask import Flask, send_from_directory
    except ImportError as exc:
        raise RuntimeError('Dashboard support is not installed. Run: pip install ".[dashboard]"') from exc

    app = Flask(__name__)

    @app.get("/")
    def report():
        return send_from_directory(folder, "report.html")

    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
