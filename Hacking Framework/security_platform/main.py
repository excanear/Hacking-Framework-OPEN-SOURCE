"""
Security Platform — top-level entry point.

Run with:
    python main.py                   # start API server (development)
    uvicorn api.server:app --reload  # hot-reload development
"""

from __future__ import annotations

import uvicorn

from api.server import app  # noqa: F401 — ensure app is importable as module


def main() -> None:
    uvicorn.run(
        "api.server:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
