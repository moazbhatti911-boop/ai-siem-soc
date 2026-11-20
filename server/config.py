"""Server configuration, read from the environment (and ``.env``).

Values are read dynamically (not only at import time) so tests can override
them with environment variables before each test.
"""

import os

from dotenv import load_dotenv

load_dotenv()

DEFAULT_API_KEY = "change-this-api-key"


def api_key() -> str:
    """API key clients must send in the ``X-API-Key`` header."""
    return os.environ.get("SIEM_API_KEY", DEFAULT_API_KEY)


def server_url() -> str:
    """Base URL this server listens on (for clients and the dashboard)."""
    return os.environ.get("SIEM_SERVER_URL", "http://127.0.0.1:8003")


def db_path() -> str:
    """SQLite database file (``SIEM_DB_PATH`` overrides the default)."""
    return os.environ.get("SIEM_DB_PATH", "siem.db")


def port() -> int:
    """Port for uvicorn (default 8003)."""
    return int(os.environ.get("SIEM_PORT", "8003"))
