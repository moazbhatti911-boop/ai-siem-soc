"""API-key authentication for the server.

Clients send ``X-API-Key: <key>``. The expected key comes from ``.env``
(``SIEM_API_KEY``). A missing or wrong key gets HTTP 401, not a 422.
"""

from fastapi import Header, HTTPException

from server import config


async def require_api_key(x_api_key: str | None = Header(default=None)) -> str:
    """FastAPI dependency: reject requests without the correct API key."""
    if x_api_key is None or x_api_key != config.api_key():
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return x_api_key
