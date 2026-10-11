"""State helpers: CSRF token minting and callback parsing."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

from .errors import KeywayError


def generate_state() -> str:
    """Mint one random CSRF state token (16 bytes, hex)."""
    return secrets.token_hex(16)


@dataclass(frozen=True)
class CallbackParams:
    """Extracted ``?code=`` / ``?state=`` from an app callback URL.

    Missing params are empty strings (not ``None``) so the caller can fail
    closed the same way the Go demo does before calling exchange.
    """

    code: str = ""
    state: str = ""


def parse_callback_url(url: str) -> CallbackParams:
    """Extract :class:`CallbackParams` from an app callback URL."""
    if not isinstance(url, str):
        raise KeywayError("invalid_request", "unreadable callback URL")
    try:
        query = urlsplit(url).query
    except ValueError as exc:
        raise KeywayError("invalid_request", "unreadable callback URL") from exc
    params = parse_qs(query, keep_blank_values=True)
    code = params.get("code", [""])[0]
    state = params.get("state", [""])[0]
    return CallbackParams(code=code, state=state)
