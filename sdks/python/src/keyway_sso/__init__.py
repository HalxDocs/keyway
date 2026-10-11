"""keyway-sso: Python SDK for Keyway — one OAuth2-style login flow for SAML and OIDC."""

from .client import Identity, KeywayClient
from .errors import KeywayError
from .state import CallbackParams, generate_state, parse_callback_url

__all__ = [
    "CallbackParams",
    "Identity",
    "KeywayClient",
    "KeywayError",
    "generate_state",
    "parse_callback_url",
]

__version__ = "0.1.0"
