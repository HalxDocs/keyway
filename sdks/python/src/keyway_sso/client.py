"""Client talks to one Keyway deployment.

Mirrors Go ``pkg/client.Client``: the base URL is validated once at
construction, :meth:`KeywayClient.build_authorize_url` builds the redirect,
and :meth:`KeywayClient.exchange_code` redeems the single-use code.
Zero runtime dependencies (stdlib ``urllib`` only).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from .errors import KeywayError


@dataclass(frozen=True)
class Identity:
    """Normalized user your app receives after SSO.

    Raw IdP claims never cross this boundary.
    """

    email: str  #: Verified login identifier for account matching.
    name: str = ""  #: Human-readable display name, possibly empty.
    groups: list[str] = field(default_factory=list)  #: Normalized group memberships.


def _is_valid_base_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    # Mirrors Go url.ParseRequestURI: absolute URL with a host is required.
    return bool(parsed.scheme and parsed.hostname)


class KeywayClient:
    """Talks to one Keyway deployment."""

    def __init__(self, base_url: str, timeout: float | None = None) -> None:
        """Build a client for the deployment at ``base_url``.

        The trailing slash is trimmed so URL construction never
        double-slashes. ``timeout`` is the default socket timeout in
        seconds for :meth:`exchange_code` (``None`` means no timeout).
        """
        if not isinstance(base_url, str) or not base_url.strip():
            raise KeywayError("invalid_request", "base URL is required")
        trimmed = base_url.strip().rstrip("/")
        if not _is_valid_base_url(trimmed):
            raise KeywayError("invalid_request", "invalid base URL")
        self._base_url = trimmed
        self._timeout = timeout

    @property
    def base_url(self) -> str:
        return self._base_url

    def build_authorize_url(
        self,
        tenant: str,
        redirect_uri: str,
        state: str = "",
        connection: str = "",
    ) -> str:
        """Build the redirect your app sends the user to.

        ``state`` is your own CSRF token; Keyway echoes it back as
        ``?state=`` alongside ``?code=``. Empty ``state``/``connection``
        are omitted (never leaked as bare keys).
        """
        if not tenant or not redirect_uri:
            raise KeywayError("invalid_request", "tenant and redirect_uri are required")
        params = [("tenant", tenant), ("redirect_uri", redirect_uri)]
        if state:
            params.append(("state", state))
        if connection:
            params.append(("connection", connection))
        return f"{self._base_url}/authorize?{urlencode(params)}"

    def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        timeout: float | None = None,
    ) -> Identity:
        """Redeem one single-use code for its verified identity.

        ``redirect_uri`` must match the one used in
        :meth:`build_authorize_url` or redemption fails closed.
        """
        if not code or not redirect_uri:
            raise KeywayError("invalid_request", "code and redirect_uri are required")
        body = urlencode({"code": code, "redirect_uri": redirect_uri}).encode("utf-8")
        request = Request(
            f"{self._base_url}/token",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        effective_timeout = self._timeout if timeout is None else timeout
        try:
            with urlopen(request, timeout=effective_timeout) as response:
                payload = json.load(response)
        except HTTPError as exc:
            raise self._error_from_http(exc) from exc
        except URLError as exc:
            reason = exc.reason
            detail = str(reason) if reason else "request failed"
            raise KeywayError("network_error", detail) from exc
        return self._identity_from_payload(payload)

    @staticmethod
    def _error_from_http(exc: HTTPError) -> KeywayError:
        code = "invalid_grant"
        description = exc.msg or ""
        try:
            data = json.loads(exc.read().decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            data = None
        if isinstance(data, dict):
            if isinstance(data.get("error"), str) and data["error"]:
                code = data["error"]
            detail = data.get("error_description", data.get("error"))
            if isinstance(detail, str) and detail:
                description = detail
        if not description:
            description = f"request failed with status {exc.code}"
        return KeywayError(code, description, exc.code)

    @staticmethod
    def _identity_from_payload(payload: object) -> Identity:
        if isinstance(payload, dict):
            email = payload.get("email")
            if isinstance(email, str) and email:
                name = payload.get("name")
                groups = payload.get("groups")
                return Identity(
                    email=email,
                    name=name if isinstance(name, str) else "",
                    groups=cast("list[str]", list(groups)) if isinstance(groups, list) else [],
                )
        raise KeywayError("invalid_grant", "identity has no email")
