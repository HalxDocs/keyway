"""Single error type raised by keyway-sso.

``code`` passes through the server's stable ``error`` field so callers can
branch on it (``invalid_request``, ``invalid_grant``, ``login_failed``, ...).
``description`` carries the human-readable ``error_description``.
"""


class KeywayError(Exception):
    def __init__(self, code: str, description: str, status: int | None = None) -> None:
        message = f"{code}: {description}" if description else code
        super().__init__(message)
        self.code = code
        self.description = description or ""
        self.status = status
