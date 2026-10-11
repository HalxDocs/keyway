"""Minimal Keyway-integrated app — Python port of examples/demo-sso/main.go.

Home page mints a state cookie + login link; /callback verifies state
first, then redeems the single-use code. Zero dependencies (stdlib only).

    PYTHONPATH=src python3 examples/demo_callback.py
    # open http://localhost:3000, click Log in with SSO
"""

import html
import os
import secrets
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from keyway_sso import KeywayClient, KeywayError, generate_state, parse_callback_url

KEYWAY = os.environ.get("KEYWAY_URL", "http://127.0.0.1:8080")
TENANT = os.environ.get("KEYWAY_TENANT", "acme")
REDIRECT = os.environ.get("APP_REDIRECT", "http://localhost:3000/callback")
CONNECTION = os.environ.get("KEYWAY_CONNECTION", "")
PORT = int(os.environ.get("PORT", "3000"))

client = KeywayClient(KEYWAY)


def get_cookie(handler: BaseHTTPRequestHandler, name: str) -> str:
    cookie = SimpleCookie(handler.headers.get("Cookie", ""))
    morsel = cookie.get(name)
    return morsel.value if morsel else ""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path == "/":
            state = generate_state()
            login_url = client.build_authorize_url(
                tenant=TENANT, redirect_uri=REDIRECT, state=state, connection=CONNECTION
            )
            body = (
                f'<h1>demo-sso (python)</h1><p><a href="{html.escape(login_url)}">'
                "Log in with SSO</a></p>"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header(
                "Set-Cookie", f"keyway_state={state}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300"
            )
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/callback":
            params = parse_callback_url(f"http://localhost{self.path}")
            want = get_cookie(self, "keyway_state")
            # compare_digest needs ASCII-only str; guard first so odd input
            # fails closed with 400 instead of raising a 500.
            state_ok = (
                bool(want)
                and bool(params.state)
                and want.isascii()
                and params.state.isascii()
                and secrets.compare_digest(params.state, want)
            )
            if not state_ok:
                self.send_error(400, "state mismatch: login did not start here")
                return
            try:
                ident = client.exchange_code(code=params.code, redirect_uri=REDIRECT)
            except KeywayError as exc:
                self.send_error(502, f"exchange failed: {exc}")
                return
            body = (
                "<h1>logged in</h1>"
                f"<p>email: {html.escape(ident.email)}</p>"
                f"<p>name: {html.escape(ident.name)}</p>"
                f"<p>groups: {html.escape(', '.join(ident.groups))}</p>"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"demo listening on http://localhost:{PORT} for tenant {TENANT!r}")
    server.serve_forever()
