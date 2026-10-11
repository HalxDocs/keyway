"""Ports pkg/client/client_test.go TestAuthURL/TestNewValidatesURL/TestExchange."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

from keyway_sso import Identity, KeywayClient, KeywayError


class StubHandler(BaseHTTPRequestHandler):
    """httptest-style stub: only POST /token answers 200, like client_test.go."""

    def do_POST(self):
        if self.path != "/token":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", 0))
        form = dict(parse_qsl(self.rfile.read(length).decode("utf-8")))
        if form.get("code") != "code-1" or form.get("redirect_uri") != "https://app.example/callback":
            body = json.dumps({"error": "invalid_grant", "error_description": "code mismatch"}).encode()
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = json.dumps({"email": "ada@example.com", "name": "Ada", "groups": ["eng"]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class BuildAuthorizeUrlTest(unittest.TestCase):
    def test_full_params(self):
        client = KeywayClient("https://keyway.example")
        url = client.build_authorize_url(
            tenant="acme",
            redirect_uri="https://app.example/callback",
            state="csrf-123",
            connection="conn-1",
        )
        parsed = urlsplit(url)
        self.assertEqual(parsed.path, "/authorize")
        query = dict(parse_qsl(parsed.query))
        self.assertEqual(
            query,
            {
                "tenant": "acme",
                "redirect_uri": "https://app.example/callback",
                "state": "csrf-123",
                "connection": "conn-1",
            },
        )

    def test_omits_empty_state_and_connection(self):
        client = KeywayClient("https://keyway.example")
        url = client.build_authorize_url(tenant="acme", redirect_uri="https://app.example/callback")
        self.assertNotIn("connection=", url)
        self.assertNotIn("state=", url)

    def test_rejects_missing_tenant_or_redirect(self):
        client = KeywayClient("https://keyway.example")
        with self.assertRaises(KeywayError):
            client.build_authorize_url(tenant="", redirect_uri="https://app.example/callback")
        with self.assertRaises(KeywayError):
            client.build_authorize_url(tenant="acme", redirect_uri="")


class ConstructorTest(unittest.TestCase):
    def test_rejects_empty_and_malformed_urls(self):
        with self.assertRaises(KeywayError):
            KeywayClient("")
        with self.assertRaises(KeywayError):
            KeywayClient("   ")
        with self.assertRaises(KeywayError):
            KeywayClient("://bad")

    def test_trims_trailing_slash(self):
        client = KeywayClient("https://keyway.example/")
        url = client.build_authorize_url(tenant="acme", redirect_uri="https://app.example/callback")
        self.assertNotIn("//authorize", url)

    def test_trims_whitespace_and_rejects_hostless(self):
        client = KeywayClient("  https://keyway.example/  ")
        self.assertEqual(client.base_url, "https://keyway.example")
        with self.assertRaises(KeywayError):
            KeywayClient("https:")


class ExchangeCodeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), StubHandler)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_redeems_code_for_identity(self):
        client = KeywayClient(self.base)
        ident = client.exchange_code(code="code-1", redirect_uri="https://app.example/callback")
        self.assertIsInstance(ident, Identity)
        self.assertEqual(ident.email, "ada@example.com")
        self.assertEqual(ident.name, "Ada")
        self.assertEqual(ident.groups, ["eng"])

    def test_rejects_bad_code_with_server_code(self):
        client = KeywayClient(self.base)
        with self.assertRaises(KeywayError) as ctx:
            client.exchange_code(code="bad-code", redirect_uri="https://app.example/callback")
        self.assertEqual(ctx.exception.code, "invalid_grant")
        self.assertIn("code mismatch", ctx.exception.description)

    def test_rejects_missing_code_or_redirect(self):
        client = KeywayClient(self.base)
        with self.assertRaises(KeywayError):
            client.exchange_code(code="", redirect_uri="https://app.example/callback")

    def test_sends_form_encoded_body(self):
        seen = {}

        class SpyHandler(StubHandler):
            def do_POST(self):
                seen["content_type"] = self.headers.get("Content-Type")
                seen["path"] = self.path
                super().do_POST()

        server = ThreadingHTTPServer(("127.0.0.1", 0), SpyHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = KeywayClient(f"http://127.0.0.1:{server.server_port}")
            client.exchange_code(code="code-1", redirect_uri="https://app.example/callback")
            self.assertEqual(seen["content_type"], "application/x-www-form-urlencoded")
            self.assertEqual(seen["path"], "/token")
        finally:
            server.shutdown()
            server.server_close()


class NoEmailTest(unittest.TestCase):
    def test_rejects_identity_without_email(self):
        class NoEmailHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.dumps({"name": "Nope"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), NoEmailHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = KeywayClient(f"http://127.0.0.1:{server.server_port}")
            with self.assertRaises(KeywayError):
                client.exchange_code(code="x", redirect_uri="https://app.example/callback")
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
