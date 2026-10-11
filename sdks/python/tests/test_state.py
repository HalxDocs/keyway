"""Tests for state helpers."""

import re
import unittest

from keyway_sso import CallbackParams, KeywayError, generate_state, parse_callback_url


class GenerateStateTest(unittest.TestCase):
    def test_mints_32_char_hex_and_is_unique(self):
        first, second = generate_state(), generate_state()
        self.assertRegex(first, r"\A[0-9a-f]{32}\Z")
        self.assertNotEqual(first, second)


class ParseCallbackUrlTest(unittest.TestCase):
    def test_extracts_code_and_state(self):
        params = parse_callback_url("https://app.example/callback?code=abc&state=xyz")
        self.assertEqual(params, CallbackParams(code="abc", state="xyz"))

    def test_missing_params_are_empty_strings(self):
        params = parse_callback_url("https://app.example/callback")
        self.assertEqual(params.code, "")
        self.assertEqual(params.state, "")

    def test_rejects_non_string_input(self):
        with self.assertRaises(KeywayError):
            parse_callback_url(None)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
