# keyway-sso

Python SDK for [Keyway](https://github.com/HalxDocs/keyway) — one OAuth2-style login flow for SAML and OIDC. Zero runtime dependencies (stdlib `urllib` only), fully typed (`py.typed`), Python 3.10+.

```sh
pip install keyway-sso
```

> Note: plain `keyway` is taken on PyPI by an unrelated package, hence `keyway-sso` (imported as `keyway_sso`).

```python
from keyway_sso import KeywayClient, generate_state, parse_callback_url

keyway = KeywayClient("http://127.0.0.1:8080")

# 1. Send the user to Keyway (store `state` in an HttpOnly cookie first).
state = generate_state()
login_url = keyway.build_authorize_url(
    tenant="acme",
    redirect_uri="http://localhost:3000/callback",
    state=state,
    # connection="conn-abc",  # required only when the tenant has 2+ active connections
)

# 2. On GET /callback: verify state BEFORE touching the code.
params = parse_callback_url(request.url)
if params.state != stored_state:
    raise Exception("state mismatch")

# 3. Swap the single-use code (60s, redirect_uri-bound) for the identity.
ident = keyway.exchange_code(code=params.code, redirect_uri="http://localhost:3000/callback")
print(ident.email, ident.name, ident.groups)
```

See `examples/demo_callback.py` — a dependency-free port of Go `examples/demo-sso`:

```sh
PYTHONPATH=src python3 examples/demo_callback.py
# open http://localhost:3000, click Log in with SSO
```

## API

| Method | Mirrors Go | Notes |
|---|---|---|
| `KeywayClient(base_url, timeout=None)` | `client.New` | Trims trailing `/`, raises `KeywayError` on empty/bad URL |
| `build_authorize_url(tenant, redirect_uri, state="", connection="")` | `Client.AuthURL` | Omits empty `state`/`connection` keys |
| `exchange_code(code, redirect_uri, timeout=None)` | `Client.Exchange` | `POST /token` form-encoded; raises `KeywayError` |
| `generate_state()` | demo `newState` | 16 random bytes via `secrets`, hex |
| `parse_callback_url(url)` | demo `handleCallback` | Returns `CallbackParams(code, state)` (`""` when missing) |

Errors: `KeywayError(code, description, status=None)`. `code` is the server's stable `error` field (`invalid_request`, `invalid_grant`, ...), so branch on it. `str(err)` renders `"code: description"`.

`Identity` is a frozen dataclass: `email: str`, `name: str = ""`, `groups: list[str]`.

## Parity

Same contract as `pkg/client`, `keyway-js`, and `keyway-ts`: exact-match `redirect_uri`, 60s single-use code, `state` round-trip, `{"email","name","groups"}` only — raw IdP claims never cross the boundary.
