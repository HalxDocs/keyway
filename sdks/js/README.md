# keyway-js

JavaScript SDK for [Keyway](https://github.com/HalxDocs/keyway) — one OAuth2-style login flow for SAML and OIDC. Zero runtime dependencies, works on Node 18+ and in the browser (via bundler). Dual ESM + CJS.

```js
// ESM
import { KeywayClient } from "keyway-js";
// CJS
const { KeywayClient } = require("keyway-js");
```

## Quickstart

```js
import { KeywayClient, generateState, parseCallbackUrl } from "keyway-js";

const keyway = new KeywayClient("http://127.0.0.1:8080");

// 1. Send the user to Keyway (store `state` in an HttpOnly cookie first).
const state = generateState();
const loginUrl = keyway.buildAuthorizeUrl({
  tenant: "acme",
  redirectUri: "http://localhost:3000/callback",
  state,
  // connection: "conn-abc", // required only when the tenant has 2+ active connections
});

// 2. On GET /callback: verify state BEFORE touching the code.
const { code, state: returned } = parseCallbackUrl(req.url);
if (returned !== storedState) throw new Error("state mismatch");

// 3. Swap the single-use code (60s, redirect_uri-bound) for the identity.
const { email, name, groups } = await keyway.exchangeCode({
  code,
  redirectUri: "http://localhost:3000/callback",
});
```

See `examples/express-callback.js` — a dependency-free port of Go `examples/demo-sso`.

## API

| Method | Mirrors Go | Notes |
|---|---|---|
| `new KeywayClient(baseUrl, {fetch?, timeoutMs?})` | `client.New` | Trims trailing `/`, throws `KeywayError` on empty/bad URL |
| `buildAuthorizeUrl({tenant, redirectUri, state?, connection?})` | `Client.AuthURL` | Omits empty `state`/`connection` keys |
| `exchangeCode({code, redirectUri, signal?})` | `Client.Exchange` | `POST /token` form-encoded; throws `KeywayError` |
| `generateState()` | demo `newState` | 16 random bytes, hex |
| `parseCallbackUrl(url)` | demo `handleCallback` | Returns `{code, state}` (`""` when missing) |

Errors: `KeywayError { code, description, status }`. `code` is the server's stable `error` field (`invalid_request`, `invalid_grant`, ...), so switch on it.

## Parity with Go

Same contract as `pkg/client`: exact-match `redirect_uri`, 60s single-use code, `state` round-trip, `{"email","name","groups"}` only — raw IdP claims never cross the boundary.
