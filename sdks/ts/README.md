# keyway-ts

TypeScript SDK for [Keyway](https://github.com/HalxDocs/keyway) — one OAuth2-style login flow for SAML and OIDC. Zero runtime dependencies, strict types, Node 18+. Dual ESM + CJS.

```ts
// ESM
import { KeywayClient } from "keyway-ts";
// CJS
import { KeywayClient } from "keyway-ts"; // const { KeywayClient } = require("keyway-ts");
```

## Quickstart

```ts
import { KeywayClient, generateState, parseCallbackUrl } from "keyway-ts";
import type { Identity } from "keyway-ts";

const keyway = new KeywayClient("http://127.0.0.1:8080");

// 1. Send the user to Keyway (store `state` in an HttpOnly cookie first).
const state: string = generateState();
const loginUrl: string = keyway.buildAuthorizeUrl({
  tenant: "acme",
  redirectUri: "http://localhost:3000/callback",
  state,
  // connection: "conn-abc", // required only when the tenant has 2+ active connections
});

// 2. On GET /callback: verify state BEFORE touching the code.
const { code, state: returned } = parseCallbackUrl(req.url);
if (returned !== storedState) throw new Error("state mismatch");

// 3. Swap the single-use code (60s, redirect_uri-bound) for the identity.
const { email, name, groups }: Identity = await keyway.exchangeCode({
  code,
  redirectUri: "http://localhost:3000/callback",
});
```

See `examples/express-callback.ts` — a dependency-free port of Go `examples/demo-sso` (run with `npx -y tsx examples/express-callback.ts`).

## API

| Method | Mirrors Go | Notes |
|---|---|---|
| `new KeywayClient(baseUrl, {fetch?, timeoutMs?})` | `client.New` | Trims trailing `/`, throws `KeywayError` on empty/bad URL |
| `buildAuthorizeUrl({tenant, redirectUri, state?, connection?})` | `Client.AuthURL` | Omits empty `state`/`connection` keys |
| `exchangeCode({code, redirectUri, signal?})` | `Client.Exchange` | `POST /token` form-encoded; throws `KeywayError` |
| `generateState()` | demo `newState` | 16 random bytes via WebCrypto, hex |
| `parseCallbackUrl(url)` | demo `handleCallback` | Returns `{code, state}` (`""` when missing) |

Errors: `KeywayError { code: KeywayErrorCode, description, status? }`. `code` is the server's stable `error` field (`invalid_request`, `invalid_grant`, ...) as an open union — known codes autocomplete, future codes still compile.

## Parity

Same contract as `pkg/client` and `keyway-js`: exact-match `redirect_uri`, 60s single-use code, `state` round-trip, `{"email","name","groups"}` only — raw IdP claims never cross the boundary.
