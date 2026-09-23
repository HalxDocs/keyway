# Keyway Engineering — explained like you're five (but with all the details)

> Keyway is a self-hosted Enterprise SSO connector for Go: one OAuth2-style flow in your app, SAML or OIDC to each customer's IdP. Single static binary, SQLite by default, zero infrastructure — MIT licensed.

Think of Keyway as a **playground bouncer with a rulebook**.

* Your app is the playground.
* Each customer brings their own ID-checker (their IdP: Okta, Auth0, Google, Azure AD).
* Some ID-checkers speak Spanish (SAML), some speak French (OIDC).
* Your app only speaks one language: "give me `{email, name, groups}`".
* Keyway stands in the middle and translates. It never lets a stranger in, never writes down passwords, and never guesses.

---

## 1. The big picture (draw it on a napkin)

```text
                    ┌─────────────────────────────────┐
                    │             KEYWAY              │
                    │      (one Go binary + 1 file)   │
  Your app          │                                 │   Customer IdP
  (playground)      │  /authorize → remember login    │   (ID-checker)
                    │  /callback/* → verify proof     │   speaks SAML or OIDC
  ┌──────┐  code    │  /token → hand over sticker     │   ┌──────────┐
  │ App  │─────────▶│                                 │──▶│ Okta /   │
  │      │◀─────────│  SQLite: tenants, connections,  │◀──│ Auth0 /  │
  └──────┘ redirect │  pending logins, one-time codes │   │ Google   │
                    │                                 │   └──────────┘
                    │  Secrets locked in a safe       │
                    └─────────────────────────────────┘
```

Concrete example — Acme Corp:

```sh
# 1. You tell the bouncer: "Acme's kids go to THIS slide"
./keyway tenant create --id acme --redirect-uris http://localhost:3000/callback

# 2. You introduce the bouncer to Acme's ID-checker
./keyway connection add --tenant acme --type oidc \
  --issuer https://acme.us.auth0.com/ --client-id ABC --client-secret XYZ \
  --email-claim email --name-claim name

# 3. Bouncer phones the ID-checker BEFORE any kid arrives
./keyway connection test --id conn-xyz
./keyway connection activate --id conn-xyz

# 4. Kid arrives → app sends kid to bouncer → bouncer sends kid to ID-checker
open "http://127.0.0.1:8080/authorize?tenant=acme&redirect_uri=http://localhost:3000/callback&state=app-123"

# 5. Kid comes back with a stamped hand → bouncer swaps it for a 60-second sticker
curl -X POST http://127.0.0.1:8080/token -d code=... -d redirect_uri=http://localhost:3000/callback
# {"email":"ada@example.com","name":"Ada","groups":["eng"]}
```

Five HTTP doors only (`internal/api/server.go:66-84`):

| Door | What happens |
|---|---|
| `GET /authorize?tenant=&redirect_uri=&state=[&connection=]` | Start login, `302` to IdP |
| `GET /callback/oidc/{id}?code=&state=` | Finish OIDC, `302` to app with `?code=&state=` |
| `GET+POST /callback/saml/{id}` (`SAMLResponse+RelayState`) | Finish SAML, `302` to app |
| `POST /token` (`code+redirect_uri`) | Burn code, return `{email,name,groups}` |
| `GET /healthz` | Says `{"status":"ok"}`, touches nothing |
| `GET /saml/metadata/{id}` + `/admin/*` | SP metadata + operator API |

---

## 2. Layers: everyone has one job (like LEGO)

```text
  ┌──────────────┐  only place allowed to import go-oidc / crewjam/saml
  │ oidc + saml  │  translators: messy foreign language → clean Identity
  └──────┬───────┘
         ▼
  ┌──────────────┐  internal/normalize/identity.go:24
  │  normalize   │  ONE struct the whole product promises:
  └──────┬───────┘  {Email, Name, Groups, RawClaims}
         ▼
  ┌──────────────┐  internal/flow/service.go — the rulebook owner
  │     flow     │  remembers logins, checks everything IN ORDER
  └──────┬───────┘
         ▼
  ┌──────────────┐  internal/api/server.go — thin HTTP glue
  │     api      │  parses URLs, calls flow, holds NO login state
  └──────┬───────┘
         ▼
  ┌──────────────┐  internal/storage/sqlite.go — one file, 4 tables
  │   storage    │  tenants, connections, auth_requests, auth_codes
  └──────┬───────┘
         ▼
  ┌──────────────┐  cmd/keyway — thin dispatcher, only flags + exit codes
  │  cmd + cli   │
  └──────────────┘
  pkg/client — the pocket map you give to apps (AuthURL + Exchange)
```

Rules enforced by `CONTRIBUTING.md:22-24`:

* Protocol code never imports storage.
* Storage never imports protocols.
* `pkg/client` stays dependency-free.

Why? So you can swap SQLite for Postgres later without touching a single login check. The `Storage` interface lives in the *consuming* package (`internal/flow/store.go:23-98`) — the waiter writes the menu, the kitchen fulfills it, not the reverse.

Tiny example of why this matters:

```go
// flow doesn't know what SQLite is. It just says "I need this":
type Storage interface {
  SaveAuthRequest(ctx, r AuthRequest) error
  ConsumeCode(ctx, code string, nowUnix int64) (AuthCode, error)
  // ...
}
// sqlite satisfies it. A test fake satisfies it. Postgres could too.
```

---

## 3. The religion: fail closed, fail loud, fail early

Keyway's motto: **"When in doubt, say NO — loudly, at the front door, not at the kid's birthday party."**

### 3a. Check at creation, not at login

`internal/connection/validate.go:5-14`:

```go
// Both CLI and admin API call Connection.Validate() BEFORE storing.
if c.AttributeMap.EmailClaim == "" {
  return error("email claim mapping is required")
}
```

Story: if Acme forgets to say "email lives in the `email` field", Keyway yells during setup — not when Ada is trying to log in at 9am Monday.

Adapters double-check at construction (`internal/oidc/adapter.go:35-60`, `internal/saml/adapter.go:62-102`): wrong type, missing issuer, no email mapping → refuse to even start.

### 3b. Closed boxes, not open bags

```go
type ConnectionType string // only "saml" or "oidc" — "smal" fails to compile-think
type ConnectionStatus string // only "untested" | "active" | "disabled"
type AttributeMap struct { EmailClaim, NameClaim, GroupsClaim string } // exactly 3, no map typos
```

Redirect allowlist is **exact match only** (`internal/tenant/tenant.go:33-54`):

```text
Allowed: http://localhost:3000/callback
Attacker: http://localhost:3000/callback.evil.com  → REJECTED
Why: prefix matching would let evil-callback pass. Exact == safe.
Empty list == deny all.
```

### 3c. Status-gated logins (the bouncer's wristband system)

```text
  [untested] --test passes + activate--> [active] <--disable--> [disabled]
      ^                                      |  (re-activate allowed)
      |                                      |
      +--- NEVER go back here. No silent regression. (storage/sqlite_connections.go:151-160)
```

* Only `active` starts or finishes logins (`internal/flow/service.go:109-111`, `finish_oidc.go:23-25`, `finish_saml.go:24-26`).
* `?connection=` given? It must belong to YOUR tenant and be `active`.
* No `?connection=`? You must have **exactly 1** active connection. Zero → "nothing to log in with". Two → "tell me which one, I won't guess" (`service.go:124-126`). Guessing would log Ada into the wrong company.

### 3d. Anti-guessing, anti-replay, anti-smuggling

Picture two lines at the bouncer: the French line (OIDC) and Spanish line (SAML). You can't get a French ticket and sneak into the Spanish line:

```go
// internal/flow/finish.go:29-47
req := GetAuthRequestByState(state)
if req.Protocol != protocol { Delete(req); REJECT }       // line-hopper? out.
if req.ConnectionID != connectionID { Delete(req); REJECT } // wrong company? out.
if now >= req.ExpiresAt { Delete(req); REJECT }              // late? out.
```

Codes give nothing away (`internal/flow/store.go:11-14`, `storage/sqlite_codes.go:30-44`):

```text
Wrong code? Expired code? Already-used code? → same answer: "not found".
```

Like a bouncer who says "nope" the same way every time, so you can't learn which fake IDs almost worked. And a redirect mismatch **burns** the already-consumed code (`flow/finish.go:66-77`) — fail-closed.

---

## 4. The algorithm, step by step (follow Ada)

Ada works at Acme. She clicks "Log in with SSO".

```text
Step 0 ── Setup (once per customer)
  tenant{acme, allowlist:[app/callback]} + connection{conn-1, oidc, untested}
  → test (phone the IdP) → activate (wristband ON)

Step 1 ── GET /authorize  (internal/api/authorize.go + flow/service.go:133-153)
  App: "tenant=acme, redirect_uri=app/callback, state=app-123"
  Keyway:
    1. Tenant exists? Is redirect_uri EXACTLY in allowlist? No → 400.
    2. Resolve connection (explicit or exactly-1-active).
    3a. OIDC: mint state=hex(16B), nonce=hex(16B) [crypto/rand]
        Save AuthRequest{id, tenant, conn, protocol=oidc, state, nonce, redirect, expires=now+10m}
        Return AuthCodeURL(state, nonce, baseURL/callback/oidc/conn-1)
    3b. SAML: mint relay=hex(16B), adapter.StartLogin(relay) → {RequestID, signed-AuthnRequest-URL}
        Save AuthRequest{state=relay, SAMLRequestID=RequestID, protocol=saml, ...}
        Return IdP redirect URL
  Browser: 302 → IdP login page

Step 2 ── Callback  (internal/api/callback.go + flow/finish_oidc.go + finish_saml.go)
  OIDC: IdP → GET /callback/oidc/conn-1?code=xyz&state=<state>
  SAML: IdP → POST /callback/saml/conn-1 {SAMLResponse, RelayState}
  Keyway:
    1. lookupRequest(state) — protocol + connection + expiry (see 3d).
    2. Re-fetch connection — still active? Flipped mid-login → reject.
    3. VERIFY (the only place untrusted bytes become trusted):
       OIDC: ExchangeCode(code) → raw ID token → VerifyToken(raw, expectedNonce)
             checks: signature (JWKS) + iss + aud + exp + nonce == stored nonce (strict!)
             then: email = claims[EmailClaim] (required!), name/groups by map
       SAML: FinishLogin(received, expected{RequestIDs:[storedID], RelayState:stored})
             checks: RelayState == stored FIRST (before touching XML!)
             then ParseXMLResponse: signature vs IdP metadata (unsigned → reject),
             InResponseTo == stored RequestID, Destination == ACSURL,
             time window NotBefore/NotOnOrAfter ± skew (saml/login.go:126-139),
             then attributes by map. Panics converted to rejections.
    4. finishIdentity: mint AuthCode{32 random bytes → hex, tenant, Identity, redirect, expires=now+60s}
       IssueCode (INSERT) + DeleteAuthRequest (one login → one code, never two)
  Browser: 302 → app/callback?code=<one-time>&state=app-123 (verbatim round-trip for app CSRF)

Step 3 ── POST /token  (internal/api/token.go + flow/finish.go:66-78)
  App: "code=<one-time>, redirect_uri=app/callback"
  Keyway:
    ConsumeCode = DELETE FROM auth_codes WHERE code=? AND expires_at>? RETURNING ...
      (one SQL statement = exactly-once even with many connections — sqlite_codes.go:38-42)
    Not found → 400 invalid_grant (same for unknown/expired/used).
    Found but redirect mismatch → reject (code already burned by the DELETE).
    Found + match → {"email","name","groups"} — RawClaims NEVER cross this line.
```

Timings to memorize:

| Thing | Lifetime | Why |
|---|---|---|
| `AuthRequest` (pending login) | `10m` (`flow/request.go:20`) | Long enough for slow typing at IdP, short enough to not pile up |
| `AuthCode` (sticker) | `60s` (`flow/code.go:12`) | Stolen stickers die fast |
| OIDC `state/nonce`, SAML `relay/RequestID` | per-login `crypto/rand` | Never reused, never predictable |

Example rows:

```text
auth_requests: id=a1b2… tenant=acme conn=conn-1 proto=oidc state=9f… nonce=3c… redirect=app/callback exp=+10m
auth_codes:    code=7e… (256-bit) tenant=acme identity={"email":"ada@…"} redirect=app/callback exp=+60s
```

---

## 5. Cryptography: only boring, standard locks (no homemade locks)

```text
  ┌─────────────┐  KEYWAY_MASTER_KEY (hex, 32 bytes, from `keyway keygen` → crypto/rand)
  │    SAFE     │  AES-256-GCM (stdlib), fresh 96-bit nonce per Seal
  │  AES-GCM    │  stored as nonce|ciphertext → same secret seals differently each time
  │  Box        │  wrong key or 1 flipped bit → error, never data
  └─────────────┘  sealing happens at storage boundary (sqlite_connections.go:20-26):
                   "the last place plaintext may legally exist."
                   Plaintext courier field → ciphertext in DB → unsealed only in memory.
                   v1 has NO rotation (ciphertext has no version prefix) — documented, not silent.
```

What Keyway does NOT do (on purpose):

* No passwords anywhere → no bcrypt/argon2 (nothing to hash).
* No sessions → no session store to steal.
* No JWT minting → only opaque hex codes (`crypto/rand`, 256-bit). OIDC JWTs are *verified* (never minted) via `go-oidc` `IDTokenVerifier`.
* No assertion encryption (SAML signing only) — signatures verified every response, unsigned rejected.

SP identity (how the IdP recognizes Keyway):

```sh
# One per deployment, reused across that deployment's customer IdPs (saml/adapter.go SPConfig)
./keyway sp-keygen  # RSA-2048, self-signed, CN=keyway-sp, 825 days, DigitalSignature-only
                    # key file 0600, refuses to overwrite (cli/spkeygen.go)
./keyway start --sp-key ./sp.key --sp-cert ./sp.crt --base-url https://sso.example.com
# Without flags: ephemeral identity + LOUD warning (cli/start.go:43-45), restarts break IdP trust.
# TLS is NOT Keyway's job: Keyway serves plain HTTP on loopback (default 127.0.0.1:8080),
# Caddy terminates TLS with free certs (Caddyfile:1-5).
```

Randomness rule: **if it's security-sensitive, it's `crypto/rand`** — states, nonces, relays, request IDs, auth-request IDs, auth codes, connection IDs, SP serials (128-bit), master keys. No `math/rand`, no timestamps-as-secrets.

Admin gate (`api/admin_auth.go:14-27`, `api/server.go:41-43`):

```text
KEYWAY_ADMIN_TOKEN set?    → require `Authorization: Bearer <token>`, constant-time compare.
Empty?                     → OPEN — deliberate localhost-dev posture only.
Prod safety net (both must agree): compose fails fast without token + Caddy answers 404 for /admin/* at edge.
```

---

## 6. Storage: one file, four tables, zero servers

`internal/storage/sqlite.go:15-59` (pure-Go `modernc.org/sqlite`, WAL, single conn, FK on):

```sql
tenants(id PK, name, redirect_uris JSON '[]', created_at)
connections(id PK, tenant_id FK→tenants, type, status, saml_metadata, oidc_issuer,
            oidc_client_id, oidc_secret_sealed BLOB, attr_email, attr_name, attr_groups, created_at)
auth_requests(id PK, tenant_id, connection_id, protocol, state INDEXED, app_state,
              nonce, saml_request_id, redirect_uri, expires_at, created_at)
auth_codes(code PK, tenant_id, identity_json, redirect_uri, expires_at, created_at)
```

Story for a 5-year-old: one toy box with four drawers. `tenants` = which families may play. `connections` = which ID-checker each family trusts (secrets in a locked pouch). `auth_requests` = "Ada went to the ID-checker, expect her back in 10 minutes with ticket #9f". `auth_codes` = "Ada proved who she is, here's a 60-second sticker". A janitor (`DeleteExpired`) throws away old tickets so the box never overflows.

---

## 7. Operations: how grown-ups run it without getting paged

* **Who runs the box?** `docs/operator-models.md`: default = customer self-hosts (their host, their master key, their file — Halx cost ~$0). Middle = Halx hosts one stack *per customer* (separate DB+key+ports via `scripts/new-customer.ps1`). Never = one shared DB for all customers before v2 (one key burn = all customers + no RBAC/audit/rate-limits yet).
* **Config via env/flags (12-factor):** `KEYWAY_MASTER_KEY`, `KEYWAY_ADMIN_TOKEN`, `--addr --db --base-url --sp-key --sp-cert`. New `base-url` = new callback URLs → update IdP dashboard first.
* **Logs tell outcomes, not secrets:** `authorize/callback/token` log `ok|error + tenant + op`, never tokens/assertions. `GET /healthz` touches no storage/adapters/IdPs (`api/health.go:8-14`) so Auth0 outages don't restart healthy containers.
* **Test-before-you-trust:** `flow/conntest.go:10-18` builds the *real* adapter with the *real* SP identity (entityID+key+ACS) — OIDC runs live discovery, SAML parses metadata. `connection test` must pass before `activate` lets real users in.
* **SDK does the fiddly bits:** `pkg/client/client.go` — `AuthURL(tenant,redirect,state,connection)` builds encoding correctly (AppState CSRF round-trip preserved), `Exchange(code,redirect)` POSTs form + decodes `{email,name,groups}` + rejects empty-email. Go today; TS/Python same surface next.

```go
// smallest real app (examples/demo-sso):
authURL, _ := client.AuthURL("acme", "http://localhost:3000/callback", myCSRF, "")
// → redirect browser there … IdP … back with ?code=&state=
ident, _ := client.Exchange(ctx, code, "http://localhost:3000/callback")
// ident.Email is now safe to match an account.
```

---

## 8. Process: how the rulebook stays honest

`CONTRIBUTING.md`: atomic conventional commits (`feat(api): …`), `go build ./... + go test ./...` gate every PR, behavior-first fail-closed tests (assert the rejection, not just the happy path), temp-dir stores instead of globals, injectable `ProviderFunc` instead of mutable package state (`oidc/discovery.go:16-22` — tests inject `httptest` issuer, prod passes `oidc.NewProvider`), no committed secrets (`*.db*, sp.key/crt, .env, customers/` ignored). Decisions that hurt (shared tenancy, no rotation) are written in `operator-models.md` / `SECURITY.md` so they aren't relitigated silently.

---

## One-line synthesis

Keyway is built like a bouncer with a rulebook — every trust decision is made once, loudly, at the earliest possible point, using only standard cryptography, and everything downstream can assume the decision already happened.

## File map (where to look when something breaks)

| Symptom | Open first |
|---|---|
| Login won't start | `flow/service.go:133-153`, `tenant/tenant.go`, `connection/connection.go` |
| OIDC fails | `oidc/adapter.go:74-110`, `oidc/authorize.go`, `oidc/discovery.go`, `flow/finish_oidc.go` |
| SAML fails | `saml/login.go:85-121`, `saml/adapter.go`, `flow/finish_saml.go` |
| Code rejected | `flow/code.go`, `flow/finish.go:66-78`, `storage/sqlite_codes.go` |
| Secret won't unseal | `secret/secret.go`, `storage/sqlite_connections.go:60-95` |
| Admin 401/404 | `api/admin_auth.go`, `api/server.go:66-84`, `Caddyfile` |
| Need new storage | `flow/store.go` (implement it; don't touch flow) |
