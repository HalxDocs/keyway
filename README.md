# Keyway — self-hosted Enterprise SSO connector for Go

One OAuth2-style flow in your app. SAML or OIDC on the other end. Your
customer's IdP, your binary: a single static Go binary, SQLite by default,
zero required infrastructure.

## 10-minute quickstart

```sh
go build -o keyway ./cmd/keyway

# 1. Master key for sealed OIDC secrets (hex, 32 bytes).
export KEYWAY_MASTER_KEY="$(./keyway keygen)"

# 2. Start (localhost only by default).
./keyway start --db ./keyway.db --base-url http://127.0.0.1:8080 &
# Uses an ephemeral SP identity; pass --sp-key/--sp-cert files for a stable one.

# 3. Register your customer's SSO.
./keyway tenant create --id acme --name Acme \
  --redirect-uris http://localhost:3000/callback

# OIDC (Auth0 / Google / Azure AD test app):
./keyway connection add --tenant acme --type oidc \
  --issuer https://YOUR-TENANT.us.auth0.com/ \
  --client-id CLIENT_ID --client-secret CLIENT_SECRET \
  --email-claim email --name-claim name

# ..or SAML (Okta developer org: copy the IdP metadata XML to a file):
./keyway connection add --tenant acme --type saml \
  --metadata ./acme-okta.xml \
  --email-claim http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress \
  --name-claim http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name

# 4. Dry-run before going live (SAML needs the server's SP flags).
./keyway connection test --id conn-<id> \
  --sp-entity-id http://127.0.0.1:8080/sp \
  --sp-acs-url http://127.0.0.1:8080/callback/saml/conn-<id> \
  --sp-key ./sp.key --sp-cert ./sp.crt

# Approve the tested connection for logins (untested logins are refused).
./keyway connection activate --id conn-<id>

# 5. Log in: open the authorize URL, follow the IdP redirect, land back
#    on your app with ?code=...&state=....
http://127.0.0.1:8080/authorize?tenant=acme&redirect_uri=http://localhost:3000/callback&state=app-123

# 6. Exchange the single-use code (60s) for the normalized identity.
curl -X POST http://127.0.0.1:8080/token \
  -d code=... -d redirect_uri=http://localhost:3000/callback
# {"email":"ada@example.com","name":"Ada","groups":["eng"]}
```

## Commands

| Command | Purpose |
|---|---|
| `keyway start` | Serve flow + admin API (`--addr`, `--db`, `--base-url`, `--sp-entity-id`, `--sp-key`, `--sp-cert`) |
| `keyway keygen` | Print a fresh master key for `KEYWAY_MASTER_KEY` |
| `keyway tenant create\|list` | Provision and inspect customers |
| `keyway tenant redirect add\|remove` | Allowlist or drop app callback URLs |
| `keyway connection add\|list\|delete\|test\|activate\|disable` | Register, inspect, remove, dry-run, approve, suspend IdPs |
| `keyway status` | Tenant/connection counts and DB size |

Admin API mirrors the CLI at `/admin/*` (tenants, connections, `POST
/admin/connections/{id}/test|activate|disable`). Connection responses never include secrets.

## Tested with Auth0

End-to-end login verified Sep 2026 against an Auth0 EU dev tenant:
OIDC discovery, `/authorize` redirect, hosted login, callback, and
`POST /token` returning the normalized identity.

```sh
./keyway status --db ./keyway.db
# tenants: 1
# connections: 1
# storage: sqlite (45056 bytes)

./keyway connection test --id conn-<id> --db ./keyway.db
# connection "conn-<id>": OIDC discovery ok
```

![Auth0 hosted login continuing to keyway](docs/auth0-login.png)

![Terminal: status and OIDC discovery ok](docs/terminal-proof.png)

## Demo app

`examples/demo-sso` is the smallest Keyway-integrated app: home page with
a login link, callback that verifies `state` and exchanges the code via
`pkg/client`. Tenant `acme` already allowlists its callback URL.

```sh
./keyway start --db ./keyway.db --base-url http://127.0.0.1:8080 \
  --sp-key ./sp.key --sp-cert ./sp.crt &
go run ./examples/demo-sso
# open http://localhost:3000 and click Log in with SSO
```

With several active connections on one tenant, point the demo at one
explicitly (otherwise `/authorize` refuses to guess):

```sh
go run ./examples/demo-sso --connection conn-<id>
```

The demo keeps two Keyway addresses: `--keyway` (public, embedded in the
login link the browser follows) and `--keyway-internal` (server-side code
exchange, defaults to `--keyway`). They coincide for bare-metal dev and
differ in compose, where the browser uses published localhost while the
demo dials `http://keyway:8080`.

## Docker

Dev stack (Keyway + demo, loopback-bound ports, same URLs as above):

```sh
cp .env.example .env  # then set KEYWAY_MASTER_KEY (keyway keygen)
docker compose up -d --build
```

One isolated stack per customer (see `docs/operator-models.md`):
`scripts/new-customer.ps1` scaffolds `customers/<id>/` with fresh secrets
and its own ports — same files, separate volumes:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\new-customer.ps1 -CustomerId acme2 -KeywayPort 8081 -DemoPort 3001
docker compose --env-file customers/acme2/.env -p keyway-acme2 up -d --build
```

Run admin commands against the container database (exec inherits the
compose environment, including the master key from `.env`):

```sh
docker compose exec keyway /keyway status --db /data/keyway.db
```

Migrate an existing local database — sealed secrets travel with the same
master key, and the SP key/cert are already bind-mounted read-only:

```sh
docker compose cp ./keyway.db keyway:/data/keyway.db
docker compose restart keyway
```

Production, zero-cost path: any VM with a public IP plus DNS A records.
Caddy terminates TLS with free automatic certificates; going public is
config only — the services are unchanged:

```sh
KEYWAY_BASE_URL=https://sso.example.com \
DEMO_REDIRECT=https://app.example.com/callback \
KEYWAY_HOST=sso.example.com DEMO_HOST=app.example.com \
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

A new base URL changes every connection's callback URL, so add the new
`https://<host>/callback/...` URLs in the IdP dashboard first (Auth0 app
Allowed Callback URLs plus the SAML2 addon callback). `GET /healthz` is a
dependency-free liveness probe for orchestrators.

## Railway ($0 trial, no card — then $1/mo free credit)

Railway fits this stack well: it builds the `Dockerfile` natively, its free
`*.up.railway.app` domains come with valid TLS (no Caddy needed), and a
0.5 GB volume holds the SQLite file with room to spare. Trial = $5 for 30
days, no card; after that the Free plan gives $1/mo credit, which covers
two near-idle Go services at this scale — watch the usage page, and note
trial volumes are deleted 30 days after credits expire unless you upgrade.
Two hard requirements: verify your GitHub account (`railway.com/verify`)
or outbound HTTPS to Auth0 stays restricted, and generate **fresh**
secrets — never reuse the dev master key or client secrets here.

Setup (all values exact):
- **Service `keyway`**: repo `HalxDocs/keyway`, builder Dockerfile,
  start command
  `/keyway start --addr=0.0.0.0:8080 --db=/data/keyway.db --base-url=https://<keyway-domain> --sp-key=/data/sp.key --sp-cert=/data/sp.crt`,
  volume mounted at `/data`, healthcheck path `/healthz`. Env:
  `KEYWAY_MASTER_KEY` (fresh, from `keyway keygen`),
  `KEYWAY_ADMIN_TOKEN` (fresh, `openssl rand -hex 32`).
- **Service `demo`**: same repo/image, start command
  `/demo-sso --keyway=https://<keyway-domain> --keyway-internal=http://keyway.railway.internal:8080 --addr=0.0.0.0:3000 --tenant=acme --redirect=https://<demo-domain>/callback`
  (append `--connection=conn-<id>` once several connections are active).
  Env: none required.
- **First boot**: generate `sp.key`/`sp.crt` once and place them in the
  volume (Railway service shell), then provision over the public admin API
  with the bearer token — tenant, connections, `test`, `activate` — exactly
  mirroring the CLI quickstart. Then add the
  `https://<keyway-domain>/callback/...` URLs in Auth0 and log in at the
  demo domain.

## Free permanent hosting (this machine + tunnels, $0)

No VM, no card, no domain: this PC stays on, Cloudflare quick tunnels
(free, no account) publish `:8080`/`:3000` on public `https://` URLs, and
`scripts/sync-public-urls.ps1` closes the loop after every reboot (tunnel
hostnames rotate). It re-points `.env`, recreates the stack, re-allowists
the demo callback, and — with `AUTH0_SYNC=true` plus M2M credentials
(Management API, `update:clients` scope) — merges the new OIDC callback
into the Auth0 app without dropping the old ones. The SAML2 addon has no
stable API field, so the script prints the exact values to paste (~30s).

```powershell
# after any reboot (Docker Desktop up, tunnels running):
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\sync-public-urls.ps1
```

Boot persistence is a Startup batch file (no elevation needed): wait 60s
for the Docker daemon, `docker compose up -d`, then both tunnels. URLs
only change when a tunnel restarts, so one sync run after boot is enough
— the stack itself is unaffected by rotation.

## Security notes

- SAML signatures verified against IdP metadata on every response;
  unsigned assertions rejected. OIDC ID tokens verified (issuer, audience,
  expiry, signature) plus a strict nonce check.
- Authorization codes: 60s, single-use, `redirect_uri`-bound.
- OIDC secrets sealed at rest (AES-256-GCM); no key rotation in v1.
- `redirect_uri` allowlisted per tenant; login outcomes logged, assertions
  and tokens never logged.
- Admin API (`/admin/*`) takes a static bearer token via `--admin-token`
  / `KEYWAY_ADMIN_TOKEN`, enforced in code with constant-time comparison.
  Empty means open: acceptable for localhost dev behind loopback-bound
  ports, never for production. prod compose fails fast without the token,
  and Caddy answers `/admin/*` with 404 at the public edge regardless —
  both layers must agree before admin is reachable.
- Stable SP identity: generate `sp.key`/`sp.crt` once per deployment and
  pass `--sp-key`/`--sp-cert` to `keyway start`; without them the server
  mints an ephemeral identity on every boot. Keep the key `0600` and out
  of version control.

## Layout

`internal/oidc`, `internal/saml` (only protocol-aware code) →
`internal/normalize` (`Identity`) → `internal/flow` (orchestration) →
`internal/api` (HTTP) → `internal/storage` (SQLite) → `cmd/keyway`.
`internal/secret` seals credentials; `internal/cli` drives the binary.
