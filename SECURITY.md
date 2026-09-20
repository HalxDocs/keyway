# Security policy

Keyway sits on the login path between apps and identity providers, so its
security posture is documented as code-level fact, not aspiration. This
file states what is supported, how to report, and what to expect.

## Supported versions

Only the tip of `master` receives security fixes. There are no release
branches and no backports — pull latest, rebuild the image, redeploy.

## Report privately

**Do not open a public issue for a suspected vulnerability.** Use
GitHub's private vulnerability reporting
(Security tab → Report a vulnerability) so details stay embargoed until a
fix ships.

Include: affected commit, endpoint or command, impact (what an attacker
gains), and a minimal reproduction. Redact all secrets — rotate any
credential that appears in a report.

## Scope

In scope: the login flow (`/authorize`, `/callback/*`, `/token`),
protocol verification (OIDC/SAML adapters), sealed-secret storage, the
admin auth gate, and the shipped Docker/Caddy configuration.

Out of scope: your IdP's dashboard configuration, your host/VM hardening,
TLS termination you terminate yourself, tunnel URLs, secrets you paste
into chats or issues (rotate them instead), and upstream dependencies —
report those to their own projects (but tell us if you need a bump).

## Response

Best effort, no SLA: triage confirmation, a fix on `master`, and a
post-fix note in the advisory. Severity is judged by blast radius —
cross-tenant impact outranks single-deployment impact, matching the
operator model in `docs/operator-models.md`.

## Known limitations (documented gaps, not reports)

- No master-key rotation in v1 (ciphertext carries no version prefix).
- Admin auth is a single static bearer token; admin has no RBAC or audit
  log.
- An empty `KEYWAY_ADMIN_TOKEN` leaves `/admin/*` open — correct only for
  localhost dev behind loopback-bound ports (see README security notes).
