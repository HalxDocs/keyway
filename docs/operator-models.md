# Operator models (decided Sep 2026, do not relitigate without new facts)

Three roles exist: HalxDocs (ships Keyway), the customer (brings their
IdP), and the customer's employees (click Log in; they never host
anything). The open question was only who operates the box between the app
and the IdP.

## 1. Customer self-hosts (default)

The customer's IT runs one Keyway: their host, their `KEYWAY_MASTER_KEY`,
their database file. HalxDocs supplies the image plus the compose files.

- IdP secrets never leave the customer's boundary.
- Customer owns uptime, backups, data residency.
- Cost per customer to HalxDocs: ~$0 plus support time.
- Hurdle: the customer needs someone who can run Docker and paste IdP
  values from a runbook.

## 2. HalxDocs hosts one shared instance (not before v2)

Every customer's IdP secrets in one SQLite file under one master key held
by HalxDocs. Rejected at current maturity because:

- One key compromise burns all customers; enterprise security reviews will
  ask exactly this on day one.
- No per-tenant KMS, no admin RBAC, no audit log, no rate limiting — the
  multi-tenant tables are operator convenience, not a SaaS isolation
  boundary.
- HalxDocs would own simultaneous outages for every customer.

Revisit only when a deal requires single-URL multi-tenancy AND funds the
hardening: per-tenant secret encryption, admin RBAC + audit trail,
Postgres, tenant-level rate limits and status isolation.

## 3. HalxDocs hosts one stack per customer (the pragmatic middle)

Same isolated deployment as local dev, cloned per customer: separate DB,
separate master key, separate Auth0 app, separate Railway project or
compose directory. Blast radius of one; `scripts/new-customer.ps1`
scaffolds it. Chargeable as managed onboarding, and the self-host handoff
is trivial — the customer's instance IS the config they would run.

## Decision rule

Default to 1; sell 3 as managed onboarding; onboard each new customer as
a second copy, never a second row in the same database. Revisit 2 only
per the conditions above.
