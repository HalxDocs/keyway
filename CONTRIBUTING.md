# Contributing

Small, reviewable changes beat large ones. This repo is maintained with
atomic commits, and pull requests are held to the same bar.

## Commit style

Conventional, lowercase scope, imperative subject — one concern per
commit, so any commit reverts cleanly on its own:

- `feat(storage): ...`, `feat(cli): ...`, `feat(api): ...`
- `fix(...)`, `refactor(...)`, `test(...)`
- `docs(...)`, `chore(...)`

## Before opening a PR

- `go build ./...` and the full `go test ./...` pass; add or extend tests
  for the behavior you change (see existing `*_test.go` for the pattern:
  table-free, behavior-first, fail-closed assertions).
- New HTTP routes come with route tests; new CLI subcommands with CLI
  tests; new storage methods with round-trip tests.
- Keep the dependency graph acyclic the way it is: protocol code never
  imports storage, storage never imports protocols, `pkg/client` stays
  dependency-free.
- Never commit generated or secret material: binaries, `*.db*`, `sp.key`,
  `sp.crt`, `.env`, `customers/`, tunnel logs. The `.gitignore` and
  `.dockerignore` already cover these — if your `git status` shows them,
  stop and fix your paths, not the ignore files.
- Update `README.md` (and `docs/` where it exists) when behavior,
  commands, or deployment steps change. Docs-only fixes need no code.

## Scope guidance

Bug fixes and small features with tests get reviewed fastest. New
protocols, datastores, or multi-tenancy changes need a design discussion
in an issue first — see `docs/operator-models.md` for decisions already
taken that PRs should not relitigate silently.
