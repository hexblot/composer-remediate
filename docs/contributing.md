# Contributing

## Ground rules

- Every change that affects behaviour comes with a unit test or a fixture.
- PHPStan level 8 must pass: `ddev composer phpstan`.
- Documentation is part of the change. If a page in `docs/` describes the code you touched,
  update it in the same commit; `mkdocs build --strict` runs in CI.
- Design decisions and their reasons are recorded in `docs/design-decisions.md`. Add a section when you change one.
- `docs/cli-reference.md` is generated: after changing a command, run `ddev composer cli-reference`.
  CI fails when it is stale.

## Commit messages

Conventional-commit style subjects (`feat:`, `fix:`, `docs:`, `test:`, `chore:`), imperative mood,
no trailer lines. Commits on `main` are signed (SSH signing keys work fine: `git config gpg.format ssh`
and register the public key on GitHub as a *signing* key).

## Adding a fixture

See [Test fixtures](fixtures.md). Fixtures must be real historical project states with provenance
recorded in their `README.md`.
