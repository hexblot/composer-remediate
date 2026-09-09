# Contributing

## Ground rules

- Every change that affects behaviour comes with a unit test or a fixture.
- PHPStan level 8 must pass: `ddev composer phpstan`.
- Documentation is part of the change. If a page in `docs/` describes the code you touched,
  update it in the same commit; `mkdocs build --strict` runs in CI.
- Design decisions are recorded as ADRs under `docs/adr/`. Add one when you change a decision.

## Commit messages

Conventional-commit style subjects (`feat:`, `fix:`, `docs:`, `test:`, `chore:`), imperative mood,
no trailer lines.

## Adding a fixture

See [Test fixtures](fixtures.md). Fixtures must be real historical project states with provenance
recorded in their `README.md`.
