# Contributing

## Ground rules

- Every change that affects behaviour comes with a unit test or a fixture.
- PHPStan level 8 must pass: `ddev composer phpstan`.
- Coverage: `ddev xdebug on` once, then `ddev composer test:coverage` prints a summary and writes an
  HTML report to `build/coverage/` (gitignored). Xdebug roughly triples the fixture suite's run time,
  so leave it off for ordinary runs (`ddev xdebug off`). In CI the PHP 8.4 job measures coverage with
  PCOV, prints the summary on the run's summary page, uploads the HTML and Clover reports as the
  `coverage` artifact and, on pushes to `main`, writes the line-coverage badge data to the `badges`
  branch that the README badge reads; the other matrix jobs run without a coverage driver.
- The `ci` workflow does not run for commits that only touch `docs/`, `mkdocs.yml`, root Markdown
  files or the docs pipelines; the `docs` workflow builds and deploys those. A hand edit to a
  generated docs page is therefore caught by the next code push, not immediately.
- Documentation is part of the change. If a page in `docs/` describes the code you touched,
  update it in the same commit; `mkdocs build --strict` runs in CI (locally:
  `pipx run --spec mkdocs --pip-args=pymdown-extensions mkdocs build --strict`).
- Design decisions and their reasons are recorded in `docs/design-decisions.md`. Add a section when you change one.
- `docs/cli-reference.md` and `docs/case-studies.md` are generated: after changing a command, run
  `ddev composer cli-reference`; after adding or rebuilding a fixture, run `ddev composer case-studies`.
  CI fails when either is stale.

## Commit messages

Conventional-commit style subjects (`feat:`, `fix:`, `docs:`, `test:`, `chore:`), imperative mood,
no trailer lines. Commits on `main` are signed (SSH signing keys work fine: `git config gpg.format ssh`
and register the public key on GitHub as a *signing* key).

## Adding a fixture

See [Test fixtures](fixtures.md). Fixtures must be real historical project states with provenance
recorded in their `README.md`.
