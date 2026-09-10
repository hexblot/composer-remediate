# Contributing

## Ground rules

- Every change that affects behaviour comes with a unit test or a fixture.
- PHPStan level 8 must pass: `ddev composer phpstan`.
- Coverage: `ddev composer test:coverage` prints a summary and writes HTML and Clover reports to
  `build/coverage/` (gitignored). The DDEV web image installs PCOV (`.ddev/web-build/Dockerfile`,
  settings in `.ddev/php/custom.ini`), the same driver the PHP 8.4 CI job uses, so local figures match
  the badge; PCOV adds little to the run time and needs no toggling. Keep `ddev xdebug off` for
  coverage runs: with both extensions loaded PHPUnit still picks PCOV, but Xdebug slows the suite.
  Outside DDEV, without PCOV, the script falls back to Xdebug (it sets `XDEBUG_MODE=coverage`), whose
  line counts differ from PCOV's by a fraction of a percent. In CI the PHP 8.4 job prints the summary
  on the run's summary page, uploads the HTML and Clover reports as the `coverage` artifact and, on
  pushes to `main`, writes the line-coverage badge data to the `badges` branch that the README badge
  reads; the other matrix jobs run without a coverage driver.
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
