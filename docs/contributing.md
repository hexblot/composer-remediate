# Contributing

## Ground rules

- Every change that affects behaviour comes with a unit test or a fixture.
- Command behaviour (options, exit codes, report files) is tested through
  `tests/Support/CommandRunner`, which runs the plugin's commands via Composer's console application
  against a scratch copy of a fixture; add a case to `tests/Integration/RemediateCommandTest.php` or
  `DbCommandsTest.php` when you add or change an option.
- PHPStan level 8 must pass: `ddev composer phpstan`.
- The layer rules in `deptrac.yaml` must pass: `ddev composer deptrac`. Plugin → Command → Output →
  Engine → Advisory, each layer depending only on those inside it; the advisory code (feed readers,
  database, providers) never reaches into planning, so a database can be built and served without a
  project. Third-party code is classified too (Semver, ComposerPlugin, ComposerApi, SymfonyConsole,
  SymfonyProcess, SymfonyYaml) and each project layer lists which of them it may use, so the report
  shows zero uncovered dependencies and the run fails on a dependency nobody has classified: when you
  pull in a new library or a new corner of Composer, add a layer for it and allow it where it is
  meant to be used. Deptrac needs PHP 8.2 or newer, so it is installed separately with
  `ddev composer --working-dir=tools/deptrac install` (its lock is committed; the PHP 8.4 CI job runs
  it). `ddev composer check` runs PHPStan, Deptrac and the tests together.
- Methods stay short enough to read in one screen. Commands parse options, assemble collaborators and
  emit the report in separate methods; the planner's search phases (candidates, expansion, descent,
  global combination) are separate methods or classes; renderers have one method per report section.
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
- The `ci` workflow does not run for commits that only touch hand-written pages under `docs/`,
  `mkdocs.yml`, root Markdown files or the docs pipelines; the `docs` workflow builds and deploys
  those. The generated pages (`docs/cli-reference.md`, `docs/case-studies.md`) and the JSON schema do
  trigger it, because it checks them for staleness. It can also be started by hand from the Actions tab.
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
