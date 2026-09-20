# Contributing

## Ground rules

- Every change that affects behaviour comes with a unit test or a fixture.
- Command behaviour (options, exit codes, report files) is tested through
  `tests/Support/CommandRunner`, which runs the plugin's commands via Composer's console application
  against a scratch copy of a fixture; add a case to `tests/Integration/RemediateCommandTest.php` or
  `DbCommandsTest.php` when you add or change an option.
- The shipped GitHub Action's body is `action/run.sh`, a file rather than a string inside `action.yml`
  so that `ddev composer test:action` can run that exact script against a local git remote with stubbed
  `composer` and `gh` commands (`tests/Action/action-test.sh`). Which revision the branch is built from,
  what goes into the commit and which credential authenticates the push are decisions the PHP suite
  cannot reach, and every defect that part has had lived in one of them. What the harness cannot cover
  is GitHub itself: the pull request calls are stubbed, so their arguments are checked and their
  behaviour is not.
- The advisory database's life (download, confirm, replace, outage, pin, project-chosen source) is
  tested end to end in `tests/Integration/DatabaseLifecycleTest.php` against a real HTTPS publisher:
  `tests/Support/TlsPublisher` starts `tests/Support/tls-server.php`, a PHP TLS stream server on an
  ephemeral loopback port with a certificate generated for 127.0.0.1, and the project's `cafile`
  setting makes Composer's curl layer trust it, so the production code path runs unchanged. It needs
  only the `openssl` and `curl` extensions and runs in a few seconds, locally and on every CI job.
  When a change touches how the database is chosen, verified or replaced, add the whole-run assertion
  there as well as the unit test: the security guarantees span settings, locator, planner and
  renderers, and the layered tests do not catch a disagreement between them.
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
  it and, on pushes to `main`, writes the README's architecture badge to the `badges` branch: "passing",
  or "failing (n)" with the number of violations and uncovered dependencies). `ddev composer check` runs
  PHPStan, Deptrac and the tests together.
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
- Changes go to `main` through a pull request, one branch per change: what you would want
  reviewed and tested as a whole, merged within a day or two rather than kept alive for weeks. Anything
  under `src` goes that way. Documentation edits, regenerated fixture reports and changelog work can be
  pushed to `main` directly. A release is the same shape: branch, pull request, full matrix and review,
  merge, tag from `main`.
- CI cost follows that. A push to `main` and a draft pull request run one job (PHP 8.4, Composer
  latest) carrying PHPStan, Deptrac, PCOV coverage and the badges, the end-to-end tests and the
  generated-page checks. Marking a pull request ready for review runs the full PHP matrix (8.1 to 8.5)
  and the Composer-version matrix (2.4 to 2.9 on their PHP versions), whatever the diff touches, so the
  tree that gets merged and tagged has always had a full run. Work in a draft while you iterate and pay
  for the matrix once. The Actions tab's manual run has a `full` switch for the whole matrix without a
  pull request. The advisory
  database workflow polls the feeds every six hours and publishes only when the dataset changed.
- `composer test:contract` is a suite apart from the others. It states the guarantees the tool has to
  hold whatever else changes, rather than the behaviour of any one class: advisory data that cannot be
  fully read never yields a clean result, what a scan consumes is what was verified, an incomplete run
  is never presented as successful by any report format, files holding private data are owner-only
  from the moment they exist, acceptance and severity compose to the same answer however combined, and
  a printed command parses back to the arguments it was built from. Each is checked over a range of
  inputs rather than the one case that first broke it. A new report format, advisory source or
  temporary file belongs in the relevant invariant rather than only in its own test.
- The coverage invariant is the one to be strict with. Advisory normalisation reads documents written
  by other people, so every place it decides it cannot read something is a place that can quietly
  narrow what the tool knows, and a narrower advisory looks exactly like a smaller one. Four rounds of
  review found paths that had been left silent one at a time. When touching a reader, the question is
  not "does this parse the shapes I have seen" but "can anything here be dropped without a gap being
  recorded", and the answer belongs in the invariant before the code. Two distinctions carry most of
  it: a record is another ecosystem's only when the reader positively read it as such, never because
  its identity could not be read; and a part that says nothing readable is not a part saying nothing
  is affected, whether it is absent, null, empty or unrecognised. Reading an identity means reading
  all of it, the ecosystem and the name, and a name is read only when it is one a lock could hold
  (`PackageName`, which is Composer's own syntax): a range filed under a name nothing can match is
  lost as completely as one that was dropped, and there are three readers, so the rule lives in one
  place and all three call it. The one thing a reader may drop in
  silence is a shape it can read and knows to be redundant, like OSV's commit ranges, and a file that
  is not an advisory at all, which the layout rather than the contents has to decide.
- The full run also executes the suite on Windows and macOS with PHP 8.4. What this tool does is
  filesystem work, subprocess execution and process forking, and all three differ between operating
  systems: replacing an open file by rename, the meaning of `0700`, path separators, whether `fork`
  exists at all. Two things cannot be asserted on Windows and are skipped there with the reason given
  in the test: a file mode of `0600`, which has no meaning without POSIX mode bits, and creating a
  symbolic link, which needs a privilege an ordinary account does not have. Static analysis, Deptrac
  and the action harness stay on Linux, being platform-independent and bash respectively.
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
