# Design decisions

The docs describe what the tool does; this page records why the non-obvious choices were made and what was rejected. Sections are in the order the decisions were taken.

## Ship as a Composer plugin, not a standalone CLI
### Context

The original pitch described a standalone `composer-remediate` binary. The remediation engine needs the
project's repositories, authentication, platform configuration and Composer version to reproduce
the user's real resolution context.

### Decision

Deliver the tool as a Composer plugin exposing `composer remediate`. The engine is written as a
plain library under `Remediate\Engine` so a standalone wrapper can be added later without
restructuring.

### Alternatives

- **Standalone CLI depending on `composer/composer`.** Full control, but it must rediscover
  `auth.json`, private repositories, `config.platform` and the installed Composer version, and it
  may bundle a different Composer than the one the user runs.

### Consequences

- Private Packagist and Satis users get a working tool on day one.
- The plugin uses exactly the solver the user uses, so validation results match what
  `composer update` will do.
- Installation is `composer global require`, the most natural path for the audience.
- Coupling to Composer's plugin API (`composer-plugin-api ^2.0`) is accepted; see "Touch Composer's `@internal` classes only inside adapters" below.

## Remediation candidates are `composer update` commands
### Context

The technical design described candidate generation, validation and ranking as three separate
subsystems operating on abstract graph edits.

### Decision

A candidate *is* one concrete `composer update` invocation: an allow list, a transitive-update mode
(`-w`/`-W`), temporary constraints (`--with`), the minimal-changes flag, and optionally a root
constraint change. Validation runs that invocation through the solver; ranking compares the
resulting lock diffs; the recommendation is the invocation that won.

### Alternatives

- **Abstract graph edits translated to commands at the end.** More expressive in theory, but
  every edit would still have to be expressed as something Composer can execute, and the
  translation step is where recommendations and reality drift apart.

### Consequences

- Sections 11, 13 and 14 of the technical design collapse into one loop.
- Every recommendation is trivially reproducible by the user.
- The design stays compatible with Composer gaining the same capability upstream.

## Validate with an in-process `Installer` dry-run, subprocess fallback
### Context

The technical design left open whether to use Composer as a library or as a subprocess.
Investigation of Composer's source established that `Installer::getLockTransaction()` exists and
that a dry-run stores the new lock array in memory (`Locker::setLockData()` with `$write = false`
populates a cache readable through `getLockData()`), while `composer update --dry-run` on the
command line has no machine-readable output.

### Decision

Primary route: for each candidate create a fresh `Composer` instance with plugins and scripts
disabled, configure `Installer` for a dry-run update, run it, and read the lock transaction and
virtual lock. Fallback route: run `composer update … --no-install --no-scripts --no-plugins
--no-audit` in a scratch copy of the project and read the written lock file. Both produce the same
`LockDiff`. The two are composed by a `FallbackSolver`: a candidate whose in-process solve ends in
an error (not a conflict, not a network failure) is retried through the subprocess, and the report's
solver line says how many solves took that route. `--solver` pins either route.

### Alternatives

- **Subprocess only.** Simplest coupling, but a PHP boot per candidate, repeated metadata loading,
  and scratch-directory management, for no gain in fidelity since the plugin already runs inside
  the user's Composer.
- **Library only.** Leaves no escape hatch when Composer's `Installer` API changes.

### Consequences

- Candidate evaluation is fast enough to try many candidates per finding.
- The solver's own failure explanation is captured through a buffered IO for the report.
- Isolation between successive in-process runs must be verified (static caches such as
  `Intervals` are cleared between runs).
- Solver results are copied into detached `Package` objects. The packages a solve returns point back
  at their repository and, through it, at that solve's whole Composer instance; keeping them alive in
  the plan retained every solve's object graph (1.5 GB after 136 solves on one fixture). Detaching
  them and collecting cycles after each solve brought the same run to 87 MB.
- `Installer::getLockTransaction()` only exists from Composer 2.10. On 2.4 to 2.9 the solver runs
  a real lock-only update inside the scratch copy (`setWriteLock(true)`, install disabled) and reads
  the written lock back; Composer writes the lock only while `executeOperations` stays enabled,
  which is harmless because no install step runs. CI exercises 2.4, 2.7, 2.8 and 2.9 on matching PHP
  versions; Composer 2.4 itself does not run on PHP 8.5.

## Promise "no third party sees your graph", not "fully offline"
### Context

The pitch promised that `plan` runs fully offline and that the dependency graph never leaves the
machine. Composer's solver needs package metadata for every version it considers and fetches it
from the configured repositories; the Packagist advisory API receives package names. Both facts
were verified in Composer's source.

### Decision

State the promise as: *no third party sees your dependency graph; network use is exactly what
`composer update` itself would do against your configured repositories.* Provide a real `--offline`
mode that sets `COMPOSER_DISABLE_NETWORK` and fails loudly on a cache miss rather than silently
using the network.

### Consequences

- The documentation lists exactly which data goes where.
- The Phase 2 advisory database removes the advisory-lookup request; solver metadata requests
  remain and are identical to a normal update.

## Advisory database is built locally from live sources and may be shared centrally
### Context

The pitch devoted roughly half of the technical design to a signed SQLite advisory artifact with an
hourly publish-on-change pipeline. Packagist, OSV and FriendsOfPHP already publish advisory data,
and Composer already parses Packagist's.

### Decision

The database is a local build: `remediate db:build` pulls the configured sources and writes a
SQLite file. Because the file is portable, a team or this project can publish it, and users point
at a shared copy with `--database-location <path-or-URL>` to avoid rebuilding on every run. The
project's own published, signed, released-only-on-change artifact is the reference instance of that
sharing model, not a separate product. Phases 0 and 1 use Packagist's advisory API through
Composer's classes and do not need the database at all.

### Consequences

- Remediation quality is delivered before any data infrastructure exists.
- Offline analysis, private advisories and reproducible advisory snapshots are served by the same
  file format whether built locally or downloaded.
- The signed-artifact pipeline is built last and only after the local build is stable.

## Fixtures freeze package metadata, not just advisories
### Context

The design pinned the advisory database hash for reproducibility but not the package metadata the
solver consumes. The smallest valid upgrade for a historical lock file changes whenever upstream
publishes a release, so solver-backed tests against live Packagist rot within weeks.

### Decision

Every fixture ships a static Composer repository (`repo/packages.json`) with every package version
the solver may consider, and the harness disables packagist.org. Composer accepts `file://` URLs
for `type: composer` repositories, so no web server is involved.

### Consequences

- Fixture tests are deterministic and run offline in CI.
- Fixtures are larger; a `build-fixture` script assembles the repository from a warm Composer
  cache so they are not hand-written.
- `COMPOSER_DISABLE_NETWORK` is not used in fixture runs because its check precedes Composer's
  local-file transport.

## Composer 2.4 minimum, 2.7 for the full feature set
### Context

The pitch's example command uses `-m` (`--minimal-changes`). Composer's changelog places that flag
in 2.7.0 (February 2024) for partial updates, extended to full updates in 2.9.0; `composer audit`
and temporary constraints on transitive packages arrived in 2.4.0, `--no-install` in 2.0. An earlier
revision of this page attributed the flag to 2.9; an adversarial adoption review caught the error.

### Decision

Refuse to run on Composer older than 2.4 (detected by the presence of the 2.4 `Auditor` class, since
`composer-plugin-api ^2.0` cannot express the runtime floor). On 2.4 through 2.6 omit `-m`; diffs
may be larger than necessary. Develop and test against `composer/composer ^2.9` with 2.4, 2.7, 2.8,
2.9 and the latest release in the CI matrix. PHP 8.1 or newer for reach (Composer itself runs on 7.2.5+); since 8.1 reached end of life in December 2025 the command prints a warning on PHP older than 8.2 rather than refusing to run, so teams on an unsupported runtime still get a remediation plan.

### Consequences

- Users on current Composer get the intended behaviour; users on older 2.x still get valid plans.
- Capability detection (`Installer::setMinimalUpdate()` exists) decides which flags are emitted;
  the subprocess solver parses `composer --version` with the 2.7 threshold.

## Touch Composer's `@internal` classes only inside adapters
### Context

Composer's advisory classes (`Auditor`, `SecurityAdvisory`, `AdvisoryProviderInterface`,
`RepositorySet::getMatchingSecurityAdvisories`) are marked `@internal`. `Auditor::audit()` changed
its signature in each of 2.7, 2.8, 2.9 and 2.10, and 2.10 deprecated `config.audit` in favour of
`config.policy`.

### Decision

The engine defines its own `AdvisoryProvider` interface and `Advisory` value object. Exactly one
adapter class talks to Composer's advisory internals, and a second adapter shells out to
`composer audit --locked --format=json` when the in-process interface is missing or incompatible.
The same rule applies to any other `@internal` API the engine needs.

### Consequences

- A Composer release that changes an internal signature breaks one adapter, not the engine.
- Fixtures feed the engine through a JSON provider that never touches Composer's classes.
- The adapter reads `SecurityAdvisory::$severity` only when the property exists (it does not in 2.4)
  and fails with "advisory data unavailable" when no configured repository provides advisories at
  all, rather than reporting a clean lock.
- An advisory source that only knows the advisories of the current lock (`composer audit` output,
  the audit fallback) cannot say whether a candidate lock is clean, so the planner verifies nothing
  against it: findings are reported without a remediation and the run exits 2. Recommending a fix
  checked against an incomplete source would be a fix verified against nothing.
- Coverage gaps gate the exit code. A record about a locked package the source could not read means
  the source cannot vouch for that package; a lock with such gaps and no findings exits 4 unless the
  operator accepts the gaps explicitly. Earlier releases only warned, which let a gate read "the
  data is incomplete" as "the lock is clean".
- The fallback engages only on a PHP error from the in-process adapter (a method that no longer
  exists, a changed signature): that is what an incompatible `@internal` API looks like at runtime.
  A lookup failure (network down, no repository provides advisories) is not retried through
  `composer audit`, which would face the same repositories; the run reports "advisory data
  unavailable". When the fallback engages, the report's advisory source reads
  `composer audit --locked` and a warning explains that only current-lock advisories are known, so
  candidate locks could not be checked for other advisories. Composer older than 2.4 has neither
  route and is rejected up front. The child runs with `--no-plugins --no-scripts`: a subprocess
  does not inherit the parent's switches, and without them Composer would activate the analysed
  project's allowed plugins (see the plugin boundary below). A test installs a real plugin whose
  `activate()` leaves a marker and asserts the fallback never triggers it.

## The plugin boundary: `composer remediate` versus `composer-remediate`
### Context

Composer activates every plugin the project allows while it discovers plugin commands, before the
`remediate` command runs. Disabling plugins on the scratch instances protects the candidate solves,
but nothing inside a plugin command can undo what Composer did at startup. The promise "planning
never executes the analysed project's plugins" was therefore only true inside the engine, not at the
command line users actually type.

### Decision

Ship both entry points and say what each guarantees. `composer remediate` is the convenient form for
projects you maintain yourself: it inherits Composer's exact configuration, and the project's other
allowed plugins have already run, as they do for every Composer command. `bin/composer-remediate` is
the boundary: it boots Composer's `Application` from the installed Composer (the phar on PATH or
`REMEDIATE_COMPOSER_BINARY`) with `--no-plugins --no-scripts` forced from the first instruction and
applies `--offline` before any HTTP client exists. Use it for projects you do not trust.

### Consequences

- The security policy states the boundary precisely instead of over-promising.
- The binary has no copy of `composer/composer`; it reuses the user's installation, so both entry
  points solve with the same Composer release.

## Search downwards for the lowest parent version that admits the fix
### Context

Composer's `--minimal-changes` keeps *transitive* packages at their locked versions when possible,
but the package named on the command line is still moved to the newest version its constraints
allow. In the synthetic fixture, `composer update acme/app-framework -W -m` jumped the parent from
1.0.0 to 1.2.0 and dragged a sibling along (three changes), although 1.1.0 already required the fixed
child (two changes). The pitch explicitly asks for "the smallest parent upgrade that permits" a
fixed version.

### Decision

After a parent-update candidate validates, the planner probes downwards: it re-solves with a
temporary upper bound on the parent (`--with 'A:>current,<newest'`), accepts the result if it is
still valid and lower, and repeats until the solve breaks, the vulnerability returns, or a small step
budget is exhausted. The lowest working version is then pinned as an extra candidate rendered as
`composer update A:1.1.0 -W -m …`, and ranking decides between the pinned and the plain command.

### Alternatives

- **Enumerate parent versions from repository metadata.** Requires loading metadata outside the
  solver and reimplementing the eligibility check the solver already performs.
- **Only report the plain command.** Simpler, but contradicts the minimal-blast-radius principle and
  would have failed the fixture a human would consider obvious.

### Consequences

- A few extra solves per finding; bounded by `Planner::MAX_DESCENT_STEPS`.
- Candidates gained the notion of *pins* (`name:version` in the allow list), which are temporary
  constraints from the solver's point of view.
- The descent applies to single-parent updates and root-constraint widenings; multi-parent unions
  are left as they are for now.

## Disable Composer's advisory blocking inside candidate solves
### Context

Composer 2.10 introduced `config.policy.advisories.block` (default true). During an update, a
`SecurityAdvisoryPoolFilter` removes every version with a known advisory from the solver pool for
packages that are not locked, after fetching advisories from the repositories. Older Composer
releases have no such filter.

### Decision

Candidate solves run with blocking disabled (`Installer::setPolicyConfig()` with
`withBlockingDisabled()` in-process; `COMPOSER_NO_BLOCKING=1` for the subprocess fallback). The
planner performs its own advisory check on every resulting lock, using the same advisory provider
that produced the findings, and rejects candidates that keep the vulnerability or introduce a new
one.

### Alternatives

- **Rely on the pool filter.** It would make results differ between Composer 2.4–2.9 and 2.10+,
  perform an extra network round-trip per solve, and use Packagist's advisories even when the user
  supplied a different advisory source (a private database, a fixture snapshot).

### Consequences

- Identical behaviour across the supported Composer range and fully offline fixtures.
- The recommended command, when the user runs it on Composer 2.10+, additionally benefits from
  blocking; the planner's result is a lower bound on safety, not an upper bound.
- The Phase 0 evaluation question "does blocking make the tool redundant?" is answered in part: the
  filter picks safe versions once the user has chosen *which* package to update, which is precisely
  the choice this tool makes.

## A security fix is one goal; the engine plans towards goals

Recorded when Phase 7 (goal-driven planning) was added to the roadmap, so the reasoning is kept even
though the work comes after `--apply`.

### Decision

The planner's input is a goal on a locked package: "leave the advisory's affected range" today,
"satisfy this constraint" in Phase 7. Candidate generation, conflict expansion, parent descent,
ranking, global combination, acceptance rules and the reports are shared; only the goal's
acceptance test and the ranking's view of root-constraint changes differ.

### Reasoning

- The motivating case (composer/composer discussion 12777) is a major TYPO3 upgrade blocked by a
  transitive `typo3/cms-*` package that Composer's error never names. The conflict-expansion step
  built for Shopware's sibling pins answers it as it stands. Treating the upgrade as a goal reuses
  that machinery instead of copying it.
- A verified upgrade command is the same deliverable as a verified fix command: a dry run by
  Composer's own solver, the lock diff, the rejected alternatives with the solver's reasons, and the
  promise that the tool recommends and never modifies.
- Keeping the security fix as the default goal keeps the project's scope (and its OWASP framing)
  intact: goal-driven planning is the general form of what `composer remediate` already does, not a
  second product.

### Alternatives

- **A separate upgrade tool.** It would duplicate the search and the reports and would drift from
  them; the only genuinely new code is the goal's acceptance test and the ranking preference.
- **Interpreting release notes or choosing target versions.** Out of scope: the user names the goal.

### Consequences

- A run with no advisory data becomes valid for a goal, so the fail-closed rules (exit 4 without
  data, no-new-advisories when data exists) need a goal-mode variant with its own tests.
- Constraint drag changes meaning per goal: last resort for a fix, expected for an upgrade. The
  ranker and the text renderer must know which goal they serve.
- Fixtures from Composer's discussions board join the corpus, with the human-chosen command recorded
  the same way as the security cases.

## The published advisory database is the default source, kept current at a fixed path

### Context

Until 0.6 a run with nothing configured asked the configured repositories for advisories, as
`composer audit` does, and the advisory database was opt-in. A URL was cached under a hidden name in
Composer's cache directory and refreshed by age. Users who wanted the database in CI had to build or
download it themselves on every run, and a locally built file at a given path was never reused: the
tool could not tell whether it was current.

### Decision

A run keeps one database file at a known path (default: `<composer cache dir>/remediate/advisories.sqlite`)
and, on every run, confirms it against the source it comes from (default: this project's
`advisory-db-latest` release) by content, not by date: same sha256, same dataset hash, or a newer
local build count as current; anything else is replaced by a verified download or, on request, a
rebuild from the sources. Path, source and maximum age are independent settings, each with its own
default, so configuring one never moves another. When the source cannot be reached the copy is used
and the report says so; when there is no copy at all the configured repositories are asked and the
report says that too. `--no-database` and a local path as the source keep the old behaviours.

### Reasoning

- Every report then carries the same exploit data, coverage gaps and three merged sources, rather
  than only the reports of users who knew about the database.
- Comparing content survives CI caches, which restore files with arbitrary timestamps, and lets a
  locally built database (with `--include`, say) be recognised as current instead of overwritten.
- The freshness request is a few bytes against a release asset, needs no token, and is not subject to
  GitHub's API rate limit.
- The chain degrades one step at a time with a warning at each step, never silently: current copy,
  download, unconfirmed copy, repository API, exit 4. `--database-max-age` and `--database-sha256`
  let an operator refuse the degraded steps.

### Alternatives

- **Keep the repository API as the default and document the cache pattern.** Leaves most users
  without exploit data and coverage gaps, and every CI user writing the same shell test of a file's age.
- **Compare by HTTP `Last-Modified` or file modification time.** Breaks on cache restores and
  re-uploads, and cannot recognise a local build.
- **A hidden cache only.** That is what 0.6 did; it could not be declared as a CI cache artefact
  without knowing the hashed file name.

### Consequences

- A plain run contacts github.com once per run. The privacy page lists the request and the three
  ways to stop it (`--no-database`, `--offline`, a local path as the source).
- The trust anchor for the default is TLS plus the publisher's digest and the release workflow's
  protected environment; `--database-sha256` pins a digest for anyone who wants more.
- Publishing `latest.json` next to a mirrored database (sha256, dataset_hash, published_at) is what
  lets clients of that mirror recognise their own builds; a `.sha256` sidecar alone still verifies.
