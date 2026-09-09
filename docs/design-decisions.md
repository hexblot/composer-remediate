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
`LockDiff`.

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

## Composer 2.4 minimum, 2.9 for the full feature set
### Context

The pitch's example command uses `-m` (`--minimal-changes`). Composer's changelog places that flag
in 2.9.0 (November 2025), `composer audit` and temporary constraints on transitive packages in 2.4.0,
and `--no-install` in 2.0.

### Decision

Refuse to run on Composer older than 2.4. On 2.4 through 2.8 omit `-m` and warn that resulting diffs
may be larger than necessary. Develop and test against `composer/composer ^2.9` with 2.4, 2.8, 2.9
and the latest release in the CI matrix. PHP 8.1 or newer.

### Consequences

- Users on current Composer get the intended behaviour; users on older 2.x still get valid plans.
- Runtime detection through `Composer::getVersion()` decides which flags are emitted.

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
