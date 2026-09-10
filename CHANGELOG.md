# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Exploit data in the advisory database.** `remediate:db-build` enriches every CVE with its FIRST
  EPSS probability and percentile and its CISA KEV listing date (`--enrich`, on by default;
  `--epss-file` / `--kev-file` read local copies). Only the CVEs the database names are stored. A
  feed that cannot be fetched is recorded in the metadata and the build continues without it;
  `remediate:db-status` shows what the database carries. Reports order findings by urgency (known
  exploited first, then EPSS, then severity; development-only findings last), print `EPSS 0.93 (97th
  percentile); listed in CISA KEV since …` under each advisory, and count KEV-listed packages in the
  summary. JSON gains `epss`, `epss_percentile` and `kev_added` per advisory and
  `packages_known_exploited` in the summary; SARIF tags such rules `known-exploited`; CycloneDX and
  GitLab reports carry the values. The dataset hash includes KEV membership (a new listing changes
  what to fix first) but not EPSS scores. Databases built without the data still read; their reports
  say `no exploit data`. Tests: both feeds with scripted downloads and local files, build-to-report
  round trip, a failing feed, hash behaviour, an old database, ordering rules, every output format.
- **Abandoned packages on the dependency path.** When Packagist marks the vulnerable package or a
  parent on its path abandoned (the marker travels in `composer.lock`, so this needs no network), the
  report says so with the replacement Packagist names, under the finding and in the summary; JSON
  gains `abandoned` per finding and `packages_with_abandoned_dependency` in the summary; SARIF,
  CycloneDX and GitLab reports carry the names. The lock snapshot now preserves the marker. Tests:
  planner detection on a scripted lock, every output format.

### Changed

- Findings are ordered by urgency (see above); before, they were ordered by package name. The stored
  fixture reports and the case-studies page are regenerated accordingly.

[Unreleased]: https://github.com/hexblot/composer-remediate/compare/v0.4.2...HEAD

## [0.4.2] - 2026-09-10

A correctness release answering the third adversarial recheck. The recheck of 0.4.1 confirmed the six
earlier findings as fixed and reported three new ones, all rated P1; each is fixed here with a test
that reproduces the reviewer's case, and the reviewer's closure pass on these fixes found nothing
further.

### Recheck (third round)

- The `composer audit --locked` fallback wired in 0.4.1 launched its child without `--no-plugins
  --no-scripts`, so Composer activated the analysed project's allowed plugins in that child: the
  compatibility-recovery route broke the plugin boundary the standalone binary exists to keep. The
  child now carries both switches. Covered by an integration test that installs a real plugin whose
  `activate()` writes a marker, shows that a plain `composer audit` does trigger it, and asserts the
  fallback adapter never does.
- OSV `limit` events: the normaliser kept the smallest of several limits and ignored an explicit
  `limit: "*"`. OSV's BeforeLimits predicate accepts a version below *any* limit, so the cap is the
  largest limit and a `*` limit lifts it; the old behaviour truncated genuinely affected versions
  (introduced 1.0.0 with limits 2.0.0 and 3.0.0 lost 2.x). Covered by unit tests for both shapes.
- Coverage gaps: a package whose value in a Packagist-shaped document is not a list of advisories
  (`{"advisories":{"acme/lib":"upstream-error"}}`) was skipped without a gap, so a private
  `--include` file with that shape built a clean database; it is now a gap for that package, which
  fails a private-file build and is retained for public feeds. An OSV record naming several packages
  recorded a gap only when *every* package's range was unreadable; a readable sibling hid the failure.
  The record is kept for the readable packages and a gap is recorded for each unreadable one.
  Covered by mapper, private-file and OSV-source tests.

[0.4.2]: https://github.com/hexblot/composer-remediate/releases/tag/v0.4.2

## [0.4.1] - 2026-09-10

A testing release. The suite grows from 111 to 171 tests and line coverage from 74% to 94%, with
no source file below 75%: the command layer, the advisory feed readers and both advisory adapters,
none of which had a test before, are now covered. Two defects surfaced on the way and are fixed
below, and the `composer audit` fallback that the design had promised since 0.1.0 is wired in.

### Added

- Tests: the command layer, driven through Composer's console application the way `composer
  remediate` runs, against the synthetic fixture. `remediate`: option validation (format, report
  spec, solver, release age), the lock-file check, the exit-code contract including a search budget
  too small to reach the fix, every report file format next to the JSON on standard output,
  `--format=none`, an unwritable report path, `--fail-on`, `--ignore`, the whole `--baseline` /
  `--update-baseline` workflow, `--offline`, advisory-source selection (missing snapshot, missing
  database via option, `REMEDIATE_DATABASE` and `extra.remediate.database`) and platform flags
  repeated in the recommended command. `remediate:db-build` from a local FriendsOfPHP checkout plus
  `--include`, the default build path, an unknown source; `remediate:db-status` on the result
  (metadata, sources, coverage gaps), on a missing file, via the environment variable, and on a
  database built before coverage gaps were recorded. Plugin capability and command registration.
- Tests: the feed readers with a scripted HTTP layer and archives built in the test. `ZipArchiveReader`
  (filtering, directory entries, a body that is not an archive, download failures, cleanup of the
  download); `OsvDumpSource` (alias ranking, ADVISORY reference as link, "MODERATE" mapped to
  medium, published/modified/withdrawn dates, several Packagist packages per document, other
  ecosystems ignored, invalid JSON and unreadable versions as coverage gaps, gaps reset per fetch,
  custom URL); `PackagistApiSource` (mapping, gaps, a body that is not an object, a document without
  `advisories`, transport failures); `FriendsOfPhpSource` from the GitHub archive (aliases, earliest
  branch time, non-Composer advisories skipped without a gap, scalar documents, empty ranges and
  invalid YAML as gaps naming the package from the path). The default advisory adapter
  `ComposerRepositoryAdvisoryProvider` with a fake Composer repository: conversion of full and partial
  advisories, per-package caching and incremental queries, merging across repositories with
  duplicate ids dropped, the failure when no repository provides advisories, transport failures,
  construction from a `RepositoryManager`. The `composer audit` fallback provider with a stand-in
  binary (leading noise before the JSON, one run per process, no JSON, undecodable JSON).
  `NormalizedAdvisory`, `Strategy` and `VersionStep` helpers.

### Changed

- The `composer audit --locked` fallback adapter, described in the design decisions since 0.1.0 but
  never wired in, is now used when Composer's in-process advisory API fails with a PHP error (a
  removed method or changed signature in Composer's `@internal` classes). The run switches once,
  the report's advisory source shows the fallback, and a warning explains that only current-lock
  advisories are known. Lookup failures are not retried through it: no repository providing
  advisories, or a network failure, still exits with "advisory data unavailable" rather than a clean
  result. Composer older than 2.4 is still rejected up front. Covered by unit tests of the switch
  (PHP error switches and warns once, lookup failures and ordinary exceptions propagate, the primary
  is not retried) and a command test that the default source with packagist.org disabled exits 4.

### Fixed

- FriendsOfPHP advisories lost their report date: the upstream files write `time: 2024-05-01 10:00:00`
  unquoted, which the YAML parser hands over as an integer timestamp, and the source only accepted
  text. Integer timestamps are now read, so `reportedAt` is populated for FriendsOfPHP records.
- Test bootstrap: Composer reads `$_SERVER` before `getenv()`, so the cache isolation was lost when
  the environment already exported `COMPOSER_CACHE_DIR` (DDEV does); tests now set both.

[0.4.1]: https://github.com/hexblot/composer-remediate/releases/tag/v0.4.1

## [0.4.0] - 2026-09-10

This release responds to an adversarial adoption review of 0.3.0 (twenty findings, nine rated as
able to undermine a security decision) and to the reviewer's recheck of the first response (six
remaining findings). Each item below names its change; the tests that establish it are listed in the
"Tests" bullets, and where a boundary is documented rather than removed the text says so.

### Recheck (second round)

- The subprocess solver pins `COMPOSER` to the scratch manifest. Before, the child inherited a
  `COMPOSER=/path/alternate.json` from the parent and updated the analysed project's real lock while
  the planner read the untouched scratch lock. Covered by an integration test that runs the real
  Composer binary with `COMPOSER` set to another manifest and asserts that file is unchanged.
- `composer-remediate` never includes any project's `vendor/autoload.php` (Composer's autoloader
  executes `autoload.files`, which is project code). It boots Composer from the phar it finds and
  registers the plugin's own classes through a PSR-4 mapping. Covered by an entry-point test that
  installs the binary in a project whose autoloader plants a probe and asserts the probe never runs.
- Database ingestion keeps coverage gaps: an upstream record the build cannot interpret is stored in
  a `gap` table with source, id, package and reason; `composer remediate` warns for every gap that
  names a package in the lock ("treated as unaffected by that record"); `remediate:db-status` lists
  them; databases built before gap tracking are flagged. A private `--include` file with an
  unreadable record fails the build, matching `--advisories-file`. Database reads use the strict range
  parser; the lenient one is gone.
- OSV events are evaluated per the specification: sorted by version, `introduced` opens an interval,
  the next `fixed`/`last_affected` closes it, and `limit` caps the whole range instead of closing an
  interval of its own. "introduced 1.0, fixed 1.1, limit 2.0" no longer marks 1.5 affected.
- The locator records whether a cached download was verified (`<cache>.status.json`) and repeats the
  disclosure on every cache hit, offline included; caches written by earlier versions are flagged as
  unverified.
- The fixture harness executes the printed command through a shell, verbatim, with a `composer` on
  PATH that adds `--no-install`; quoted constraints are no longer split on whitespace.
- Documentation regrouped by intent (Use it, Understand it, Integrate it, Evidence, Project) with
  three new pages: Reading the report, Comparison with other tools, and Case studies generated from
  the fixture corpus (`bin/case-studies.php`, checked for staleness in CI).

### Added

- `composer-remediate` binary: runs the same commands with the analysed project's plugins and
  scripts disabled from the first instruction, reusing the installed Composer for its classes and
  the fallback solver. `composer remediate` (the plugin command) keeps Composer's usual behaviour of
  activating the project's other allowed plugins at startup; SECURITY.md and the privacy page now
  state both boundaries precisely.
- `--solver=auto|in-process|subprocess`: the documented subprocess fallback is now wired. A
  candidate whose in-process solve errors (not a conflict, not a network failure) is retried through
  `composer update --no-install`; the report's solver line counts the retries.
- `--solve-budget` (default 60): hard ceiling on solver runs per finding across candidates, conflict
  expansion, parent descent and simplification. Every solve is counted; the report shows the count
  per finding (`solver_runs`) and in total, and a bounded search that finds nothing reads "none found
  within the search budget" instead of "none".
- Typed outcomes for findings without a fix: `none`, `none found within the search budget`,
  `unknown: solver error` (exit 3) or `unknown: network failure while solving` (exit 5). A tool
  failure can no longer produce the actionable-policy exit 2.
- `--ignore-platform-req` / `--ignore-platform-reqs` are repeated in every recommended command, so
  the printed command is the request that was verified.
- Blocking-risk note when a recommended command moves a package to a version that still carries
  another advisory (Composer 2.10+ advisory blocking may refuse it).
- Client-side sha256 verification of a downloaded advisory database against the publisher's
  `.sha256` sidecar; a missing sidecar and a stale cache reused after a failed refresh are reported
  as warnings with the cache age.
- `IgnorePolicy`: `config.audit.ignore` entries with `apply: block` and `config.policy.advisories`
  entries with `on-audit: false` no longer suppress findings; package rules are matched as packages
  (with their constraint), not as advisory ids.
- Tests: planner rules with a scripted solver (unknown severity, tool-error and network exits,
  combined-command cooldown, `--no-dev` baseline, all-advisory fixed range, platform flags, blocking
  risk, budget), parser strictness, OSV `versions`/`limit`/event order, ignore scoping, HTML link
  safety, fallback solver composition (with scripted routes), the real subprocess solver, the
  standalone entry point, database download/checksum/cache behaviour with a scripted HTTP layer,
  coverage gaps from build to report; freshly rendered JSON validated against the schema for every
  fixture; the synthetic fixture's recommended command executed verbatim by a shell with the real
  Composer binary and the resulting lock re-matched. Not covered by tests: the CLI driven against a
  live advisory repository, and the Composer 2.4 advisory adapter beyond the CI matrix job.

### Changed

- No advisory-capable repository, a malformed advisory document (an error payload, a malformed
  entry, an unparsable range) now stop the run with exit 4 instead of reading as a clean lock.
  `composer audit --format=json` output passed as `--advisories-file` is recognised as covering the
  current lock only.
- OSV normalisation honours explicit `versions` in addition to `ranges` and the `limit` event.
- Unknown *and unrecognised* severities count towards `--fail-on`.
- The combined command is held to the same rules as individual candidates: no new advisories and
  the `--min-release-age` cooldown; its simplified spelling is re-matched instead of inheriting the
  original's results. Releases without a known date are refused by the cooldown.
- Under `--no-dev` an untouched development finding is no longer counted as "newly introduced" by a
  production fix.
- The fixed range escapes every advisory known for the package, not only those affecting the locked
  version; ignored advisories do not shrink it.
- "Identical lock" for simplification now compares source and dist references and the
  production/development split, not only versions.
- `composerJsonPath()` / `lockPath()` follow `COMPOSER=alternate.json`.
- `--minimal-changes` is documented as a Composer 2.7.0 feature (2.9 extended it), and the subprocess
  solver's threshold follows. Composer older than 2.4 is refused at runtime. The Composer 2.4
  `SecurityAdvisory` class has no `severity` property; the adapter no longer reads it unconditionally.
- HTML reports turn only `http(s)` advisory links into anchors.
- `--min-release-age` rejects non-numeric input instead of coercing it to zero.
- The advisory-database workflow publishes `sha256sum` output (digest and filename) so
  `sha256sum -c` works as documented.
- README no longer claims the smallest fix; the search is bounded and ranked.
- JSON report (schema still version 1, additive): `solver_runs` and `search_exhausted` per finding,
  `outcome` on findings without a fix, `blocking_risk` on verified ones, `solver_runs` in the
  metadata.

## [0.3.0] - 2026-09-09

### Added

- SARIF 2.1.0 output (`--output=results.sarif`, `--format=sarif`) for GitHub Code Scanning: one rule
  per advisory with a numeric `security-severity`, one result per vulnerable package located at its
  `composer.lock` line, the verified command in the message.
- `--fail-on <severity>`: only findings at or above the threshold affect the exit code; findings of
  unknown severity always count. Shown in the summary and in the JSON report.
- Published JSON Schema for the report (`docs/schema/report.schema.json`), validated against every
  stored fixture report.
- Seven more historical fixtures (BookStack 2023 and 2024, Pixelfed, USAGov Drupal, Invoice Ninja,
  Kimai 1.x, Shopware 6.4.20.2), each with stored console, JSON, HTML and SARIF reports.
- Composer version matrix in CI: 2.4, 2.7, 2.8, 2.9 and latest on matching PHP versions.
- Generated CLI reference page, CI integration guide with gate policies.

### Changed

- Composer releases before 2.10 have no `Installer::getLockTransaction()`; the in-process solver
  now performs a lock-only update inside the scratch copy there and reads the lock back.
- Solver results are copied into detached package objects and cycles are collected after each
  solve; peak memory for 136 solves dropped from 1.5 GB to 87 MB.

[0.4.0]: https://github.com/hexblot/composer-remediate/releases/tag/v0.4.0

[0.3.0]: https://github.com/hexblot/composer-remediate/releases/tag/v0.3.0

## [0.2.0] - 2026-09-09

### Added

- `composer remediate:db-build`: builds a local SQLite advisory database from Packagist's full
  dump, OSV's Packagist archive and the FriendsOfPHP repository; records sharing an identifier are
  merged, every source's range is kept, semantic disagreements are flagged, and a dataset hash
  identifies the logical content. `--include` merges private advisories from a JSON file.
- `composer remediate --database-location=<path|URL>`, `REMEDIATE_DATABASE` and
  `extra.remediate.database` read advisories from such a database, also offline; URLs are cached.
- `composer remediate:db-status` shows provenance, source record counts and the dataset hash.
- A reference database published by this project as GitHub releases `db-YYYY-MM-DD.HH` (and the
  `advisory-db-latest` pointer), refreshed hourly and released only when the dataset changes, with
  sha256 and build-provenance attestation.
- Report summary at the end of every format: findings count and one verified command that fixes all
  findings, or how many of them it fixes.
- Generated CLI reference page (`docs/cli-reference.md`), CI integration guide, coloured console
  output, stored example reports per fixture.

### Changed

- `--offline` now also covers the advisory lookup; without a snapshot or database it exits 4 with a hint.
- Development-only findings are listed after production ones.

[0.2.0]: https://github.com/hexblot/composer-remediate/releases/tag/v0.2.0

## [0.1.0] - 2026-09-09

First release. A Composer plugin (`composer remediate`) that finds the smallest Composer-verified
`composer update` command removing each known vulnerability from `composer.lock`.

### Added

- Advisory matching from the configured repositories (Packagist by default) or a JSON snapshot
  (`--advisories-file`), including packages reached through `replace` and `provide`.
- Dependency paths to the root for every finding.
- Candidate commands from least to most invasive: plain update, update with dependencies, parent
  update with all dependencies, root-constraint widening, optional direct requirement
  (`--allow-direct-require`).
- Validation of every candidate with Composer's own solver in a dry run; the resulting lock is
  re-checked against the advisories.
- Lowest-working-parent-version search, conflict-driven discovery of sibling packages that pin the
  parent, and simplification of the winning command.
- Deterministic ranking: no root constraint changes, no major changes, no pre-releases, fewest
  changes, smallest version movement.
- One combined command for all findings, verified, with a report summary ("fixes k of n").
- Text (coloured in a terminal), HTML (self-contained) and JSON reports; `--format` for stdout and
  repeatable `--output` files.
- `--offline`, `--ignore`, `--no-dev`, `--ignore-platform-req(s)`; `config.audit.ignore` and
  `config.policy.advisories.ignore` are honoured.
- Exit codes: 0 clean, 1 fix available, 2 no verified fix, 3 error, 4 advisories unavailable,
  5 network failure during solving.
- Fixture harness with frozen package metadata and advisory snapshots; six fixtures including five
  real historical projects.

[0.1.0]: https://github.com/hexblot/composer-remediate/releases/tag/v0.1.0
