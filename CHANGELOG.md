# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

This release responds to an external architecture review of 0.3.0 (twenty findings, nine rated as
able to undermine a security decision). Every finding is addressed below and covered by a test.

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
- Tests for each guarantee: planner rules with a scripted solver (unknown severity, tool-error and
  network exits, combined-command cooldown, `--no-dev` baseline, all-advisory fixed range, platform
  flags, blocking risk, budget), parser strictness, OSV `versions`/`limit`, ignore scoping, HTML link
  safety, fallback solver; freshly rendered JSON validated against the schema for every fixture; the
  synthetic fixture's recommended command executed by the real Composer binary and the resulting
  lock re-matched.

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
