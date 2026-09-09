# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/).

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
