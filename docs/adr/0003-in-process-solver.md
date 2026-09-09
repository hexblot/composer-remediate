# 0003 — Validate with an in-process `Installer` dry-run, subprocess fallback

**Status:** accepted, 2026-09-09

## Context

The technical design left open whether to use Composer as a library or as a subprocess.
Investigation of Composer's source established that `Installer::getLockTransaction()` exists and
that a dry-run stores the new lock array in memory (`Locker::setLockData()` with `$write = false`
populates a cache readable through `getLockData()`), while `composer update --dry-run` on the
command line has no machine-readable output.

## Decision

Primary route: for each candidate create a fresh `Composer` instance with plugins and scripts
disabled, configure `Installer` for a dry-run update, run it, and read the lock transaction and
virtual lock. Fallback route: run `composer update … --no-install --no-scripts --no-plugins
--no-audit` in a scratch copy of the project and read the written lock file. Both produce the same
`LockDiff`.

## Alternatives

- **Subprocess only.** Simplest coupling, but a PHP boot per candidate, repeated metadata loading,
  and scratch-directory management, for no gain in fidelity since the plugin already runs inside
  the user's Composer.
- **Library only.** Leaves no escape hatch when Composer's `Installer` API changes.

## Consequences

- Candidate evaluation is fast enough to try many candidates per finding.
- The solver's own failure explanation is captured through a buffered IO for the report.
- Isolation between successive in-process runs must be verified (static caches such as
  `Intervals` are cleared between runs).
