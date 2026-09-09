# 0005 — Advisory database is built locally from live sources and may be shared centrally

**Status:** accepted, 2026-09-09

## Context

The pitch devoted roughly half of the technical design to a signed SQLite advisory artifact with an
hourly publish-on-change pipeline. Packagist, OSV and FriendsOfPHP already publish advisory data,
and Composer already parses Packagist's.

## Decision

The database is a local build: `remediate db:build` pulls the configured sources and writes a
SQLite file. Because the file is portable, a team or this project can publish it, and users point
at a shared copy with `--database-location <path-or-URL>` to avoid rebuilding on every run. The
project's own published, signed, released-only-on-change artifact is the reference instance of that
sharing model, not a separate product. Phases 0 and 1 use Packagist's advisory API through
Composer's classes and do not need the database at all.

## Consequences

- Remediation quality is delivered before any data infrastructure exists.
- Offline analysis, private advisories and reproducible advisory snapshots are served by the same
  file format whether built locally or downloaded.
- The signed-artifact pipeline is built last and only after the local build is stable.
