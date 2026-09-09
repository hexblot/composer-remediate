# 0006 — Fixtures freeze package metadata, not just advisories

**Status:** accepted, 2026-09-09

## Context

The design pinned the advisory database hash for reproducibility but not the package metadata the
solver consumes. The smallest valid upgrade for a historical lock file changes whenever upstream
publishes a release, so solver-backed tests against live Packagist rot within weeks.

## Decision

Every fixture ships a static Composer repository (`repo/packages.json`) with every package version
the solver may consider, and the harness disables packagist.org. Composer accepts `file://` URLs
for `type: composer` repositories, so no web server is involved.

## Consequences

- Fixture tests are deterministic and run offline in CI.
- Fixtures are larger; a `build-fixture` script assembles the repository from a warm Composer
  cache so they are not hand-written.
- `COMPOSER_DISABLE_NETWORK` is not used in fixture runs because its check precedes Composer's
  local-file transport.
