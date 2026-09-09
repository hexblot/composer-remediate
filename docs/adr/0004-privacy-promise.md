# 0004 — Promise "no third party sees your graph", not "fully offline"

**Status:** accepted, 2026-09-09

## Context

The pitch promised that `plan` runs fully offline and that the dependency graph never leaves the
machine. Composer's solver needs package metadata for every version it considers and fetches it
from the configured repositories; the Packagist advisory API receives package names. Both facts
were verified in Composer's source.

## Decision

State the promise as: *no third party sees your dependency graph; network use is exactly what
`composer update` itself would do against your configured repositories.* Provide a real `--offline`
mode that sets `COMPOSER_DISABLE_NETWORK` and fails loudly on a cache miss rather than silently
using the network.

## Consequences

- The documentation lists exactly which data goes where.
- The Phase 2 advisory database removes the advisory-lookup request; solver metadata requests
  remain and are identical to a normal update.
