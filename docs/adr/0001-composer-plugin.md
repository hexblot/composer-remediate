# 0001 — Ship as a Composer plugin, not a standalone CLI

**Status:** accepted, 2026-09-09

## Context

The pitch describes a standalone `composer-remediate` binary. The remediation engine needs the
project's repositories, authentication, platform configuration and Composer version to reproduce
the user's real resolution context.

## Decision

Deliver the tool as a Composer plugin exposing `composer remediate`. The engine is written as a
plain library under `Remediate\Engine` so a standalone wrapper can be added later without
restructuring.

## Alternatives

- **Standalone CLI depending on `composer/composer`.** Full control, but it must rediscover
  `auth.json`, private repositories, `config.platform` and the installed Composer version, and it
  may bundle a different Composer than the one the user runs.

## Consequences

- Private Packagist and Satis users get a working tool on day one.
- The plugin uses exactly the solver the user uses, so validation results match what
  `composer update` will do.
- Installation is `composer global require`, the most natural path for the audience.
- Coupling to Composer's plugin API (`composer-plugin-api ^2.0`) is accepted; see
  [0008](0008-isolate-internals.md).
