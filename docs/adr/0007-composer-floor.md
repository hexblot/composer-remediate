# 0007 — Composer 2.4 minimum, 2.9 for the full feature set

**Status:** accepted, 2026-09-09

## Context

The pitch's example command uses `-m` (`--minimal-changes`). Composer's changelog places that flag
in 2.9.0 (November 2025), `composer audit` and temporary constraints on transitive packages in 2.4.0,
and `--no-install` in 2.0.

## Decision

Refuse to run on Composer older than 2.4. On 2.4 through 2.8 omit `-m` and warn that resulting diffs
may be larger than necessary. Develop and test against `composer/composer ^2.9` with 2.4, 2.8, 2.9
and the latest release in the CI matrix. PHP 8.1 or newer.

## Consequences

- Users on current Composer get the intended behaviour; users on older 2.x still get valid plans.
- Runtime detection through `Composer::getVersion()` decides which flags are emitted.
