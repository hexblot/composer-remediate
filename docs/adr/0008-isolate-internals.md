# 0008 — Touch Composer's `@internal` classes only inside adapters

**Status:** accepted, 2026-09-09

## Context

Composer's advisory classes (`Auditor`, `SecurityAdvisory`, `AdvisoryProviderInterface`,
`RepositorySet::getMatchingSecurityAdvisories`) are marked `@internal`. `Auditor::audit()` changed
its signature in each of 2.7, 2.8, 2.9 and 2.10, and 2.10 deprecated `config.audit` in favour of
`config.policy`.

## Decision

The engine defines its own `AdvisoryProvider` interface and `Advisory` value object. Exactly one
adapter class talks to Composer's advisory internals, and a second adapter shells out to
`composer audit --locked --format=json` when the in-process interface is missing or incompatible.
The same rule applies to any other `@internal` API the engine needs.

## Consequences

- A Composer release that changes an internal signature breaks one adapter, not the engine.
- Fixtures feed the engine through a JSON provider that never touches Composer's classes.
