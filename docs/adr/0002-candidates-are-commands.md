# 0002 — Remediation candidates are `composer update` commands

**Status:** accepted, 2026-09-09

## Context

The technical design described candidate generation, validation and ranking as three separate
subsystems operating on abstract graph edits.

## Decision

A candidate *is* one concrete `composer update` invocation: an allow list, a transitive-update mode
(`-w`/`-W`), temporary constraints (`--with`), the minimal-changes flag, and optionally a root
constraint change. Validation runs that invocation through the solver; ranking compares the
resulting lock diffs; the recommendation is the invocation that won.

## Alternatives

- **Abstract graph edits translated to commands at the end.** More expressive in theory, but
  every edit would still have to be expressed as something Composer can execute, and the
  translation step is where recommendations and reality drift apart.

## Consequences

- Sections 11, 13 and 14 of the technical design collapse into one loop.
- Every recommendation is trivially reproducible by the user.
- The design stays compatible with Composer gaining the same capability upstream.
