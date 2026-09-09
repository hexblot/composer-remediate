# 0010 — Disable Composer's advisory blocking inside candidate solves

**Status:** accepted, 2026-09-09

## Context

Composer 2.10 introduced `config.policy.advisories.block` (default true). During an update, a
`SecurityAdvisoryPoolFilter` removes every version with a known advisory from the solver pool for
packages that are not locked, after fetching advisories from the repositories. Older Composer
releases have no such filter.

## Decision

Candidate solves run with blocking disabled (`Installer::setPolicyConfig()` with
`withBlockingDisabled()` in-process; `COMPOSER_NO_BLOCKING=1` for the subprocess fallback). The
planner performs its own advisory check on every resulting lock, using the same advisory provider
that produced the findings, and rejects candidates that keep the vulnerability or introduce a new
one.

## Alternatives

- **Rely on the pool filter.** It would make results differ between Composer 2.4–2.9 and 2.10+,
  perform an extra network round-trip per solve, and use Packagist's advisories even when the user
  supplied a different advisory source (a private database, a fixture snapshot).

## Consequences

- Identical behaviour across the supported Composer range and fully offline fixtures.
- The recommended command, when the user runs it on Composer 2.10+, additionally benefits from
  blocking; the planner's result is a lower bound on safety, not an upper bound.
- The Phase 0 evaluation question "does blocking make the tool redundant?" is answered in part: the
  filter picks safe versions once the user has chosen *which* package to update, which is precisely
  the choice this tool makes.
