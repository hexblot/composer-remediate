# 0009 — Search downwards for the lowest parent version that admits the fix

**Status:** accepted, 2026-09-09

## Context

Composer's `--minimal-changes` keeps *transitive* packages at their locked versions when possible,
but the package named on the command line is still moved to the newest version its constraints
allow. In the synthetic fixture, `composer update acme/app-framework -W -m` jumped the parent from
1.0.0 to 1.2.0 and dragged a sibling along (three changes), although 1.1.0 already required the fixed
child (two changes). The pitch explicitly asks for "the smallest parent upgrade that permits" a
fixed version.

## Decision

After a parent-update candidate validates, the planner probes downwards: it re-solves with a
temporary upper bound on the parent (`--with 'A:>current,<newest'`), accepts the result if it is
still valid and lower, and repeats until the solve breaks, the vulnerability returns, or a small step
budget is exhausted. The lowest working version is then pinned as an extra candidate rendered as
`composer update A:1.1.0 -W -m …`, and ranking decides between the pinned and the plain command.

## Alternatives

- **Enumerate parent versions from repository metadata.** Requires loading metadata outside the
  solver and reimplementing the eligibility check the solver already performs.
- **Only report the plain command.** Simpler, but contradicts the minimal-blast-radius principle and
  would have failed the fixture a human would consider obvious.

## Consequences

- A few extra solves per finding; bounded by `Planner::MAX_DESCENT_STEPS`.
- Candidates gained the notion of *pins* (`name:version` in the allow list), which are temporary
  constraints from the solver's point of view.
- The descent applies to single-parent updates and root-constraint widenings; multi-parent unions
  are left as they are for now.
