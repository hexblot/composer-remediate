# How it works

The planner is a loop over *candidates*, where every candidate is a concrete `composer update`
invocation. Nothing is inferred about what "ought" to resolve; Composer's solver decides.

```text
composer.json + composer.lock
        │
        ▼
 dependency graph ─────► advisory matching ─────► findings
        │                                             │
        │                                             ▼
        │                                   candidate generation
        │                                   (ordered, least invasive first)
        │                                             │
        ▼                                             ▼
 for each candidate:  Composer\Installer dry-run  ──► new lock (in memory)
                              │
                              ├── solver failed ──────────► rejected (with the solver's reason)
                              │
                              └── solved ──► re-match advisories on new lock
                                                   │
                                                   ├── still vulnerable ──► rejected
                                                   └── clean ────────────► valid candidate
                                                                                 │
                                                                                 ▼
                                                                          ranking → plan
```

## 1. Dependency graph

The locked packages are loaded through Composer's `Locker` and wrapped in an
`InstalledRepository`, the same structure `composer why` walks. For each vulnerable package the
planner collects every path back to the root, so a package required by two parents produces two
paths, and a remediation that fixes one path but leaves the other blocking is rejected later by the
solver.

Root-controlled packages are those named in the project's `require` or `require-dev`.

## 2. Advisory matching

Advisories arrive through an `AdvisoryProvider`. Phase 0 uses the same Packagist advisory API that
`composer audit` uses, through Composer's own repository classes. Each advisory carries an
*affected versions* constraint; the locked version is tested against it with Composer's semver
implementation, so dev branches and aliases behave exactly as they do in Composer.

Composer does not consult `replace` declarations when matching advisories. The planner does: a
monorepo package such as `symfony/symfony` is checked against advisories for every package it
replaces.

## 3. Candidate generation

For a vulnerable package `V` with fixed range `F`, and `A` the nearest root-required ancestor on
each path, candidates are generated in this order:

| # | Command shape | When it wins |
|---|---|---|
| 1 | `composer update V` | The lock file is simply stale; the existing constraints already permit a fixed version. |
| 2 | `composer update V -w -m --with V:F` | The parent constraint permits a fixed version but a sibling dependency also has to move. |
| 3 | `composer update A -W -m --with V:F` | The parent must move. Tried for the nearest `A` first, then further ancestors, then the union of ancestors when several parents block. |
| 4 | widen the root constraint of `A` to the next major, then `composer update A -W -m` | No release within the current root constraint works. Tagged as a major change. |
| 5 | add `V` as a direct requirement with range `F` | Advanced strategy, disabled by default: it takes ownership of a transitive package. |

`--with V:F` is a temporary constraint. Composer applies it by removing every version of `V`
outside `F` from the solver's pool, and it works for transitive packages since Composer 2.4. The
package must still be reachable through the allow list or `-w`/`-W` for the solver to change it.

### Finding the lowest working parent version

`composer update A -W -m` keeps *transitive* packages where they are when possible, but it still
moves `A` itself to the newest version the root constraint allows. That is often more than the
smallest safe change: if `A` 1.1.0 already requires the fixed `V`, jumping to `A` 1.2.0 may drag
other packages along. After a parent update validates, the planner therefore probes downwards with
a temporary upper bound on `A` (`--with 'A:>current,<newest'`) until the solve breaks or the
vulnerability comes back, and then pins the lowest version that worked:

```text
composer update A:1.1.0 -W -m --with 'V:>=1.1.0'
```

The descent is bounded to a handful of solves per finding. Both the pinned command and the plain
one are kept as candidates; ranking decides.

## 4. Validation

Each candidate is executed as a **dry-run** of Composer's `Installer` against a fresh in-memory
`Composer` instance with plugins and scripts disabled. A dry-run writes nothing and installs
nothing, but it does compute the full lock transaction, which the planner reads back. If the solver
fails, the candidate is rejected and the solver's explanation is kept for the report.

A successful solve is not enough. The planner re-runs advisory matching on the new lock, and a
candidate that resolves but still contains an affected version is rejected.

When running in-process is impossible, a fallback runs `composer update … --no-install` in a
scratch copy of the project and reads the written lock file. Both routes produce the same lock
diff.

## 5. Ranking

Valid candidates are ordered by deterministic rules, in this order of precedence:

1. no root constraint changes;
2. no major-version changes;
3. fewest changed packages;
4. fewest direct dependency changes;
5. fewest removals and additions;
6. smallest total version movement.

A weighted score may replace these rules once the fixture corpus provides evidence for the weights.

## 6. Multiple findings

Per-finding winners are merged into a single command, which is validated again. If every finding
disappears, the report presents one combined plan; otherwise it presents per-finding plans.

## 7. Output

Text output follows the format on the [home page](index.md). JSON output exposes the same structure
plus reproducibility metadata: engine version, advisory source and fetch time, Composer and PHP
versions, and hashes of `composer.json` and `composer.lock`.
