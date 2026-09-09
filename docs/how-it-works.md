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

### Sibling packages that pin the parent

Meta-package families pin each other exactly: `shopware/administration` requires `shopware/core
6.4.15.1`, `drupal/core-dev` requires `drupal/core 10.3.1`. Updating the parent alone then fails
with Composer's message "X is locked to version … and an update of this package was not
requested". The planner reads those names out of the solver output, adds them to the command and
retries, a bounded number of times, so the recommendation becomes
`composer update shopware/core shopware/storefront shopware/administration … -W -m`.

### Simplifying the winning command

`--with` and `-m` exist to steer the solver during the search. Before a command is recommended,
the planner re-solves it without them (each separately, then both) and keeps the simplest spelling
that produces exactly the same lock. A human ends up with `composer update acme/app-framework:1.1.0
-W -m` rather than the same command with a trailing constraint they would never have typed.

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
3. no pre-release versions (alpha, beta, RC, dev) among the targets;
4. fewest changed packages;
5. fewest direct dependency changes;
6. fewest removals and additions;
7. smallest total version movement, measured on the actual version numbers so a lower parent
   version wins a tie.

A weighted score may replace these rules once the fixture corpus provides evidence for the weights.

## 6. Multiple findings

Several advisories on the same package are planned together: the fixed range is the complement of
the union of their affected ranges, and a candidate is valid only when all of them are gone. One
package, one command.

Across packages, the per-package winners are merged into a single command and validated with one
more solve. The report's summary then says either "you can fix all N findings with …", or "… fixes
k of N findings" when some advisories have no reachable fix, or lists the per-package commands when
no single command resolves.

## 7. Pruning

Two rules keep the number of solves small. Root-constraint widening is never tried once a valid
candidate without root changes exists, because ranking rule 1 would discard it anyway. The parent
descent is skipped when an existing valid candidate is already at least as good as the best result
the descent could reach (two changed packages, no major change). Skipped candidates are listed in
the report so the reasoning stays visible.

## 8. Output

Text output is the default:

```text
CVE-2026-XXXXX
────────────────────────────────────────────────────────────
Affected
  symfony/http-foundation 6.4.21
  CVE-2026-XXXXX: <advisory title>
    affected versions: >=6.4.0,<6.4.24
Introduced by
  root
  └── drupal/core-recommended 11.4.2
      └── symfony/http-foundation 6.4.21  (requires 6.4.21)
Current state
  Transitive dependency.
Recommended remediation
  drupal/core-recommended 11.4.2 -> 11.4.3
  symfony/http-foundation 6.4.21 -> 6.4.24
Composer validation
  PASS  3 packages changed, 0 added, 0 removed, 0 root constraints changed
Expected changes
  drupal/core 11.4.2 -> 11.4.3
  drupal/core-recommended 11.4.2 -> 11.4.3
  symfony/http-foundation 6.4.21 -> 6.4.24
Recommended command
  composer update drupal/core-recommended -W -m --with 'symfony/http-foundation:>=6.4.24'
Other candidates
  rejected: composer update symfony/http-foundation
      resolves, but symfony/http-foundation ends at 6.4.21 which is still affected by CVE-2026-XXXXX
```

Three report formats exist and can be produced in one run. `--format` (default `text`, or `none`)
chooses what goes to standard output; `--output` writes a file whose format is inferred from its
extension and may be repeated:

```bash
composer remediate --output=report.html --output=report.json          # text on stdout, two files
composer remediate --format=none --output=report.json                 # file only, quiet stdout
composer remediate --format=json | jq '.findings[].remediation.command'
```

- **text**: the human-readable plan above.
- **html**: a self-contained page (inline CSS, no scripts, no external resources) with a summary
  table, one section per finding, the dependency paths, the expected changes and every candidate
  that was tried or skipped. Suitable as a CI artifact.
- **json**: the same content for machines. Top-level keys: `schema_version`, `analysis_metadata`
  (Composer and PHP versions, advisory source, hashes of `composer.json` and `composer.lock`,
  timestamp), `exit_code`, `warnings`, `findings[]` (package, advisories, the first ten dependency
  paths plus `paths_total`, `remediation` with `status`, `command`, `summary` and `changes`, and all
  `candidates` with their outcome) and `unsolved_findings[]`. Stored examples for every fixture live
  under `tests/Fixture/<name>/reports/`.
