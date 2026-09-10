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
`composer audit` uses, through Composer's own repository classes; if that `@internal` API breaks at
runtime, the lookup falls back to a `composer audit --locked` subprocess and the report says so (see
[design decisions](design-decisions.md#touch-composers-internal-classes-only-inside-adapters)). Each advisory carries an
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
that produces exactly the same lock: the same version, the same source and dist references, and the
same production/development classification for every package. A human ends up with `composer update acme/app-framework:1.1.0
-W -m` rather than the same command with a trailing constraint they would never have typed.

## 4. Validation

Each candidate is executed as a **dry-run** of Composer's `Installer` against a fresh in-memory
`Composer` instance with plugins and scripts disabled. A dry-run writes nothing and installs
nothing, but it does compute the full lock transaction, which the planner reads back. If the solver
fails, the candidate is rejected and the solver's explanation is kept for the report.

A successful solve is not enough. The planner re-runs advisory matching on the new lock, and a
candidate that resolves but still contains an affected version is rejected.

When the in-process route fails for a reason that is neither a dependency conflict nor a network
error (an exception inside Composer's PHP API, typically a version incompatibility), the same
candidate is retried through a fallback that runs the real `composer update … --no-install` in a
scratch copy of the project and reads the written lock file. Both routes produce the same lock diff.
`--solver=in-process` or `--solver=subprocess` pins one route; the default `auto` is the fallback
chain. The subprocess uses the Composer binary that is running the plugin (or
`REMEDIATE_COMPOSER_BINARY`), so both routes solve with the same Composer release.

Whatever the route, a solve that fails for tool or network reasons is recorded as such. A finding
without a verified fix is reported as "none" only when every solve completed; when a solve errored
the outcome is "unknown" and the exit code is 3 (solver error) or 5 (network), never 2.

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
the union of *every* advisory the source knows for that package (not only the ones hitting the
locked version, so a newer release affected by a different advisory is never proposed), and a
candidate is valid only when all of them are gone. Ignored advisories do not shrink the range. One
package, one command.

Across packages, the per-package winners are merged into a single command and validated with one
more solve, under the same acceptance rules as any candidate: no new advisories, no release younger
than the cooldown, and the simplest spelling is re-matched rather than assumed. The report's summary then says either "you can fix all N findings with …", or "… fixes
k of N findings" when some advisories have no reachable fix, or lists the per-package commands when
no single command resolves.

## 7. Gating, baselines and cooldowns

The exit code encodes the outcome (0 clean, 1 fixable, 2 not fixable, 3 to 5 tool problems) and two
options shape which findings count towards it:

- `--fail-on <severity>`: findings whose advisories are all below the threshold are reported but do
  not affect the exit code. Unknown severities always count.
- `--baseline <file>`: findings listed in the file (advisory@package keys) are reported, marked
  `[baselined]`, and excluded from the exit code. `--update-baseline` writes the current findings to the
  file. This is how a gate is introduced on a project with existing findings: accept today's state,
  fail on anything new, and delete entries as fixes land.

`--min-release-age <days>` rejects every candidate whose resulting lock contains a release published
within the last N days, or a release whose date is unknown (the guard never promises an age it
cannot prove). It applies to individual candidates and to the combined command alike. It is a
supply-chain cooldown: a version that appeared yesterday may be compromised or broken, and nothing
forces a security fix to be applied within hours. When every fix is too young the finding reports
"no verified remediation" with the young releases named.

`--ignore-platform-req` and `--ignore-platform-reqs` change what the solver accepts, so a command
verified under them is only reproduced by a command that carries them: the flags are repeated in
every recommended command. When a recommended command moves a package to a version that still
carries another (pre-existing) advisory, the report flags a **blocking risk**: Composer 2.10+
advisory blocking may refuse that update until the advisory is ignored in `config.policy` or
blocking is disabled.

A finding whose only fix requires widening a `composer.json` constraint is marked as **constraint
drag**: the report names the root requirement that blocks every fix within the current constraints.
Ignore entries (`--ignore`, `config.audit.ignore`, `config.policy`) that match nothing in the lock are
reported as stale so the configuration stays honest. When the advisory source is a database, upstream
records its build could not interpret are reported as coverage gaps for the affected locked packages
(see [Advisory database](advisory-database.md#coverage-gaps)). Composer's own scoping is respected: an
`audit.ignore` entry with `apply: block` or a `policy.advisories` entry with `on-audit: false` is an
install-time exception, not an audit-time one, and does not suppress a finding here; package rules
apply only within their constraint.

## 8. Pruning and budget

Two rules keep the number of solves small. Root-constraint widening is never tried once a valid
candidate without root changes exists, because ranking rule 1 would discard it anyway. The parent
descent is skipped when an existing valid candidate is already at least as good as the best result
the descent could reach (two changed packages, no major change). Skipped candidates are listed in
the report so the reasoning stays visible.

Two limits bound the work. `--max-candidates` (default 10) caps the generated candidates per
finding; `--solve-budget` (default 60) caps solver runs per finding across every phase: candidates,
conflict-driven expansion, parent descent and simplification; the last three solves are reserved
for simplifying the winner so a long descent on a worse parent cannot starve it. Every solve is counted, probes
included, and the report carries the count per finding and in total. When either limit cuts the
search short, a finding without a fix reads "none found within the search budget" rather than
"none": the search is bounded and does not prove that no fix exists. The dependency-path walk
itself uses Composer's recursive `InstalledRepository::getDependents()`; its path and depth caps
apply to the result, not to the cost of computing it, which on a very large lock is the same cost
`composer why -r -t` pays.

## 9. Output

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
- **sarif**: SARIF 2.1.0 for GitHub Code Scanning and other SARIF consumers. One rule per advisory
  (with a numeric `security-severity`), one result per vulnerable package located at its line in
  `composer.lock`, the verified command in the result message. See [CI integration](ci-integration.md).
- **cyclonedx**: a CycloneDX 1.6 SBOM (`--output=sbom.cdx.json`) listing every locked package as a
  component with a `pkg:composer/...` purl and every advisory as a vulnerability affecting its
  component, with the verified command in the CycloneDX `recommendation` field. SBOM and VEX tooling
  can consume the plan directly.
- **gitlab**: GitLab's dependency-scanning report (`--output=gl-dependency-scanning-report.json`),
  declared as `artifacts: reports: dependency_scanning:` so findings appear in the merge request
  security widget and the vulnerability report, with the verified command as the `solution`.
- **json**: the same content for machines. Top-level keys: `schema_version`, `analysis_metadata`
  (Composer and PHP versions, advisory source, hashes of `composer.json` and `composer.lock`,
  timestamp), `exit_code`, `warnings`, `findings[]` (package, advisories, the first ten dependency
  paths plus `paths_total`, `remediation` with `status`, `command`, `summary` and `changes`, and all
  `candidates` with their outcome) and `unsolved_findings[]`. The structure is published as a JSON
  Schema at [schema/report.schema.json](schema/report.schema.json); every stored fixture report is
  validated against it in the test suite. Stored examples for every fixture live under
  `tests/Fixture/third-party/<name>/reports/`.
