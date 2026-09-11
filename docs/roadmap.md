# Roadmap

This page is the current plan; the [design decisions](design-decisions.md) page explains the reasoning
behind it. The original pitch documents that started the project are in the repository history
(first commits on `main`).

## Phase 0 — prove the algorithm *(complete)*

Exit criterion: five real historical fixtures, and the planner reproduces the human-chosen
remediation for at least four.

- [x] ddev development environment, CI, this documentation site
- [x] fixture format and harness with frozen package metadata, `bin/build-fixture.php`
- [x] dependency graph, advisory matching (including `replace`), candidate generation, in-process
  solver validation, lowest-parent-version descent, deterministic ranking, text output
- [x] `composer remediate` command wired as a plugin, text/HTML/JSON reports, multiple `--output` files
- [x] five real historical fixtures with the human-chosen remediation recorded
- [x] planner reproduces the human choice for five of five (see [Test fixtures](fixtures.md))

This phase was a go/no-go gate: if the simplest strategy trivially won every fixture, the project
would have been a thin wrapper. It did not. Three of the five real cases needed machinery that no
single `composer update` invocation provides: the lowest-parent-version search (Drupal, Shopware),
conflict-driven discovery of sibling packages that pin the parent (Shopware), and the platform-bound
"no fix" verdict with the PHP requirement as the explanation (BookStack on PHP 8.0). The go decision
stands.

## Phase 1 — deterministic single-finding remediation (release 0.1) *(complete)*

- [x] hardening, PHPStan level 8, classified solver failures (conflict, network, error) with exit code 5 for network
- [x] JSON and HTML output with reproducibility metadata
- [x] merge per-finding commands into one combined, re-verified command; report summary says how many findings it fixes
- [x] `--offline`, `--ignore`, respect for `config.audit.ignore` and `config.policy.advisories.ignore`
- [x] `provide` handled like `replace` in matching; development-only findings listed after production ones
- [x] 0.1.0 tagged; published on Packagist as `hexblot/composer-remediate`

## Phase 2 — advisory database: build locally, share centrally *(complete)*

- [x] source adapters: Packagist full dump, OSV Packagist archive, FriendsOfPHP (zip or local checkout)
- [x] normalised advisory model with alias-based deduplication, every source's range kept, conflicts flagged
- [x] `composer remediate:db-build` producing a SQLite file with a dataset hash; `remediate:db-status`
- [x] `--database-location` (path or URL), `REMEDIATE_DATABASE`, `extra.remediate.database`
- [x] private or organisational advisories as an additional source (`--include=<json>`)
- [x] a reference shared instance published by this project (`.github/workflows/advisory-db.yml`): hourly build, release only when the dataset hash changes, sha256 and build-provenance attestation, `advisory-db-latest` moving pointer

## Phase 3 — ecosystem corpus, CI, version matrix *(complete)*

- [x] fixture corpus grown to twelve: BookStack ×4, koel, Pixelfed, Invoice Ninja, Kimai (Laravel and
  Symfony), Islandora and USAGov (Drupal), Shopware ×2; covers multi-parent, two-level chain,
  platform-bound and constraint-bound "no fix" cases (see [Test fixtures](fixtures.md))
- [x] more Drupal and plain Symfony application cases: Mass.gov, Open Social and Acquia CMS (five
  Drupal), wallabag and Mautic (five Symfony); a distribution pin, two monorepos with `path`
  packages, and dependencies stuck behind a project's own constraint (seventeen real fixtures)
- [x] Composer version matrix in CI (2.4, 2.7, 2.8, 2.9 and latest) on matching PHP versions, with the
  lock-file fallback for releases without `Installer::getLockTransaction()`; PHP 8.1 through 8.5
- [x] CI integration recipes (GitHub Actions, GitLab CI, JSON gates)
- [x] published JSON Schema for the report (`docs/schema/report.schema.json`), validated against every
  stored fixture report and every freshly rendered one in the test suite
- [x] the recommended command is executed by the real Composer binary in the harness (fixtures with
  `"execute": true`) and the written lock re-matched
- [x] `composer-remediate` standalone binary for a plugin-free boundary; solver fallback wired;
  scoped ignore policy; typed infrastructure failures in the exit code (adversarial adoption review,
  see the changelog)

## Phase 4 — global planning *(complete)*

- [x] treat all findings jointly and search for the smallest command set that fixes everything: the
  merged winners, then swaps of lower-ranked candidates for findings in the way, then shrinking by
  dropping contributions whose package a sibling's fix already moves, within a solve budget
- [x] explain why smaller changes were rejected: every step of the search is listed in the summary
  and in `summary.combined_search` of the JSON report, with the solver's reason

## Phase 5 — optional automation *(next)*

- [ ] `--apply`, only after the planner has earned trust
- [ ] a GitHub Action wrapper that runs `--apply` on a schedule and opens **one batched pull request**
  with advisory ids, before/after finding counts and the verified commands (the shape CVE Lite CLI
  uses, rather than one PR per package)

## Phase 6 — integrations and prioritisation *(complete)*

Features that [CVE Lite CLI](https://github.com/OWASP/cve-lite-cli) has proven useful for the
JavaScript ecosystem and that transfer to Composer, in priority order.

- [x] **SARIF output** (`--output=results.sarif`) for GitHub Code Scanning and GitLab's
  dependency-scanning report (`--output=gl-dependency-scanning-report.json`)
- [x] **CycloneDX 1.6 SBOM with vulnerabilities attached** (`--output=sbom.cdx.json`), using the
  per-vulnerability `recommendation` field for the verified command
- [x] **`--fail-on <severity>`** gate threshold, combined with the existing exit codes
- [x] **EPSS and CISA KEV enrichment** in the advisory database build: exploit likelihood and
  "exploited in the wild" flags, used to order findings by urgency rather than severity label alone
- [x] **Constraint drag** as an explicit finding: the root constraint that blocks every in-range fix is
  named in the report and counted in the summary
- [x] **Abandoned parents** on the dependency path, using Packagist's abandoned marker (read from
  the lock file, so it works offline)
- [x] **Baseline / ratcheting mode** (`--baseline`, `--update-baseline`)
- [x] **`--min-release-age <days>`** supply-chain cooldown
- [x] **Ignore hygiene**: stale `--ignore` / `config.audit.ignore` / `config.policy` entries are reported
  as a warning

Deliberately not adopted: license compliance and usage-based reachability (outside the remediation
scope), npm-style override hygiene (no Composer equivalent), multi-lockfile monorepo scanning (rare
for Composer projects).

## Phase 7 — goal-driven planning *(candidate, after Phase 5)*

Motivating case: [composer/composer#12777](https://github.com/composer/composer/discussions/12777).
A TYPO3 12 project requires `typo3/cms-core` and one extension; the extension requires
`typo3/cms-dashboard`, which the project never lists. The documented major-upgrade command fails,
Composer's error names the extension as "locked and not requested" but never the dashboard package,
and adding it by hand makes the upgrade work. The planner's conflict-expansion step already reads
those "locked" lines, widens the allow list and retries, and the report prints the resulting command
with the solver's output as evidence. It does not run here only because nothing in that lock carries
an advisory. The engine finds the smallest verified change that reaches a goal; a security fix is one
goal, "this package at this constraint" is another.

- [ ] a goal as input (`package:constraint`, one or several) in place of an advisory: candidate
  generation takes the target constraint where it now takes the fixed range above the advisory;
  acceptance becomes "the target is satisfied and no advisories are introduced"
- [ ] a run with no advisory data at all is valid for a goal (today it exits 4), while the
  no-new-advisories rule still applies whenever data is available; the fail-closed paths get their own
  tests for this mode
- [ ] goal-aware ranking: widening a root constraint is a last resort for a security fix and the point
  of a major upgrade; constraint drag is reported as the plan, not as a finding
- [ ] the same reports, exit codes and global combination; several goals are planned jointly
- [ ] fixtures: the TYPO3 case above built with `bin/build-fixture.php`, and two or three more from
  Composer's discussions board, with the human-chosen command recorded as for the security fixtures
- [ ] `--apply` and the batched pull request from Phase 5 accept goals too

Boundary: the goal is a version constraint on a locked package. Interpreting release notes, judging
breaking changes or choosing the target version is out of scope; the user names the goal and the
planner finds the smallest verified command that reaches it.

## Assurance *(ongoing, alongside the phases)*

Work that does not add features but decides whether the recommendations can be trusted. Each item
has a regression test behind it; the [changelog](https://github.com/hexblot/composer-remediate/blob/main/CHANGELOG.md)
has the details.

- [x] adversarial adoption review of 0.3.0 (another AI model working from the published repository)
  and three rechecks, answered in 0.4.0, 0.4.1 and 0.4.2; the reviewer confirmed the last recheck closed
- [x] command layer, advisory feed readers and both advisory adapters under test; 225 tests, 94% of
  lines, with PCOV in CI and in the DDEV image so local and CI figures match
- [x] Aikido scan of the workflows (SHA-pinned actions, job-scoped permissions, no template injection,
  the database release bound to a protected environment) and of the code (fail closed on incomplete
  sources, unread coverage gaps and unverified database downloads; sanitised console output;
  reference-only lock changes counted), answered in 0.6.0
- [x] architecture rules with Deptrac (`deptrac.yaml`): project layers and every third-party
  namespace classified, unclassified dependencies fail CI, badge in the README
- [x] the longest methods split after a reader's review; a Severity enum replaces the last lookup table
- [ ] SonarQube Cloud for the open-source project (applied for), as an independent view on complexity
  and duplication
- [ ] remaining long methods (`InProcessSolver::solve`, `DbBuildCommand::execute`,
  `HtmlRenderer::finding`, the planner's per-finding search) and the `PackageChange` kind constants
  as an enum
- [x] a fourth adversarial review (ten findings at c545e91 on filesystem safety, advisory completeness
  and CI decisions), answered in the release after 0.6.1 with a regression test per finding
- [ ] a fifth adversarial review once `--apply` exists, since that is the first feature that changes
  a project
