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
- [x] 0.1.0 tagged; Packagist submission is a manual step for the maintainer

## Phase 2 — advisory database: build locally, share centrally *(complete)*

- [x] source adapters: Packagist full dump, OSV Packagist archive, FriendsOfPHP (zip or local checkout)
- [x] normalised advisory model with alias-based deduplication, every source's range kept, conflicts flagged
- [x] `composer remediate:db-build` producing a SQLite file with a dataset hash; `remediate:db-status`
- [x] `--database-location` (path or URL), `REMEDIATE_DATABASE`, `extra.remediate.database`
- [x] private or organisational advisories as an additional source (`--include=<json>`)
- [x] a reference shared instance published by this project (`.github/workflows/advisory-db.yml`): hourly build, release only when the dataset hash changes, sha256 and build-provenance attestation, `advisory-db-latest` moving pointer

## Phase 3 — ecosystem corpus, CI, version matrix *(in progress)*

- [x] fixture corpus grown to twelve: BookStack ×4, koel, Pixelfed, Invoice Ninja, Kimai (Laravel and
  Symfony), Islandora and USAGov (Drupal), Shopware ×2; covers multi-parent, two-level chain,
  platform-bound and constraint-bound "no fix" cases (see [Test fixtures](fixtures.md))
- [ ] more Drupal and plain Symfony application cases (five each was the target; two and three so far)
- [x] Composer version matrix in CI (2.4, 2.7, 2.8, 2.9 and latest) on matching PHP versions, with the
  lock-file fallback for releases without `Installer::getLockTransaction()`; PHP 8.1 through 8.5
- [x] CI integration recipes (GitHub Actions, GitLab CI, JSON gates)
- [x] published JSON Schema for the report (`docs/schema/report.schema.json`), validated against every
  stored fixture report and every freshly rendered one in the test suite
- [x] the recommended command is executed by the real Composer binary in the harness (fixtures with
  `"execute": true`) and the written lock re-matched
- [x] `composer-remediate` standalone binary for a plugin-free boundary; solver fallback wired;
  scoped ignore policy; typed infrastructure failures in the exit code (external review, see
  the changelog)

## Phase 4 — global planning

- treat all findings jointly and search for the smallest command set that fixes everything
- explain why smaller changes were rejected

## Phase 5 — optional automation

- `--apply`, only after the planner has earned trust
- a GitHub Action wrapper that runs `--apply` on a schedule and opens **one batched pull request**
  with advisory ids, before/after finding counts and the verified commands (the shape CVE Lite CLI
  uses, rather than one PR per package)

## Phase 6 — integrations and prioritisation

Features that [CVE Lite CLI](https://github.com/OWASP/cve-lite-cli) has proven useful for the
JavaScript ecosystem and that transfer to Composer, in priority order.

1. **SARIF output** (`--output=results.sarif`) for GitHub Code Scanning and GitLab's
   dependency-scanning report (`--output=gl-dependency-scanning-report.json`): done.
2. **CycloneDX 1.6 SBOM with vulnerabilities attached** (`--output=sbom.cdx.json`), using the
   per-vulnerability `recommendation` field for the verified command: done.
3. **`--fail-on <severity>`** gate threshold, combined with the existing exit codes: done.
4. **EPSS and CISA KEV enrichment** in the advisory database build: exploit likelihood and
   "exploited in the wild" flags, used to order findings by urgency rather than severity label alone.
5. **Constraint drag** as an explicit finding (the root constraint that blocks every in-range fix is
   named in the report and counted in the summary): done. Abandoned parents on the path, using
   Packagist's abandoned marker: open.
6. **Baseline / ratcheting mode** (`--baseline`, `--update-baseline`): done.
7. **`--min-release-age <days>`** supply-chain cooldown: done.
8. **Ignore hygiene**: stale `--ignore` / `config.audit.ignore` / `config.policy` entries are reported
   as a warning: done.

Deliberately not adopted: license compliance and usage-based reachability (outside the remediation
scope), npm-style override hygiene (no Composer equivalent), multi-lockfile monorepo scanning (rare
for Composer projects).
