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

## Phase 3 — ecosystem corpus, CI, version matrix

- Drupal, Symfony and Laravel fixture corpora
- Composer 2.4 through latest, PHP 8.1 through 8.5 in CI
- [x] CI integration recipes (GitHub Actions, GitLab CI, JSON gates)
- [x] published JSON Schema for the report (`docs/schema/report.schema.json`), validated against every fixture report in the test suite

## Phase 4 — global planning

- treat all findings jointly and search for the smallest command set that fixes everything
- explain why smaller changes were rejected

## Phase 5 — optional automation

- `--apply`, only after the planner has earned trust
