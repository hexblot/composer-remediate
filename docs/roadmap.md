# Roadmap

This page is the current plan; the [design decisions](design-decisions.md) page explains the reasoning
behind it. The original pitch documents that started the project are in the repository history
(first commits on `main`).

## Phase 0 — prove the algorithm *(in progress)*

Exit criterion: five real historical fixtures, and the planner reproduces the human-chosen
remediation for at least four.

- [x] ddev development environment, CI, this documentation site
- [x] fixture format and harness with frozen package metadata, `bin/build-fixture.php`
- [x] dependency graph, advisory matching (including `replace`), candidate generation, in-process
  solver validation, lowest-parent-version descent, deterministic ranking, text output
- [x] `composer remediate` command wired as a plugin, text/HTML/JSON reports, multiple `--output` files
- [ ] five real historical fixtures with the human-chosen remediation recorded
- [ ] planner reproduces the human choice for at least four of them

This phase is a go/no-go gate. If the simplest strategy trivially wins every fixture, the
documentation will say so and the project narrows to multi-finding planning, explanation and CI
output.

## Phase 1 — deterministic single-finding remediation (release 0.1)

- hardening, PHPStan level 8, classified solver failures
- [x] JSON and HTML output with reproducibility metadata (pulled forward from Phase 1)
- merge per-finding commands into one combined plan and re-verify
- `--offline`, `--ignore`, respect for `config.audit.ignore` and `config.policy`
- first Packagist release

## Phase 2 — advisory database: build locally, share centrally

- source adapters: OSV, FriendsOfPHP, Packagist API, local or organisational overrides
- normalised advisory model with alias-based deduplication and explicit conflict flags
- `remediate db:build` producing a SQLite file; `--database-location` to use a shared one
- a reference shared instance published by this project, signed, released only when the data changes

## Phase 3 — ecosystem corpus, CI, version matrix

- Drupal, Symfony and Laravel fixture corpora
- Composer 2.4 through latest, PHP 8.2 through 8.5 in CI
- CI integration recipes and a published JSON schema

## Phase 4 — global planning

- treat all findings jointly and search for the smallest command set that fixes everything
- explain why smaller changes were rejected

## Phase 5 — optional automation

- `--apply`, only after the planner has earned trust
