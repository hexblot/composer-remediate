# Roadmap

The original pitch and technical design live in the repository under `pitch/`. This page is the
current plan; the [decision records](adr/index.md) explain where and why it departs from the pitch.

## Phase 0 — prove the algorithm *(in progress)*

Exit criterion: five real historical fixtures, and the planner reproduces the human-chosen
remediation for at least four.

- ddev development environment, CI, this documentation site
- fixture format and harness with frozen package metadata
- dependency graph, advisory matching, candidate generation, in-process solver validation,
  deterministic ranking, text output
- `composer remediate` command wired as a plugin

This phase is a go/no-go gate. If the simplest strategy trivially wins every fixture, the
documentation will say so and the project narrows to multi-finding planning, explanation and CI
output.

## Phase 1 — deterministic single-finding remediation (release 0.1)

- hardening, PHPStan level 8, classified solver failures
- JSON output with reproducibility metadata
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
- Composer 2.4 through latest, PHP 8.1 through 8.4 in CI
- CI integration recipes and a published JSON schema

## Phase 4 — global planning

- treat all findings jointly and search for the smallest command set that fixes everything
- explain why smaller changes were rejected

## Phase 5 — optional automation

- `--apply`, only after the planner has earned trust
