# Composer Remediate

**From vulnerable dependency to verified Composer fix.**

`composer audit` answers *what is vulnerable?* Composer Remediate answers the next question:

> What exactly should I change to remove the vulnerability with the smallest safe impact on the
> dependency graph, and can Composer prove that the change works?

It is a Composer plugin. Given a project's `composer.json` and `composer.lock` it:

1. finds vulnerable direct and transitive packages from advisory data;
2. traces each one back to the nearest dependency the project actually controls;
3. generates candidate `composer update` commands, from least to most invasive;
4. runs each candidate through Composer's own dependency solver in dry-run mode;
5. keeps only the candidates whose resulting lock file no longer contains the vulnerability;
6. ranks the survivors by blast radius and prints the winning command.

```text
$ composer remediate

CVE-2026-XXXXX  symfony/http-foundation 6.4.21
  Introduced by
    root
    └── drupal/core-recommended 11.4.2
        └── symfony/http-foundation 6.4.21
  Analysis
    Transitive dependency. The parent constraint does not permit a fixed release.
  Recommended remediation
    drupal/core-recommended 11.4.2 -> 11.4.3
  Composer validation
    PASS   3 packages updated, 0 added, 0 removed, 0 root constraints changed
  Recommended command
    composer update drupal/core-recommended -W -m
```

## What it is not

- Not a vulnerability scanner. Detection is an input; see [Privacy and network behaviour](privacy-and-network.md) for where advisory data comes from.
- Not a replacement for `composer audit`. It starts where `composer audit` stops.
- Not static analysis, reachability analysis, or SBOM tooling.
- Not automatic. The first releases recommend; they never modify your project.

## Status

Released as 0.x on [Packagist](https://packagist.org/packages/hexblot/composer-remediate); the
current version is listed in the [changelog](https://github.com/hexblot/composer-remediate/blob/main/CHANGELOG.md).
Of the [roadmap](roadmap.md), Phases 0 to 2 are complete: the planner reproduces the remediation a
competent human would choose on every one of twelve real historical projects, and the advisory
database can be built locally or shared. Phase 3 (a larger Drupal and Symfony corpus) is in
progress, and most Phase 6 integrations (SARIF, GitLab and CycloneDX reports, severity gate,
baselines, release cooldown) have landed. An external architecture review of 0.3.0 found twenty
defects, nine of them able to turn a tool failure or a policy exception into a clean result; 0.4.0
answers that review and the reviewer's recheck, with a test behind each change, and 0.4.1 puts the
command layer, the advisory feed readers and both advisory adapters under test (171 tests, 94% of
lines); 0.4.2 answers a third recheck (three findings on the audit fallback's plugin boundary, OSV
limit semantics and coverage-gap bookkeeping), which the reviewer then confirmed closed. Global planning
(Phase 4) and `--apply` (Phase 5) are still ahead, so every release so far recommends and never
modifies your project.

## Start here

- [Getting started](getting-started.md): install as a plugin, run it, the standalone binary.
- [Reading the report](reading-the-report.md): what each section and term means, exit codes, the
  other output formats.
- [CI integration](ci-integration.md): gate policies, GitHub Actions and GitLab CI jobs, SARIF and
  SBOM output, baselines.
- [How it works](how-it-works.md): candidates, validation, ranking, budgets.
- [Advisory database](advisory-database.md): build advisories into a local SQLite file, share it,
  run offline, coverage gaps.
- [Privacy and network behaviour](privacy-and-network.md): what leaves the machine, the plugin
  boundary, `--offline`.
- [CLI reference](cli-reference.md): every command and option.

## Compare and validate

- [Case studies](case-studies.md): twelve real historical projects (BookStack, koel, Pixelfed,
  Invoice Ninja, Kimai, Shopware, Drupal) with the human's choice, the planner's recommendation and
  the stored reports.
- [Comparison with other tools](comparison.md): `composer audit`, Composer 2.10 blocking, Dependabot
  and Renovate, Snyk, OSV-Scanner, CVE Lite CLI, and where this tool adds nothing.
- [Design decisions](design-decisions.md) and the [roadmap](roadmap.md).

## Inspiration

[CVE Lite CLI](https://github.com/OWASP/cve-lite-cli), an OWASP project, does this for JavaScript and
TypeScript: local-first scanning of lockfiles with copy-and-run fix commands and parent-aware
guidance for transitive dependencies. Composer Remediate applies the same idea to PHP and adds solver
verification of every recommendation.
