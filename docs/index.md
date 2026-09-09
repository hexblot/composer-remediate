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

Pre-alpha. Phase 0 of the [roadmap](roadmap.md) is in progress: the goal is to reproduce the
remediation a competent human would choose for at least four of five real historical cases.

## Inspiration

[CVE Lite CLI](https://github.com/OWASP/cve-lite-cli), an OWASP project, does this for JavaScript and
TypeScript: local-first scanning of lockfiles with copy-and-run fix commands and parent-aware
guidance for transitive dependencies. Composer Remediate applies the same idea to PHP and adds solver
verification of every recommendation.

## Where to go next

- [Getting started](getting-started.md)
- [How it works](how-it-works.md)
- [CI integration](ci-integration.md)
- [Design decisions](design-decisions.md)
