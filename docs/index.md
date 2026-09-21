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
Phases 0 to 6 of the plan are [delivered](delivered.md): the planner reproduces the remediation a
competent human would choose on every one of seventeen real historical projects (Laravel, Symfony,
Drupal, Shopware, two monorepos and a distribution), searches for the single command that fixes every
finding and explains that search, and the advisory database is kept current from the one this project
publishes, or built locally and shared. The integrations (SARIF, GitLab and CycloneDX reports, severity gate,
baselines, release cooldown, EPSS and CISA KEV urgency ordering, abandoned-package flagging) have
landed, as have `--apply` and the batched pull request. What is still to come is on the
[roadmap](roadmap.md). An adversarial adoption review of 0.3.0 (another AI model working from the published
repository, reproducing each finding) found twenty
defects, nine of them able to turn a tool failure or a policy exception into a clean result; 0.4.0
answers that review and the reviewer's recheck, with a test behind each change, and 0.4.1 puts the
command layer, the advisory feed readers and both advisory adapters under test (171 tests, 94% of
lines); 0.4.2 answers a third recheck (three findings on the audit fallback's plugin boundary, OSV
limit semantics and coverage-gap bookkeeping), which the reviewer then confirmed closed; 0.5.0 adds
EPSS and CISA KEV urgency ordering, abandoned-package flagging and the completed fixture corpus; 0.6.0
adds global planning (Phase 4: one command for every finding, with the search explained), answers an
Aikido code scan by failing closed on unverified data, and adds Deptrac layer rules; 0.6.1 repairs the
generated case-studies page that failed 0.6.0's CI run and adds the architecture badge; 0.7.0 makes the
published advisory database the default source, kept current at a fixed path and confirmed by content,
and answers a second adversarial adoption review and its four rechecks (twenty-two findings on
filesystem safety, advisory completeness, CI decisions and what the analysed project's `composer.json`
is allowed to decide). `--apply`
(Phase 5) is complete in 0.8.0: the default is still to recommend and write nothing, `--apply` runs the
command it printed and then reports the state that run left behind, and the shipped GitHub Action opens
one pull request carrying every fix it could verify. That release also answers a fresh adversarial
adoption assessment of those features, nine findings with a test each. 0.8.1 adds `--parallelize`:
almost all of a run is Composer solving, and the packages are planned independently of one another,
so planning four at once takes a 45-second run on a 201-package lock file down to about 15, with the
same report at the end. 0.9.0 is an assurance release, answering a seventh adversarial review and four
rechecks of the answers to it, all on one theme: advisory data that could be read only in part was
reading as complete coverage, so a lock could be called clean against records the build had failed to
interpret. Every reader now refuses rather than skips, a contract suite states that guarantee over all
three of them, the suite runs on Windows and macOS, and a compatibility policy says what a version
number covers. The rule that a package's identity has to be readable before a record is filed under it
found a malformed record in the live GitHub Advisory Database, whose correction is filed upstream.
0.9.1 answers three requests about the report itself: why a widening is the only route left when a
branch has published no fix at all, the `conflict` entry that makes a one-command `--with` constraint
permanent, and what an update changes about what a package is *allowed* to do — a type becoming
`composer-plugin`, `autoload.files` or binaries appearing, the source or dist host moving. All three
are in the text and HTML reports; the JSON document is unchanged, because its shape is a covered
surface and any addition to it increases `schema_version`.

## Start here

- [Getting started](getting-started.md): install as a plugin, run it, the standalone binary.
- [Reading the report](reading-the-report.md): what each section and term means, exit codes, the
  other output formats.
- [CI integration](ci-integration.md): gate policies, GitHub Actions and GitLab CI jobs, SARIF and
  SBOM output, baselines.
- [How it works](how-it-works.md): candidates, validation, ranking, budgets.
- [Advisory database](advisory-database.md): where advisories come from by default and how a copy is
  kept current, building one yourself, private advisories, running offline, coverage gaps.
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
guidance for transitive dependencies. Composer Remediate was inspired by that approach, applying it
to Composer's dependency model and using Composer's own solver to prove each recommendation before it
is shown.

## Sponsor

Development of Composer Remediate is sponsored by [Lambda Twelve](https://www.lambda-twelve.com),
which funds the maintainer's time and the tooling costs behind the work, including the AI assistance
used during development. The project takes no money from users and has no commercial tier.
