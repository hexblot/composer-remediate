# Composer Remediate

[![CI](https://github.com/hexblot/composer-remediate/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/hexblot/composer-remediate/actions/workflows/ci.yml)
[![Docs](https://github.com/hexblot/composer-remediate/actions/workflows/docs.yml/badge.svg?branch=main)](https://hexblot.github.io/composer-remediate/)
[![Advisory database](https://github.com/hexblot/composer-remediate/actions/workflows/advisory-db.yml/badge.svg)](https://github.com/hexblot/composer-remediate/releases/tag/advisory-db-latest)
[![Latest release](https://img.shields.io/github/v/release/hexblot/composer-remediate?filter=v*&display_name=tag&label=release)](https://github.com/hexblot/composer-remediate/releases)
[![PHP](https://img.shields.io/packagist/dependency-v/hexblot/composer-remediate/php)](composer.json)

**From vulnerable dependency to verified Composer fix.**

`composer audit` tells you which packages are vulnerable. `composer remediate` searches for the
least invasive `composer update` command that removes the vulnerability, proves each candidate with
Composer's own dependency solver, and recommends the best verified one. The search is bounded and
ranked, not exhaustive: the report says when a limit was hit.

```text
$ composer remediate

CVE-2026-XXXXX  symfony/http-foundation 6.4.21
  Introduced by
    root
    └── drupal/core-recommended 11.4.2
        └── symfony/http-foundation 6.4.21
  Recommended remediation
    drupal/core-recommended 11.4.2 -> 11.4.3   (3 packages updated, 0 added, 0 removed)
  Composer validation
    PASS
  Recommended command
    composer update drupal/core-recommended -W -m
```

Status: released as **0.x** on [Packagist](https://packagist.org/packages/hexblot/composer-remediate);
the current version is in the [changelog](CHANGELOG.md). Phases 0 to 2 of the
[roadmap](https://hexblot.github.io/composer-remediate/roadmap/) are complete: the planner reproduces
the remediation a competent human would choose on every one of twelve real historical projects
(BookStack, koel, Pixelfed, Invoice Ninja, Kimai, Shopware, two Drupal sites, and platform- and
constraint-bound "no fix" cases), and the advisory database can be built locally or shared. Phase 3
(a larger Drupal and Symfony corpus) is in progress; most Phase 6 integrations (SARIF, GitLab and
CycloneDX reports, severity gate, baselines, release cooldown) have landed. Two rounds of external
architecture review are answered in the changelog, each finding with a test. Global planning
(Phase 4) and `--apply` (Phase 5) are still ahead, so every release recommends and never modifies
your project. Full documentation: [hexblot.github.io/composer-remediate](https://hexblot.github.io/composer-remediate/).

## Using it as a CI gate

The command exits `0` when the lock is clean, `1` when vulnerabilities have a verified fix, `2` when
at least one has no verified fix yet, and `3` to `5` for tool, advisory-data or network errors. A
typical gate fails on `1` (apply the recommended command), warns on `2`, and keeps the HTML or JSON
report as an artifact:

```bash
composer global config --no-plugins allow-plugins.hexblot/composer-remediate true
composer global require hexblot/composer-remediate
composer remediate --no-dev --output=remediation-report.html --output=remediation-report.json
```

Add `--fail-on high` to let low and medium findings pass, `--output=results.sarif` for GitHub Code
Scanning annotations, or `--output=sbom.cdx.json` for a CycloneDX SBOM with the fixes attached.

For a project you do not trust, run the shipped `composer-remediate` binary instead of
`composer remediate`: it boots Composer with plugins and scripts disabled from the first
instruction and never includes a project's autoloader, so nothing from the analysed project executes
during planning.

Ready-made GitHub Actions and GitLab CI jobs, and `jq` recipes for severity-based gates, are in the
[CI integration guide](https://hexblot.github.io/composer-remediate/ci-integration/). Every command
and option is listed in the [CLI reference](https://hexblot.github.io/composer-remediate/cli-reference/).

## Development

PHP and Composer run inside [ddev](https://ddev.com):

```bash
ddev start
ddev composer install
ddev composer check      # phpstan + phpunit
```

Documentation is built with MkDocs (`pipx run mkdocs serve`) and published from `main` to GitHub
Pages. The CLI reference and case-studies pages are generated (`ddev composer cli-reference`,
`ddev composer case-studies`) and checked in CI.

## Acknowledgement

This project was inspired by [CVE Lite CLI](https://github.com/OWASP/cve-lite-cli), an OWASP project
that gives JavaScript and TypeScript developers local-first, lockfile-based vulnerability scanning
with copy-and-run fix commands and parent-aware guidance for transitive dependencies. Composer
Remediate brings the same idea to the PHP ecosystem, with the addition that every recommendation is
proven by Composer's own dependency solver before it is shown.

## License

MIT. See [LICENSE](LICENSE).
