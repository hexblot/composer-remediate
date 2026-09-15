# Composer Remediate

[![CI](https://github.com/hexblot/composer-remediate/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/hexblot/composer-remediate/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fhexblot%2Fcomposer-remediate%2Fbadges%2Fcoverage.json)](https://github.com/hexblot/composer-remediate/actions/workflows/ci.yml)
[![Architecture](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fhexblot%2Fcomposer-remediate%2Fbadges%2Farchitecture.json)](https://github.com/hexblot/composer-remediate/blob/main/deptrac.yaml)
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

Advisories come from the database this project publishes: a copy is kept at a fixed path under
Composer's cache directory, checked against the publisher on every run and verified by checksum, so
reports carry exploit data (FIRST EPSS, CISA KEV) and say where the advisory data has gaps. A plain run therefore
makes one small request to GitHub. `--no-database` asks your configured repositories instead, exactly
as `composer audit` does, and `--offline` uses the copy already on disk. See
[Advisory database](https://hexblot.github.io/composer-remediate/advisory-database/) and
[Privacy and network behaviour](https://hexblot.github.io/composer-remediate/privacy-and-network/).

Status: released as **0.x** on [Packagist](https://packagist.org/packages/hexblot/composer-remediate);
nothing is written to your project unless you ask for it with `--apply`. Phases 0 to 6 are
[delivered](https://hexblot.github.io/composer-remediate/delivered/): seventeen real historical
fixtures, a search for the one command that fixes every finding, and, since 0.8.0, `--apply` and a
GitHub Action that opens one batched pull request. What is still to come is on the
[roadmap](https://hexblot.github.io/composer-remediate/roadmap/). The adversarial adoption reviews
and their rechecks are answered in the [changelog](CHANGELOG.md), each finding with a test. Current
state, fixtures and evidence:
[hexblot.github.io/composer-remediate](https://hexblot.github.io/composer-remediate/).

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
`composer remediate`: it starts Composer with plugins and scripts disabled and never loads the
project's autoloader, so no code from the analysed project runs.

Ready-made GitHub Actions and GitLab CI jobs, and `jq` recipes for severity-based gates, are in the
[CI integration guide](https://hexblot.github.io/composer-remediate/ci-integration/). Every command
and option is listed in the [CLI reference](https://hexblot.github.io/composer-remediate/cli-reference/).

## Development

PHP and Composer run inside [ddev](https://ddev.com):

```bash
ddev start
ddev composer install
ddev composer --working-dir=tools/deptrac install   # once: the architecture rules need PHP 8.2+
ddev composer check      # phpstan + deptrac + phpunit
```

Changes under `src` go through a pull request, one branch per change; documentation and changelog
edits can go straight to `main`. While a pull request is a draft, CI runs a single job on PHP 8.4.
Marking it ready for review runs the tests against every supported version: PHP 8.1 to 8.5, and
Composer 2.4 to 2.9. The
[contributing guide](https://hexblot.github.io/composer-remediate/contributing/) has the rest.

Documentation is built with MkDocs (`pipx run --spec mkdocs --pip-args=pymdown-extensions mkdocs serve`) and published from `main` to GitHub
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
