# Getting started

!!! warning "Pre-alpha"
    Nothing is published on Packagist yet. These instructions describe the intended
    installation path and the current development setup.

## Requirements

| Requirement | Minimum | Notes |
|---|---|---|
| PHP | 8.1 | 8.1 reached end of life in December 2025; the plugin still runs there but prints a warning |
| Composer | 2.4 | `composer audit` and transitive `--with` constraints appeared in 2.4 |
| Composer, full feature set | 2.9 | `--minimal-changes` (`-m`) appeared in 2.9; on older versions the planner omits it and warns that diffs may be larger |

## Installation (intended)

Globally, so it is available in every project without touching their `composer.json`:

```bash
composer global config allow-plugins.hexblot/composer-remediate true
composer global require hexblot/composer-remediate
```

Or per project as a dev dependency:

```bash
composer config allow-plugins.hexblot/composer-remediate true
composer require --dev hexblot/composer-remediate
```

## Usage

```bash
composer remediate                         # analyse composer.lock, print a plan, change nothing
composer remediate --output=report.html --output=report.json   # also write HTML and JSON reports (CI artifacts)
composer remediate --format=json                                # machine-readable output on stdout
composer remediate --no-dev                # ignore findings in require-dev packages
composer remediate --ignore CVE-2024-50345 # leave an advisory out (also honours config.audit.ignore / config.policy)
composer remediate --offline --advisories-file=advisories.json   # no network at all; needs a warm Composer cache
composer remediate -v                      # show every candidate command as it is tried
```

The plugin never writes to `composer.json`, `composer.lock` or `vendor/`. Every recommendation is a
plain `composer update` command you run yourself. The report ends with a summary: how many
advisories were found, and the single command that fixes all of them, or how many of them it fixes.

See [CI integration](ci-integration.md) for gating pipelines on these results.

Exit codes: `0` no vulnerabilities, `1` vulnerabilities with a verified remediation, `2` at least
one vulnerability without a verified remediation, `3` error, `4` advisory data unavailable,
`5` package metadata could not be fetched (network).

## Developing the plugin

The repository ships a [ddev](https://ddev.com) configuration; no local PHP is required.

```bash
ddev start
ddev composer install
ddev composer check          # phpstan level 8 + phpunit
ddev composer test:fixtures  # the historical fixture suite only
```

Documentation:

```bash
pipx run mkdocs serve
```
