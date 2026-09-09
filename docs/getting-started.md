# Getting started

!!! warning "Pre-alpha"
    Nothing is published on Packagist yet. These instructions describe the intended
    installation path and the current development setup.

## Requirements

| Requirement | Minimum | Notes |
|---|---|---|
| PHP | 8.1 | 8.1 reached end of life in December 2025; the plugin still runs there but prints a warning |
| Composer | 2.4 | `composer audit` and transitive `--with` constraints appeared in 2.4; the suite runs against 2.4, 2.7, 2.8, 2.9 and the latest release in CI |
| Composer, full feature set | 2.7 | `--minimal-changes` (`-m`) appeared in 2.7.0 (2.9 extended it to full updates); on older versions the planner omits it and diffs may be larger |

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

Both forms also install `vendor/bin/composer-remediate` (or `~/.composer/vendor/bin/composer-remediate`
for a global install): a standalone entry point that runs the same commands with the analysed
project's plugins and scripts disabled from the first instruction, and that never includes a
project's autoloader. It needs a Composer phar on PATH (or `REMEDIATE_COMPOSER_BINARY`). Prefer it
when the project under analysis is not trusted; see
[Privacy and network behaviour](privacy-and-network.md#the-plugin-boundary).

## Usage

```bash
composer remediate                         # analyse composer.lock, print a plan, change nothing
composer-remediate                         # same, without activating the project's other plugins
composer remediate --output=report.html --output=report.json   # also write HTML and JSON reports (CI artifacts)
composer remediate --output=results.sarif --output=sbom.cdx.json   # SARIF for GitHub Code Scanning, CycloneDX SBOM with fixes
composer remediate --fail-on high                               # only high and critical findings affect the exit code
composer remediate --baseline=baseline.json --update-baseline   # accept today's findings; later runs fail only on new ones
composer remediate --min-release-age 7                          # never recommend a release younger than a week (or undated)
composer remediate --ignore-platform-req=php                    # validate as if PHP matched; the flag is repeated in the recommended command
composer remediate --solve-budget 80                            # allow more solver runs per finding on large graphs
composer remediate --format=json                                # machine-readable output on stdout
composer remediate --no-dev                # ignore findings in require-dev packages
composer remediate --ignore CVE-2024-50345 # leave an advisory out (also honours config.audit.ignore / config.policy)
composer remediate --database-location=advisories.sqlite         # advisories from a local database (see Advisory database)
composer remediate --offline --database-location=advisories.sqlite   # no network at all; needs a warm Composer cache
composer remediate -v                      # show every candidate command as it is tried
```

The plugin never writes to `composer.json`, `composer.lock` or `vendor/`. Every recommendation is a
plain `composer update` command you run yourself. The report ends with a summary: how many
advisories were found, and the single command that fixes all of them, or how many of them it fixes.

See [CI integration](ci-integration.md) for gating pipelines on these results.

Exit codes: `0` no vulnerabilities, `1` vulnerabilities with a verified remediation, `2` at least
one vulnerability without a verified remediation and every solve completed, `3` error (including a
solver error that left a finding's outcome unknown), `4` advisory data unavailable, `5` package
metadata could not be fetched (network).

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
