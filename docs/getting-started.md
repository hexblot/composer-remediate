# Getting started

## Requirements

| Requirement | Minimum | Notes |
|---|---|---|
| PHP | 8.1 | 8.1 reached end of life in December 2025; the plugin still runs there but prints a warning |
| Composer | 2.4 | `composer audit` and transitive `--with` constraints appeared in 2.4; the suite runs against 2.4, 2.7, 2.8, 2.9 and the latest release in CI |
| Composer, full feature set | 2.7 | `--minimal-changes` (`-m`) appeared in 2.7.0 (2.9 extended it to full updates); on older versions the planner omits it and diffs may be larger |

## Installation

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
composer remediate --database-path=.cache/advisories.sqlite      # keep the advisory database in a path your CI caches (see Advisory database)
composer remediate --offline                                     # no network at all; needs a warm Composer cache and the database already at its path
composer remediate --no-database                                 # ask the configured repositories instead, as composer audit does
composer remediate -v                      # show every candidate command as it is tried
composer remediate --parallelize=4         # plan four packages at once, in worker processes
```

While it works it says so: how many packages it matched, how many need fixing, and which one it is
verifying, with a running count of solver runs. Those lines go to the error stream, so a report on
standard output stays a report, and `-v` adds every candidate command as it is tried. A large lock file
spends minutes in Composer's solver, and the progress is there so that is recognisable as work rather
than a hang. `-q` silences it.

Most of that time is Composer solving, and the packages are planned independently of each other, so
`--parallelize=4` plans four at a time and cuts a 45-second run on a 201-package lock file to about
15. Each worker runs its own solves, so allow a few hundred megabytes of memory for each. The result
is the same either way; only the wall clock changes. See
[how long a run takes](how-it-works.md#8a-how-long-a-run-takes-and-using-more-than-one-core).

The plugin writes nothing to `composer.json`, `composer.lock` or `vendor/`: every recommendation is a
plain `composer update` command you run yourself. `--apply` is the exception, and only on request. It
runs the command it just printed, copies the manifest and lock outside the project first, and then
plans again so the report is the state that run left behind. It refuses when the recommendation would
edit `composer.json` (`--apply-root-constraints` allows it), when those files changed while the plan
was being computed, or when they are already modified in a git checkout (`--apply-allow-dirty`).
`--apply-no-install` writes the lock and leaves `vendor/` alone, for a workflow that commits the lock. The report ends with a summary: how many
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
pipx run --spec mkdocs --pip-args=pymdown-extensions mkdocs serve
```
