# Test fixtures

The planner lives or dies on fixture quality. A fixture is a real historical Composer project state
with a known vulnerability and the remediation a competent human would choose.

## Why fixtures freeze package metadata

The "smallest upgrade" for a 2024 lock file changes every time upstream publishes a new release.
A fixture validated against live Packagist would drift within weeks. Every fixture therefore
carries its own static Composer repository, and packagist.org is disabled during the test.

## Layout

```text
tests/Fixture/<name>/
  composer.json        real project manifest
  composer.lock        real lock file
  repo/packages.json.gz  static Composer repository (gzipped): every package version the solver may consider
  advisories.json      advisory snapshot, in the Packagist security-advisories API shape
  expected.json        the remediation a human would choose, plus lock diff bounds
  README.md            provenance: source project, date, CVE, why this case matters
  reports/report.md    what `composer remediate` prints for this fixture (console output)
  reports/report.json  the same plan as JSON
  reports/report.html  the same plan as a self-contained HTML page
```

The `reports/` files are committed examples, regenerated with
`php bin/run-fixture.php <name> --write-reports`; they carry fixed metadata so the output is
reproducible.

The static repository is stored gzip-compressed to keep the checkout small; the harness inflates it
into a temporary directory. The harness also copies the fixture to a temporary directory and injects

```json
"repositories": [
  {"type": "composer", "url": "file:///…/repo"},
  {"packagist.org": false}
]
```

together with any `config.platform` from `expected.json`. The committed fixture is never modified.

## Building a fixture

```bash
ddev exec php bin/build-fixture.php --project=/path/to/project --name=<fixture-name>
```

The script copies `composer.json` and `composer.lock` to a scratch directory with an empty Composer
cache, runs one full dry-run update so Composer fetches every metadata file the solver could need,
and turns that cache into `repo/packages.json`. Versions older than the locked one are dropped and
each version is trimmed to the fields the solver reads (`require`, `replace`, `provide`, `conflict`,
`dist`), which keeps Drupal-sized fixtures in the low megabytes. It then fetches advisories for every
package name in the repository from Packagist, records the build environment's PHP and extension
versions as `platform`, and writes an `expected.json` skeleton listing the findings it detected.

Finish the fixture by hand: describe the case, record provenance in `README.md`, and fill in the
command a competent human would run. The harness compares the planner's recommendation against it. Exact command strings are asserted
only on Composer releases with `--minimal-changes` (2.9+); on older releases the planner legitimately
drops `-m` (and often the `--with` guard) because they produce the same lock there, and the same
commands move many more packages (58 instead of 3 in one Laravel case), so only the outcome and the
target version are checked.

A synthetic fixture (`synthetic-transitive-parent`) exists purely to exercise the harness; every
other fixture must be a real historical project state.

## Historical snapshots

Real projects are captured with `--as-of=<date>`: package versions released and advisories reported
after that date are dropped, so the fixture reproduces the situation a developer faced at the time
rather than today's. Without it, later advisories would turn a clean "upgrade the parent" case into
"no fix" (Shopware 6.4's Twig pin is one example).

## The Phase 0 set

| # | Fixture | Case | Planner's recommendation |
|---|---|---|---|
| 1 | `bookstack-guzzle-stale-lock` (BookStack, 2022-05) | Direct `guzzlehttp/guzzle 7.4.2`, root `^7.4` permits 7.4.5 | `composer update guzzlehttp/guzzle -w -m` (the plain update stops at 7.4.4 because 7.4.5 needs a newer psr7) |
| 2 | `koel-symfony-parent-permits` (koel, 2024-10) | Transitive `symfony/http-foundation` and `symfony/process 6.4.4` via `laravel/framework ^6.4` | `composer update symfony/http-foundation`, `composer update symfony/process` |
| 3 | `shopware-twig-parent-pin` (Shopware 6.4.15.1, 2022-09) | `twig/twig 3.3.10` pinned `~3.3.8` by shopware/core; 6.4.15.2 lifts the pin; siblings pin core exactly | `composer update shopware/storefront:6.4.15.2 shopware/recovery shopware/elasticsearch shopware/administration -W -m` |
| 4 | `islandora-drupal-twig-meta-package` (Islandora starter site, 2024-08) | `twig/twig 3.10.3` pinned `~v3.10.2` by `drupal/core-recommended 10.3.1`; 10.3.4 is the first to allow the fix | `composer update drupal/core-recommended:10.3.4 -W -m` |
| 5 | `bookstack-symfony-php80-no-fix` (BookStack, 2023-12) | `symfony/http-foundation 6.0.20` under `config.platform.php` 8.0.2; every fix needs PHP 8.1 | No verified remediation, with the PHP requirement shown as the blocker |

## The Phase 3 corpus

| Fixture | Ecosystem | What it exercises |
|---|---|---|
| `bookstack-phpseclib-knpsnappy` (BookStack, 2023-02) | Laravel | Direct and transitive fixes in one lock; combined command |
| `bookstack-socialite-phpjwt-parent-minor` (BookStack, 2024-09, snapshot 2026-01) | Laravel | `firebase/php-jwt` pinned `^6.4` by `laravel/socialite`; descent pins socialite 5.24.1; twelve findings, one combined command |
| `pixelfed-laravel11-symfony` (Pixelfed, 2024-10) | Laravel 11 | Symfony 7.1 components the parent already permits |
| `usagov-drupal-core-recommended-twig` (USAGov, 2024-08) | Drupal 10.2 | Second `core-recommended` pin; the project's own next commit made the same upgrade |
| `invoiceninja-phpjwt-two-level` (Invoice Ninja, 2022-04) | Laravel | Two-level chain: `google/apiclient` and the non-root `google/auth` both pin php-jwt; `-W` moves both |
| `kimai1-symfony44-artifact-repo` (Kimai 1.x, 2023-02) | Symfony 4.4, PHP 7.3 | Mixed outcomes: 4.4 components jump to 5.4 patch releases, direct PhpSpreadsheet unfixable on PHP 7; `artifact` repository |
| `shopware-6420-twig-no-fix` (Shopware 6.4.20.2, 2023-05) | Symfony / Shopware | Constraint-bound "no fix": last 6.4 release pins twig, 6.5 needs PHP 8.1; 7 of 26 findings fixable |

Each fixture directory has a `README.md` with provenance and the reasoning behind the expected
command, and a `reports/` directory with the stored console, JSON and HTML output.
