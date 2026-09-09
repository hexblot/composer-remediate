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
  repo/packages.json   static Composer repository: every package version the solver may consider
  advisories.json      advisory snapshot, in the Packagist security-advisories API shape
  expected.json        the remediation a human would choose, plus lock diff bounds
  README.md            provenance: source project, date, CVE, why this case matters
```

The test harness copies the fixture to a temporary directory and injects

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
command a competent human would run. The harness compares the planner's recommendation against it.

A synthetic fixture (`synthetic-transitive-parent`) exists purely to exercise the harness; every
other fixture must be a real historical project state.

## The Phase 0 set

| # | Case | Expected human choice |
|---|---|---|
| 1 | Direct dependency, fixed version already permitted | `composer update <pkg>` |
| 2 | Transitive, fixed version permitted by parent constraint | `composer update <pkg> -w` |
| 3 | Transitive, parent must move | `composer update <parent> -W -m` |
| 4 | Deep transitive, framework or root package upgrade required | `composer update <framework> -W -m` |
| 5 | No valid remediation under current platform constraints | "No verified remediation found", with the blocker explained |

Phase 3 grows this into a corpus of Drupal, Symfony and Laravel cases.
