# opensocial-drupal-distribution-pins

**Fourth Drupal instance: a distribution package pins core, and the pin permits the patch.**

- Source: [goalgorilla/social_template](https://github.com/goalgorilla/social_template), the
  Composer project template for the Open Social distribution, at commit
  `b5b634ccaf48347c7e46143b1a248dea4555e987` (2024-05-21, "updated to 12.4.2").
- Snapshot date (`--as-of`): 2024-10-15, one week after Drupal 10.2.9 (2024-10-08). The same
  project snapshotted at 2024-10-01 has no fix for core at all: 10.2.9 did not exist yet.
- Platform: no `config.platform`; the fixture pins PHP 8.2.0 because the lock holds `lcobucci/clock
  3.0.0`, which requires `~8.1.0 || ~8.2.0`. Repositories: `https://packages.drupal.org/8` and
  `https://asset-packagist.org`.

## Findings

The root requires only `goalgorilla/open_social ~12.4.0` (plus monolog); everything else, Drupal
core included, arrives through the distribution, which requires `drupal/core ~10.2.5`.

| Package | Advisory | Command | Lands on |
|---|---|---|---|
| `drupal/core 10.2.6` | CVE-2024-45440 | `composer update drupal/core -w -m` | 10.2.9 (plus twig 3.14.0 and symfony/polyfill-php81) |
| `twig/twig v3.10.3` | CVE-2024-45411 | `composer update twig/twig` | v3.14.0 (adds symfony/polyfill-php81) |
| `symfony/validator v6.4.7` | CVE-2024-50343 | `composer update symfony/validator` | v6.4.12 |

`composer update drupal/core` alone stops at 10.2.7 (still affected): 10.2.9 requires a newer Twig,
so `-w` is needed and the planner adds it. Human choice: Drupal's standard
`composer update drupal/core --with-dependencies`, which is what the planner recommends. The combined
command `composer update drupal/core symfony/validator -w -m` fixes all three: the merged winners
also named `twig/twig`, but the global search found the `drupal/core` update carries it and dropped it.

This fixture also motivated a builder change: Twig 3.11+ requires `symfony/polyfill-php81`, a package
the locked graph never contained, so a frozen repository built only from what Composer loaded for
the locked graph could not express the fix. The builder now fetches the requirement closure of every
version it keeps.

Built with `bin/build-fixture.php --as-of=2024-10-15 --platform-php=8.2.0`.
