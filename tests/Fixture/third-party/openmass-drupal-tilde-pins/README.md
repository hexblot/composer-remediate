# openmass-drupal-tilde-pins

**Third Drupal instance: a meta-package whose tilde pins let the fixes through.**

- Source: [massgov/openmass](https://github.com/massgov/openmass) (Mass.gov, the Commonwealth of
  Massachusetts' site) at commit `aecbd0717c32ccc9e2fcbdefa8341a2034e09701` (2024-10-25, "Upgrade
  Drupal Test traits to 2.4. Also upgrade_status module, drush").
- Snapshot date (`--as-of`): 2024-11-25, after Symfony's 6 November releases (6.4.14, 6.4.15) and
  Twig's 3.14.1 / 3.14.2.
- Platform: `config.platform.php` 8.3 from the project, recorded as 8.3.0. Repository:
  `https://packages.drupal.org/8`, plus two `package` repositories the project declares.

## Findings

Drupal 10.3's `drupal/core-recommended` pins its dependencies with tilde constraints
(`symfony/http-foundation ~v6.4.7`, `symfony/process ~v6.4.8`, `twig/twig ~v3.14.0`), unlike the
exact pins of the 10.2 fixtures (Islandora, USAGov). Every fix therefore fits inside the pin and the
planner recommends a plain update for each package:

| Package | Advisory | Command | Lands on |
|---|---|---|---|
| `symfony/http-foundation v6.4.12` | CVE-2024-50345 | `composer update symfony/http-foundation` | v6.4.14 |
| `symfony/process v6.4.12` | CVE-2024-51736 | `composer update symfony/process` | v6.4.15 |
| `symfony/http-client v6.4.10` (direct) | CVE-2024-50342 | `composer update symfony/http-client` | v6.4.15 |
| `twig/twig v3.14.0` | CVE-2024-51754, CVE-2024-51755 | `composer update twig/twig` | v3.14.2 |

The combined command `composer update symfony/http-client symfony/http-foundation symfony/process
twig/twig` fixes all five advisories with four changes. `symfony/http-client` is also reached through
`behat/mink-goutte-driver` and `fabpot/goutte`, both abandoned on Packagist (replacements
`behat/mink-browserkit-driver` and `symfony/browser-kit`); the report names them.

Drupal core's own November 2024 advisories (SA-CORE-2024-003 to -008, released 2024-11-20) are not
in this snapshot: the Packagist feed carries no drupal/core record with a report date before the
snapshot, so `drupal/core 10.2.6`-style findings appear in the Open Social fixture (August advisory)
rather than here.

Built with `bin/build-fixture.php --as-of=2024-11-25 --platform-php=8.3.0`.
