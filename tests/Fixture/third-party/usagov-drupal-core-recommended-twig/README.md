# usagov-drupal-core-recommended-twig

**Case 4, second Drupal instance: a meta-package pin that a patch release lifts.**

- Source: [usagov/usagov-2021](https://github.com/usagov/usagov-2021) at commit
  `e29cb9ca5c8707de08c041032a1486861a2a7814` (2024-08-19). The following commit,
  `62ccb7ec…` (2024-09-16), is titled "Upgrading Core-Recommended for a Twig upgrade".
- Snapshot date (`--as-of`): 2024-09-20.
- Platform: no `config.platform`; the fixture pins PHP 8.3.0. Repository: `https://packages.drupal.org/8`.

## Findings

`twig/twig v3.8.0` (CVE-2024-45411, fixed in 3.11.0 and 3.14.0) is pinned `~v3.8.0` by
`drupal/core-recommended 10.2.7` while `drupal/core 10.2.7` allows `^3.5.0`. `drupal/core-recommended
10.2.8` (2024-09-11) pins `~v3.14.0` and is the only newer 10.2 release at the snapshot date, so no
descent is needed.

Human choice: `composer update drupal/core-recommended -W`, which the project did. The planner
recommends `composer update drupal/core-recommended -W -m` (three changes: core, core-recommended,
twig 3.14.0). `drupal/core` and the meta-package are also affected by CVE-2024-45440, fixed only in
10.2.9 (2024-09-25), so no remediation is expected for those. `symfony/validator 6.4.8`
(CVE-2024-50343) is a plain partial update.

Built with `bin/build-fixture.php --as-of=2024-09-20 --platform-php=8.3.0`.
