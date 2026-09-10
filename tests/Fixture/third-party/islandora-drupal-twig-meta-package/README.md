# islandora-drupal-twig-meta-package

**Case 4: deep transitive dependency that requires a framework meta-package upgrade.**

- Source: [Islandora/islandora-starter-site](https://github.com/Islandora/islandora-starter-site) at
  commit `d8ec76241e2a7c029521d039d158e42ef62d2dbc` (2024-08-21, "Drush 13, second attempt").
- Snapshot date (`--as-of`): 2024-09-20.
- Platform: no `config.platform` in the project; the fixture pins PHP 8.3.0.
- Repositories: `https://packages.drupal.org/8` plus an inline `package` repository for
  `library/pdf.js`, which the builder copies from the lock file.

## Findings

`twig/twig v3.10.3` is affected by CVE-2024-45411 (sandbox bypass), fixed in 3.11.0 and 3.14.0.
Root requires `drupal/core-recommended ^10.1`, locked at 10.3.1, which pins `twig/twig ~v3.10.2` and
so excludes every fix, while `drupal/core 10.3.1` allows `^3.9.3`. `drupal/core-recommended 10.3.4`
(2024-09-11) is the first release pinning `~v3.14.0`.

Human choice: Drupal's documented `composer update drupal/core-recommended -W`, which as of the
snapshot date resolves to 10.3.5. The planner recommends `composer update drupal/core-recommended:10.3.4 -W -m`,
the lowest release that admits the fix (three changes: core, core-recommended, twig).

`drupal/core 10.3.1` and the meta-package are also affected by CVE-2024-45440 (SA-CORE-2024-003);
the fixed release 10.3.6 does not exist at the snapshot date, so no remediation is expected.
`symfony/validator v6.4.9` (CVE-2024-50343) is fixed by a plain partial update.

Built with `bin/build-fixture.php --as-of=2024-09-20 --platform-php=8.3.0`.
