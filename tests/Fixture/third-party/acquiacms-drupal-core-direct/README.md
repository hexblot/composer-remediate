# acquiacms-drupal-core-direct

**Fifth Drupal instance: a monorepo distribution that requires core directly.**

- Source: [acquia/acquia-cms](https://github.com/acquia/acquia-cms), Acquia's Drupal distribution,
  at commit `3822bc67e3f49fddebbd7ee211c3a5ed5a550929` (2024-09-30, "ACMS-000: Pinned the
  default_content module and updated patch as per latest release"). The next lock changes are
  2024-10-10 and 2024-10-15 ("ACMS-4275: Updated minimum Drupal Core dependencies").
- Snapshot date (`--as-of`): 2024-11-25, after Symfony's November releases and Drupal 10.3.7.
- Platform: no `config.platform`; the fixture pins PHP 8.3.0. Repositories:
  `https://packages.drupal.org/8`, a `package` repository for a JavaScript library, `vcs`
  repositories for three drupal.org issue forks (dropped by the builder) and eighteen `path`
  repositories, one per `modules/acquia_cms_*` directory of the monorepo, each at `dev-develop`.
- `root_version`: `dev-develop`. The distribution's modules declare `conflict: acquia/acquia_cms
  <1.5.2` against the root package; in a git checkout Composer guesses the root version from the
  branch and the conflict never matches, whereas a copy without `.git` is "1.0.0+no-version-set" and
  every update fails. The fixture records what the checkout would have had.

## Findings

Unlike the Islandora, USAGov and Mass.gov fixtures there is no `drupal/core-recommended`; the root
requires `drupal/core` with a caret constraint and Drupal core requires its Symfony components with
carets too, so every fix is a plain update:

| Package | Advisory | Command | Lands on |
|---|---|---|---|
| `drupal/core 10.3.5` | CVE-2024-45440 | `composer update drupal/core` | 10.3.7 |
| `symfony/http-foundation v6.4.10` | CVE-2024-50345 | `composer update symfony/http-foundation` | v6.4.16 |
| `symfony/process v6.4.8` | CVE-2024-51736 | `composer update symfony/process` | v6.4.15 |
| `symfony/http-client v7.1.4` | CVE-2024-50342 | `composer update symfony/http-client` | v7.1.8 |
| `twig/twig v3.14.0` | CVE-2024-51754, CVE-2024-51755 | `composer update twig/twig` | v3.15.0 |

The combined command `composer update drupal/core symfony/http-client symfony/http-foundation
symfony/process twig/twig` fixes all six with five changes.

This fixture drove three builder changes. The `path` modules exist on drupal.org under the same names,
so the builder takes them from the lock file (with `extra.branch-alias`, which is how `dev-develop`
satisfies a sibling's `^3.1`), gives them a neutral dist (a `path` dist makes Composer refuse the locked
version in partial updates) and drops every other version of those names, because a path repository
takes precedence for the names it provides and Composer would never consider the drupal.org releases
in the real checkout. Without the last change every plan dragged eight modules from `dev-develop` to
release versions that the project could not install.

Built with `bin/build-fixture.php --as-of=2024-11-25 --platform-php=8.3.0`, then `root_version` added.
