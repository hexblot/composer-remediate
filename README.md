# Composer Remediate

**From vulnerable dependency to verified Composer fix.**

`composer audit` tells you which packages are vulnerable. `composer remediate` tells you the
smallest `composer update` command that removes the vulnerability, and proves it with
Composer's own dependency solver before recommending it.

```text
$ composer remediate

CVE-2026-XXXXX  symfony/http-foundation 6.4.21
  Introduced by
    root
    └── drupal/core-recommended 11.4.2
        └── symfony/http-foundation 6.4.21
  Recommended remediation
    drupal/core-recommended 11.4.2 -> 11.4.3   (3 packages updated, 0 added, 0 removed)
  Composer validation
    PASS
  Recommended command
    composer update drupal/core-recommended -W -m
```

Status: **pre-alpha**. Phase 0 is complete: the planner reproduces the remediation a competent human
would choose on five real historical projects (BookStack, koel, Shopware, a Drupal site, and a
platform-bound "no fix" case). See the [documentation](docs/index.md) and the
[roadmap](docs/roadmap.md).

## Development

PHP and Composer run inside [ddev](https://ddev.com):

```bash
ddev start
ddev composer install
ddev composer check      # phpstan + phpunit
```

Documentation is built with MkDocs (`pipx run mkdocs serve`).

## Acknowledgement

This project was inspired by [CVE Lite CLI](https://github.com/OWASP/cve-lite-cli), an OWASP project
that gives JavaScript and TypeScript developers local-first, lockfile-based vulnerability scanning
with copy-and-run fix commands and parent-aware guidance for transitive dependencies. Composer
Remediate brings the same idea to the PHP ecosystem, with the addition that every recommendation is
proven by Composer's own dependency solver before it is shown.

## License

MIT. See [LICENSE](LICENSE).
