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

Status: **pre-alpha, Phase 0**. See the [documentation](docs/index.md) and the
[roadmap](docs/roadmap.md).

## Development

PHP and Composer run inside [ddev](https://ddev.com):

```bash
ddev start
ddev composer install
ddev composer check      # phpstan + phpunit
```

Documentation is built with MkDocs (`pipx run --spec mkdocs-material mkdocs serve`).

## License

MIT. See [LICENSE](LICENSE).
