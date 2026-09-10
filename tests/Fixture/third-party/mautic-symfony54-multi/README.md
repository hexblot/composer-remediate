# mautic-symfony54-multi

**Fifth plain-Symfony instance: a monorepo whose own package pins a dependency below the fix.**

- Source: [mautic/mautic](https://github.com/mautic/mautic) at commit
  `daad1994fff57d91414a4ee3a545810eab97154e` (2024-09-16, "Bump twig/twig from 3.8.0 to 3.14.0"), a
  Symfony 5.4 application. The repository is a monorepo: the root manifest requires the application
  itself as `mautic/core-lib ^5.0` from a `path` repository (`app/`), locked at `5.0.0-dev`.
- Snapshot date (`--as-of`): 2024-11-20, after Symfony's November releases, Twig 3.15.0 and
  PhpSpreadsheet 1.29.4 (2024-11-10).
- Platform: `config.platform.php` 8.1.0 from the project. The project requires `ext-imap`, which the
  build environment lacks; the fixture adds it to the platform.

## Findings

Sixteen advisories on seven packages, all transitive through `mautic/core-lib`.

| Package | Advisories | Command | Lands on |
|---|---|---|---|
| `symfony/http-foundation v5.4.35` | CVE-2024-50345 | `composer update symfony/http-foundation` | v5.4.48 |
| `symfony/http-client v5.4.35` | CVE-2024-50342 | `composer update symfony/http-client` | v5.4.47 |
| `symfony/security-http v5.4.35` | CVE-2024-51996 | `composer update symfony/security-http` | v5.4.47 |
| `symfony/validator v5.4.35` | CVE-2024-50343 | `composer update symfony/validator` | v5.4.47 |
| `symfony/process v5.4.40` | CVE-2024-51736 | `composer update symfony/process` | v5.4.47 |
| `twig/twig v3.14.0` | CVE-2024-51754, CVE-2024-51755 | `composer update twig/twig` | v3.15.0 |
| `phpoffice/phpspreadsheet 1.27.1` | nine advisories (CVE-2024-45046 to CVE-2024-48917) | none | — |

The combined command fixes 7 of 16:

    composer update symfony/http-client symfony/http-foundation symfony/process symfony/security-http symfony/validator twig/twig

PhpSpreadsheet has no fix within the project's constraints: `mautic/core-lib 5.0.0-dev` requires
`phpoffice/phpspreadsheet ^1.15 <1.28` and the fixes are in 1.29.4 and the 2.x/3.x lines. The
constraint lives in the monorepo's own `app/composer.json`, so the human fix is a code change to that
file (Mautic's 5.x branch later moved to `^1.29.4`); the planner reports "no verified fix" rather than
inventing an update the constraints forbid.

This fixture motivated a builder change: a locked package that comes from a `path` repository may
also exist on Packagist (`mautic/core-lib` does), and the public metadata for "5.0.0-dev" is not what
the project resolved against. The builder now takes such packages from the lock file.

Built with `bin/build-fixture.php --as-of=2024-11-20`, then `ext-imap` added to the platform.
