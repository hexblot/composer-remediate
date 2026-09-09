# kimai1-symfony44-artifact-repo

**A legacy Symfony 4.4 application on PHP 7.3, with mixed outcomes and an `artifact` repository.**

- Source: [kimai/kimai](https://github.com/kimai/kimai) branch `1.x` at commit
  `2d809b4f06d5083a66bb618d9e2adabe9b152e15` (2023-02-17).
- Snapshot date (`--as-of`): 2024-11-10.
- Platform: `config.platform.php` 7.3 (from the project). The project declares an `artifact`
  repository (`var/packages/`); the builder drops it and copies its locked packages from the lock file.

## Findings

Fourteen advisories on six packages. Fixable: `symfony/http-foundation 4.4.49` and `symfony/process
4.4.44` move to 5.4.x because `symfony/framework-bundle 4.4` requires them with `^4.4|^5.0` and
5.4 still supports PHP 7.2.5; `symfony/twig-bridge` moves to 4.4.51; `twig/twig 3.5.1` moves to 3.11.3
with its dependencies. Not fixable: `phpoffice/phpspreadsheet 1.25.2` (direct) needs a release that
requires PHP 8, and `symfony/validator 4.4.48` (direct, `^4.4`) has its fix only in 5.4/6.4/7.1.

The summary's combined command fixes 6 of 14 findings:

    composer update symfony/http-foundation symfony/twig-bridge twig/twig symfony/process -w -m --with 'twig/twig:>=3.11.2,<3.12.0 || >=3.14.1'

Built with `bin/build-fixture.php --as-of=2024-11-10`.
