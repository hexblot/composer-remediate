# wallabag-symfony54-php74-guzzle5

**Fourth plain-Symfony instance: many plain updates and one dependency stuck on an EOL major.**

- Source: [wallabag/wallabag](https://github.com/wallabag/wallabag) at commit
  `91baac7e128140563cd21837edb3f2b996920574` (2024-10-31, "Bump doctrine/persistence from 3.3.3 to
  3.4.0"), a Symfony 5.4 application.
- Snapshot date (`--as-of`): 2025-01-15, after Symfony's November 2024 releases and TCPDF 6.8.0
  (2024-12-23).
- Platform: `config.platform.php` 7.4.29 and `require.php >=7.4` from the project. The project
  requires `ext-tidy`, which the build environment lacks; the fixture adds it to the platform (the
  repository copies the build machine's extension list, so a project-required extension that is not
  installed there has to be added by hand or nothing resolves).

## Findings

Sixteen advisories on eight packages, all direct requirements of the application.

| Package | Advisories | Command | Lands on |
|---|---|---|---|
| `symfony/http-foundation v5.4.45` | CVE-2024-50345 | `composer update symfony/http-foundation` | v5.4.48 |
| `symfony/http-client v5.4.41` | CVE-2024-50342 | `composer update symfony/http-client` | v5.4.47 |
| `symfony/security-http v5.4.41` | CVE-2024-51996 | `composer update symfony/security-http` | v5.4.47 |
| `symfony/validator v5.4.41` | CVE-2024-50343 | `composer update symfony/validator` | v5.4.48 |
| `symfony/process v5.4.45` (dev) | CVE-2024-51736 | `composer update symfony/process` | v5.4.47 |
| `twig/twig v3.11.1` | CVE-2024-51754, CVE-2024-51755 | `composer update twig/twig` | v3.11.3 (3.11 still supports PHP 7.2.5) |
| `tecnickcom/tcpdf 6.7.7` | CVE-2024-56519, -56521, -56522, -56527 | `composer update tecnickcom/tcpdf` | 6.8.0 |
| `guzzlehttp/guzzle 5.3.4` | CVE-2022-29248, -31042, -31043, -31090, -31091 | none | — |

The combined command fixes 11 of 16:

    composer update symfony/http-client symfony/http-foundation symfony/process symfony/security-http symfony/validator tecnickcom/tcpdf twig/twig

Guzzle has no fix within the project's constraints: the root requires `guzzlehttp/guzzle ^5.3.4`,
the fixes are in 6.5.8 and 7.4.5, and widening the root constraint does not help because
`php-http/guzzle5-adapter` (also a root requirement, abandoned on Packagist) requires the 5.x line.
The report flags the abandoned adapter. Moving off Guzzle 5 is a code change, which is what wallabag
eventually did; a remediation planner must say "no verified fix" here rather than invent one.

Built with `bin/build-fixture.php --as-of=2025-01-15`, then `ext-tidy` added to the platform.
