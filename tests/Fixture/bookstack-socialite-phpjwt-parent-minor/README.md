# bookstack-socialite-phpjwt-parent-minor

**Case 3 in a modern Laravel lock: the parent excludes the fix and a same-major parent release lifts it.**

- Source: [BookStackApp/BookStack](https://github.com/BookStackApp/BookStack) at commit
  `abda9bc00a6d64a352ff8896887d95b1768c6961` (2024-09-27).
- Snapshot date (`--as-of`): 2026-01-10, chosen so that both the fixed `firebase/php-jwt 7.0.0`
  (2025-12-15) and `laravel/socialite 5.24.1` (2026-01-01) exist.
- Platform: `config.platform.php` 8.1.0 (from the project).

## Findings

`firebase/php-jwt v6.10.1` is affected by CVE-2025-45769 (weak encryption), fixed in 7.0.0. It is
required by `laravel/socialite v5.16.0` with `^6.4`; every socialite release up to 5.24.0 keeps that
constraint and 5.24.1 widens it to `^6.4|^7.0`. Root requires `laravel/socialite ^5.10`, so the fix
is reachable without touching composer.json.

Human choice: `composer update laravel/socialite firebase/php-jwt`. The planner recommends
`composer update laravel/socialite:v5.24.1 -W -m --with 'firebase/php-jwt:>=7.0.0'`: three
changes (php-jwt 7.0.2, socialite 5.24.1, league/oauth1-client). The `--with` stays because with
`-m` alone Composer would keep php-jwt on 6.x, which `^6.4|^7.0` still allows.

Eleven further advisories in the same lock (laravel/framework, symfony/http-foundation and process,
nesbot/carbon, league/commonmark, aws/aws-sdk-php, robrichards/xmlseclibs via onelogin/php-saml) are
all fixable by partial updates, so the summary offers one combined command:

    composer update aws/aws-sdk-php laravel/socialite:v5.24.1 laravel/framework league/commonmark nesbot/carbon onelogin/php-saml robrichards/xmlseclibs symfony/http-foundation symfony/process -W -m --with 'firebase/php-jwt:>=7.0.0'

Built with `bin/build-fixture.php --as-of=2026-01-10`.
