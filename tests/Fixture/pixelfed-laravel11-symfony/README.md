# pixelfed-laravel11-symfony

**Case 2 on Laravel 11: transitive dependencies whose parent already permits the fix.**

- Source: [pixelfed/pixelfed](https://github.com/pixelfed/pixelfed) at commit
  `6c4b9dda86e00bbea395d0f5cb5f02f549e2658e` (2024-10-06).
- Snapshot date (`--as-of`): 2024-11-10.
- Platform: the project requires `php ^8.2|^8.3` without `config.platform`; the fixture pins 8.3.0.

## Findings

`symfony/http-foundation v7.1.5` (CVE-2024-50345) and `symfony/process v7.1.5` (CVE-2024-51736),
fixed in 7.1.7, both required by `laravel/framework v11.26.0` with `^7.0`.

Human choice: `composer update symfony/http-foundation symfony/process`. The planner produces one
plan per package and that combined command. `symfony/process` resolves to 7.2.0 because Packagist
dates that release 2024-11-06, inside the snapshot window.

Built with `bin/build-fixture.php --as-of=2024-11-10 --platform-php=8.3.0`.
