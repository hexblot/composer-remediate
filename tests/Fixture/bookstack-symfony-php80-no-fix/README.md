# bookstack-symfony-php80-no-fix

**Case 5: no valid remediation under the project's platform constraints.**

- Source: [BookStackApp/BookStack](https://github.com/BookStackApp/BookStack) at commit
  `88ee33ee49c0c920d8ad3fb1161fe27b62c64004` (2023-12-22, the last dependency update before the
  project's PHP 8.1 bump).
- Snapshot date (`--as-of`): 2024-11-10.
- Platform: `config.platform.php` 8.0.2 (from the project).

## Findings

`symfony/http-foundation v6.0.20` (CVE-2024-50345) and `symfony/process v6.0.19` (CVE-2024-51736)
come from `laravel/framework v9.52.16`, a root requirement at `^9.0` that requires `^6.0` for both.
The fixed releases are 5.4.46, 6.4.14 and 7.1.7: 5.4.46 is excluded by `^6.0`, every 6.1+ release
requires PHP >=8.1, 7.x requires 8.2, and upgrading Laravel does not help because laravel/framework
10 requires PHP ^8.1 too. Under `config.platform.php` 8.0.2 there is no fix; the human answer is
"raise the platform to PHP 8.1 and upgrade Laravel". The planner must report no verified
remediation and show the PHP requirement as the blocker.

The same lock has two fixable findings: `phpseclib/phpseclib 3.0.34` (direct, CVE-2024-27354 and
CVE-2024-27355) and `phenx/php-svg-lib 0.5.1` (CVE-2024-25117), both by a plain partial update.

Built with `bin/build-fixture.php --as-of=2024-11-10`.
