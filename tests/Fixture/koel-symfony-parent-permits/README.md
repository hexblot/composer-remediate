# koel-symfony-parent-permits

**Case 2: transitive dependency, the parent's constraint already permits the fix.**

- Source: [koel/koel](https://github.com/koel/koel) at commit
  `3848e8b52da79d953d04ce72ce468926287fa295` (2024-10-31, "chore(build): upgrade poddle").
- Snapshot date (`--as-of`): 2024-11-10.
- Platform: the project has no `config.platform`; the fixture pins PHP 8.3.0 (`--platform-php`).

## Findings

`symfony/http-foundation v6.4.4` (CVE-2024-50345, open redirect) and `symfony/process v6.4.4`
(CVE-2024-51736, command execution hijack on Windows), both fixed in 6.4.14. They are transitive:
root requires `laravel/framework ^10.0`, locked at 10.48.8, which requires `symfony/http-foundation
^6.4` and `symfony/process ^6.2`. Every other parent also permits 6.4.14.

Human choice: `composer update symfony/http-foundation symfony/process`. The project's next two
commits (2024-11-08) are Dependabot bumps of exactly these two packages to 6.4.14. With the
snapshot date of 2024-11-10 the newest permitted release is 6.4.15.

The planner produces one plan per package: `composer update symfony/http-foundation` and
`composer update symfony/process`, one change each. Merging them into a single command is a
Phase 1 item.

Built with `bin/build-fixture.php --as-of=2024-11-10 --platform-php=8.3.0`.
