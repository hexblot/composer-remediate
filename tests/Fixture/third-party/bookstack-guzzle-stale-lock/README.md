# bookstack-guzzle-stale-lock

**Case 1: direct dependency, the root constraint already permits the fix (stale lock).**

- Source: [BookStackApp/BookStack](https://github.com/BookStackApp/BookStack) at commit
  `4a2a044f3d0715de441aa4de9e000305d48dc7ab` (2022-05-09, "Updated PHP deps").
- Snapshot date (`--as-of`): 2022-07-01. Package versions released and advisories reported after
  that date are absent from the fixture.
- Platform: `config.platform.php` 7.4.0 (from the project), extensions from the build environment.

## Findings

`guzzlehttp/guzzle 7.4.2` is a root requirement (`^7.4`) affected by CVE-2022-31042, CVE-2022-31043,
CVE-2022-29248, CVE-2022-31090 and CVE-2022-31091; all are fixed in 7.4.5. Every other parent
(aws/aws-sdk-php, laravel/socialite, league/oauth1-client, league/oauth2-client) permits 7.4.5.

Human choice: `composer update guzzlehttp/guzzle`. That alone resolves to 7.4.4, still affected by
two advisories, because 7.4.5 requires `guzzlehttp/psr7 ^2.4.1` and the lock holds 2.2.1; the
working command is `composer update guzzlehttp/guzzle -w` (two changes). The planner recommends
`composer update guzzlehttp/guzzle -w -m`.

Incidental finding: `dompdf/dompdf 1.2.2` (CVE-2022-0085, fixed in 2.0.0) is pinned by
`barryvdh/laravel-dompdf 1.0.0` (`dompdf/dompdf ^1`), a root requirement at `^1.0`. Only widening the
root constraint to `^2.0` works, and as of 2022-07-01 that resolves to `v2.0.0-beta2` because the
project sets `minimum-stability: dev`. The planner flags the pre-release.

Built with `bin/build-fixture.php --as-of=2022-07-01`.
