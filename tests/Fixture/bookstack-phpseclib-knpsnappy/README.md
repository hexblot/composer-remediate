# bookstack-phpseclib-knpsnappy

**Cases 1 and 2 together: a direct and a transitive dependency whose constraints already permit the fix.**

- Source: [BookStackApp/BookStack](https://github.com/BookStackApp/BookStack) at commit
  `f9fcc9f3c7851fec07923f335972a50efe11ba26` (2023-02-16).
- Snapshot date (`--as-of`): 2023-03-25.
- Platform: `config.platform.php` 8.0.2 (from the project).

## Findings

`phpseclib/phpseclib 3.0.18` (direct, root `^3.0`) is affected by CVE-2023-27560, fixed in 3.0.19.
`knplabs/knp-snappy v1.4.1` is transitive via `barryvdh/laravel-snappy 1.0.x` (root `^1.0`, requires
`knplabs/knp-snappy ^1.4`), affected by CVE-2023-28115, fixed in 1.4.2.

Human choice: `composer update phpseclib/phpseclib knplabs/knp-snappy`. The planner recommends one
partial update per package and the same combined command in the summary.

Built with `bin/build-fixture.php --as-of=2023-03-25`.
