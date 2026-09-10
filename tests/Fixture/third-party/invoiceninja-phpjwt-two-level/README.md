# invoiceninja-phpjwt-two-level

**Case 3 with a two-level chain: the direct parent and an intermediate package both pin the fix out.**

- Source: [invoiceninja/invoiceninja](https://github.com/invoiceninja/invoiceninja) at commit
  `5a4614da1f8836bc9a6482b5ef24588402da6aac` (2022-04-01, branch v5-stable).
- Snapshot date (`--as-of`): 2022-04-20.
- Platform: the project requires `php ^7.4|^8.0` without `config.platform`; the fixture pins 8.0.30.

## Findings

`firebase/php-jwt v5.5.1` is affected by CVE-2021-46743 (algorithm confusion), fixed in 6.0.0. It is
required with `~5.0` by `google/apiclient v2.12.1` (root `^2.7`) and by `google/auth v1.19.0`, which is
not a root requirement. `google/apiclient 2.12.2` (2022-04-05) adds `~6.0` and `google/auth 1.21.0`
(2022-04-13) allows `^6.0`.

Human choice: `composer update firebase/php-jwt google/apiclient google/auth`. The planner recommends
`composer update google/apiclient:v2.12.2 -W -m --with 'firebase/php-jwt:>=6.0.0'`: three changes
(php-jwt 6.1.1, google/apiclient 2.12.2 pinned by the descent, google/auth 1.21.0 moved by `-W`).

`maximebf/debugbar 1.18.0` carries two advisories for its bundled jQuery (CVE-2019-11358,
CVE-2020-11022) with no fixed release at the snapshot date, so no remediation is expected there.

Built with `bin/build-fixture.php --as-of=2022-04-20 --platform-php=8.0.30`.
