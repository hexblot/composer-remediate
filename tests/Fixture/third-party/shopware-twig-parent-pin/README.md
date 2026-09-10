# shopware-twig-parent-pin

**Case 3: transitive dependency whose parent excludes the fix; the parent needs a newer patch release.**

- Source: [shopware/production](https://github.com/shopware/production) at tag `v6.4.15.1`, commit
  `5e1b7fec0050e5e118467e944222d7d4ffca9c39` (2022-09-21).
- Snapshot date (`--as-of`): 2022-10-10.
- Platform: `config.platform.php` 7.4.3 (from the project).
- The project declares two `path` repositories with globs that match nothing; the builder drops them
  and copies the locked packages from the lock file.

## Findings

`twig/twig v3.3.10` is affected by CVE-2022-39261 (template loading outside the configured
directory), fixed in 3.4.3. Root requires `shopware/core ~v6.4.0` and `shopware/storefront ~v6.4.0`;
both locked at 6.4.15.1 and both require `twig/twig ~3.3.8`, which excludes 3.4.3. `shopware/core
6.4.15.2` (2022-10-05) is the first release requiring `~3.4.3`. `shopware/administration`,
`shopware/elasticsearch` and `shopware/recovery` pin `shopware/core` to the exact version, so the whole
family has to move together.

Human choice: `composer update "shopware/*" twig/twig -w`, landing on 6.4.15.2 everywhere and twig
3.4.3 (seven changes: the five Shopware packages, twig, and `shopware/conflicts`, which keeps version
0.0.1 while its commit moves, the same-version reference change the lock diff counts). The planner
recommends
`composer update shopware/storefront:6.4.15.2 shopware/recovery shopware/elasticsearch shopware/administration -W -m`:
the same seven changes, with the parent pinned to the lowest working version rather than 6.4.16.0.

`shopwarelabs/dompdf v1.0.3` (a fork that replaces `dompdf/dompdf`) is affected by three advisories
fixed only in 2.x; every 6.4 release of shopware/core pins it exactly, so no remediation exists as of
the snapshot date.

Built with `bin/build-fixture.php --as-of=2022-10-10`.
