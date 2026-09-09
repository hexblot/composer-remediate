# shopware-6420-twig-no-fix

**Case 5 by constraint: the fix exists upstream but no release within the root constraint can reach it.**

- Source: [shopware/production](https://github.com/shopware/production) at tag `v6.4.20.2`, commit
  `0e41d421dee0dcc6cbc579813347836c23c1ba49` (2023-05-05), the final 6.4 release.
- Snapshot date (`--as-of`): 2024-09-15, a few days after CVE-2024-45411 was published.
- Platform: `config.platform.php` 7.4.3 (from the project). Two empty `path` repository globs are
  dropped by the builder.

## Findings

Twenty-six advisories on ten packages. `twig/twig v3.4.3` is affected by CVE-2024-45411 (fixed in
3.11.0 and 3.14.0); every 6.4 release of `shopware/core` pins `twig/twig ~3.4.3`, the root requires
`shopware/core ~v6.4.0`, and `shopware/core 6.5+` requires PHP 8.1 against a 7.4.3 platform. The
planner must report no verified remediation for twig, for the shopware/core advisories themselves, and
for the packages shopware/core pins exactly (shopwarelabs/dompdf, tecnickcom/tcpdf, phenx/php-svg-lib).

Still fixable by partial updates: `composer/composer`, `symfony/twig-bridge`, `aws/aws-sdk-php` (with
its dependencies) and `symfony/validator`. The summary's combined command fixes 7 of 26 findings:

    composer update aws/aws-sdk-php composer/composer symfony/twig-bridge shopware/core -W -m --with 'symfony/validator:>=5.4.43,<6.0.0 || >=6.4.11,<7.0.0 || >=7.1.4'

The honest answer for this project is a Shopware 6.5/6.6 migration; the report says so by listing
what cannot be fixed in place.

Built with `bin/build-fixture.php --as-of=2024-09-15`.
