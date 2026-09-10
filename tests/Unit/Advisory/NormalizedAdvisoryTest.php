<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Advisory;

use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\Db\AffectedRange;
use Remediate\Engine\Advisory\Db\NormalizedAdvisory;

final class NormalizedAdvisoryTest extends TestCase
{
    /**
     * @param non-empty-list<string> $aliases
     * @param list<string>           $packages
     */
    private static function advisory(array $aliases, array $packages): NormalizedAdvisory
    {
        return new NormalizedAdvisory($aliases[0], $aliases, null, null, null, null, null, array_map(static fn (string $p): AffectedRange => new AffectedRange($p, '<1.0', 'Test'), $packages), []);
    }

    public function testCveIsFoundAmongTheAliasesAndUpperCased(): void
    {
        self::assertSame('CVE-2026-1234', self::advisory(['GHSA-abcd', 'cve-2026-1234'], ['acme/lib'])->cve());
        self::assertNull(self::advisory(['GHSA-abcd', 'CVE-not-a-cve'], ['acme/lib'])->cve());
    }

    public function testPackagesAreDistinctAndLowerCase(): void
    {
        self::assertSame(['acme/lib', 'acme/other'], self::advisory(['X-1'], ['Acme/Lib', 'acme/lib', 'acme/other'])->packages());
    }

    public function testRankIdPrefersCveThenGhsaThenPksa(): void
    {
        self::assertSame(0, NormalizedAdvisory::rankId('CVE-2026-1'));
        self::assertSame(0, NormalizedAdvisory::rankId('cve-2026-1'));
        self::assertSame(1, NormalizedAdvisory::rankId('GHSA-xxxx-yyyy-zzzz'));
        self::assertSame(2, NormalizedAdvisory::rankId('PKSA-abcd-1234'));
        self::assertSame(3, NormalizedAdvisory::rankId('acme/lib/2026-01-01.yaml'));
    }
}
