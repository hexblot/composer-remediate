<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Candidate;

use Composer\Semver\Semver;
use Composer\Semver\VersionParser;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Candidate\FixedRangeResolver;

final class FixedRangeResolverTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string, string|null}>
     */
    public static function cases(): iterable
    {
        yield 'simple upper bound' => ['<6.4.24', '6.4.21.0', '>=6.4.24'];
        yield 'bounded branch' => ['>=6.4.0,<6.4.24', '6.4.21.0', '>=6.4.24'];
        yield 'two branches, current in the first' => ['>=5.4.0,<5.4.40|>=6.0.0,<6.4.24', '5.4.30.0', '>=5.4.40,<6.0.0 || >=6.4.24'];
        yield 'two branches, current in the second' => ['>=5.4.0,<5.4.40|>=6.0.0,<6.4.24', '6.4.0.0', '>=6.4.24'];
        yield 'everything affected' => ['*', '1.0.0.0', null];
        yield 'no fix above current (open ended)' => ['>=1.0.0', '1.2.0.0', null];
        yield 'exact version affected' => ['1.2.3', '1.2.3.0', '>1.2.3'];
        yield 'current already past the range' => ['<1.0.0', '2.0.0.0', '>2.0.0'];
    }

    #[DataProvider('cases')]
    public function testFixedRangeAbove(string $affected, string $current, ?string $expected): void
    {
        $parser = new VersionParser();
        $resolver = new FixedRangeResolver();
        $result = $resolver->fixedRangeAbove($parser->parseConstraints($affected), $current);

        if ($expected === null) {
            self::assertNull($result);

            return;
        }
        self::assertNotNull($result);
        self::assertSame($expected, $result->getPrettyString());
        // The pretty string must round-trip through Composer's parser to the same set.
        $reparsed = $parser->parseConstraints($result->getPrettyString());
        foreach (['0.9.0', '1.0.0', '1.2.3', '1.2.4', '2.0.0', '5.4.30', '5.4.40', '5.9.9', '6.0.0', '6.4.21', '6.4.24', '7.0.0'] as $probe) {
            self::assertSame(
                Semver::satisfies($probe, $result->getPrettyString()),
                $reparsed->matches($parser->parseConstraints('==' . $probe)),
                "round trip differs for $probe",
            );
        }
    }

    public function testFixedVersionsAreNeverAffectedAndAlwaysNewer(): void
    {
        $parser = new VersionParser();
        $affected = $parser->parseConstraints('>=5.4.0,<5.4.40|>=6.0.0,<6.4.24');
        $result = (new FixedRangeResolver())->fixedRangeAbove($affected, '6.1.0.0');
        self::assertNotNull($result);
        foreach (['6.4.24', '6.5.0', '7.0.0'] as $safe) {
            self::assertTrue(Semver::satisfies($safe, $result->getPrettyString()), "$safe should be a fixed version");
        }
        foreach (['5.4.40', '6.0.0', '6.1.0', '6.4.23'] as $notFixed) {
            self::assertFalse(Semver::satisfies($notFixed, $result->getPrettyString()), "$notFixed should not be offered");
        }
    }

    public function testShortVersion(): void
    {
        self::assertSame('6.4.24', FixedRangeResolver::shortVersion('6.4.24.0'));
        self::assertSame('6.4.24-RC1', FixedRangeResolver::shortVersion('6.4.24.0-RC1'));
        self::assertSame('1.0.0.1', FixedRangeResolver::shortVersion('1.0.0.1'));
        self::assertSame('2.0.0-dev', FixedRangeResolver::shortVersion('2.0.0.0-dev'));
    }
}
