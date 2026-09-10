<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Advisory;

use Composer\Semver\Constraint\Constraint;
use Composer\Semver\VersionParser;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\Db\RangeNormalizer;

final class RangeNormalizerTest extends TestCase
{
    private function affects(string $expression, string $version): bool
    {
        return (new VersionParser())->parseConstraints($expression)->matches(new Constraint('==', (new VersionParser())->normalize($version)));
    }

    public function testExplicitVersionsOutsideTheRangesAreAffected(): void
    {
        $expression = (new RangeNormalizer())->fromOsv([['type' => 'ECOSYSTEM', 'events' => [['introduced' => '0'], ['fixed' => '1.1.0']]]], ['1.0.0', '2.0.0']);
        self::assertNotNull($expression);
        self::assertTrue($this->affects($expression, '1.0.5'));
        self::assertTrue($this->affects($expression, '2.0.0'), 'OSV evaluates membership in ranges OR versions');
        self::assertFalse($this->affects($expression, '1.1.0'));
        self::assertFalse($this->affects($expression, '2.0.1'));
    }

    public function testLimitEventCapsTheRange(): void
    {
        $expression = (new RangeNormalizer())->fromOsv([['type' => 'ECOSYSTEM', 'events' => [['introduced' => '1.0.0'], ['limit' => '2.0.0']]]]);
        self::assertNotNull($expression);
        self::assertTrue($this->affects($expression, '1.5.0'));
        self::assertFalse($this->affects($expression, '2.0.0'));
        self::assertFalse($this->affects($expression, '3.0.0'));
    }

    public function testLimitCapsTheWholeRangeWithoutOpeningAnInterval(): void
    {
        // introduced 1.0, fixed 1.1, limit 2.0: only [1.0, 1.1) is affected; the limit does not add "<2.0".
        $expression = (new RangeNormalizer())->fromOsv([['type' => 'ECOSYSTEM', 'events' => [['introduced' => '1.0.0'], ['fixed' => '1.1.0'], ['limit' => '2.0.0']]]]);
        self::assertNotNull($expression);
        self::assertTrue($this->affects($expression, '1.0.5'));
        self::assertFalse($this->affects($expression, '1.5.0'));
        self::assertFalse($this->affects($expression, '0.9.0'));

        // A limit below an open interval's end cuts it: introduced 1.0, introduced 3.0, fixed 1.1, limit 3.5.
        $expression = (new RangeNormalizer())->fromOsv([['type' => 'ECOSYSTEM', 'events' => [['introduced' => '3.0.0'], ['limit' => '3.5.0'], ['fixed' => '1.1.0'], ['introduced' => '1.0.0']]]]);
        self::assertNotNull($expression);
        self::assertTrue($this->affects($expression, '1.0.5'));
        self::assertFalse($this->affects($expression, '2.0.0'));
        self::assertTrue($this->affects($expression, '3.2.0'));
        self::assertFalse($this->affects($expression, '3.5.0'));
        self::assertFalse($this->affects($expression, '4.0.0'));
    }

    public function testSeveralLimitsKeepTheLargestBecauseAVersionBelowAnyLimitIsAffected(): void
    {
        // OSV BeforeLimits: v is affected when it is below *any* limit, so limits union rather than intersect.
        $expression = (new RangeNormalizer())->fromOsv([['type' => 'ECOSYSTEM', 'events' => [['introduced' => '1.0.0'], ['limit' => '2.0.0'], ['limit' => '3.0.0']]]]);
        self::assertNotNull($expression);
        self::assertTrue($this->affects($expression, '1.5.0'));
        self::assertTrue($this->affects($expression, '2.5.0'), 'below the 3.0.0 limit');
        self::assertFalse($this->affects($expression, '3.0.0'));
    }

    public function testAStarLimitLiftsTheCapEntirely(): void
    {
        $expression = (new RangeNormalizer())->fromOsv([['type' => 'ECOSYSTEM', 'events' => [['introduced' => '1.0.0'], ['limit' => '2.0.0'], ['limit' => '*']]]]);
        self::assertNotNull($expression);
        self::assertTrue($this->affects($expression, '2.5.0'), 'every version is below an infinite limit');
        self::assertTrue($this->affects($expression, '9.0.0'));
        self::assertFalse($this->affects($expression, '0.9.0'));

        // The same with a closing event: the star limit changes nothing about the fixed bound.
        $expression = (new RangeNormalizer())->fromOsv([['type' => 'ECOSYSTEM', 'events' => [['introduced' => '1.0.0'], ['fixed' => '1.1.0'], ['limit' => '*']]]]);
        self::assertNotNull($expression);
        self::assertTrue($this->affects($expression, '1.0.5'));
        self::assertFalse($this->affects($expression, '1.1.0'));
    }

    public function testEventsAreEvaluatedInVersionOrderNotInputOrder(): void
    {
        $sorted = (new RangeNormalizer())->fromOsv([['type' => 'ECOSYSTEM', 'events' => [['introduced' => '1.0.0'], ['fixed' => '1.1.0'], ['introduced' => '2.0.0'], ['fixed' => '2.1.0']]]]);
        $shuffled = (new RangeNormalizer())->fromOsv([['type' => 'ECOSYSTEM', 'events' => [['fixed' => '2.1.0'], ['introduced' => '2.0.0'], ['fixed' => '1.1.0'], ['introduced' => '1.0.0']]]]);
        self::assertNotNull($sorted);
        self::assertSame($sorted, $shuffled);
        self::assertTrue($this->affects($sorted, '2.0.5'));
        self::assertFalse($this->affects($sorted, '1.5.0'));
    }

    public function testUnparsableVersionMakesTheRecordUnreadable(): void
    {
        self::assertNull((new RangeNormalizer())->fromOsv([['type' => 'ECOSYSTEM', 'events' => [['introduced' => 'not a version !!']]]]));
    }

    public function testOpenEndedRange(): void
    {
        $expression = (new RangeNormalizer())->fromOsv([['type' => 'ECOSYSTEM', 'events' => [['introduced' => '3.0.0']]]]);
        self::assertNotNull($expression);
        self::assertTrue($this->affects($expression, '9.0.0'));
        self::assertFalse($this->affects($expression, '2.9.9'));
    }
}
