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

    public function testOpenEndedRange(): void
    {
        $expression = (new RangeNormalizer())->fromOsv([['type' => 'ECOSYSTEM', 'events' => [['introduced' => '3.0.0']]]]);
        self::assertNotNull($expression);
        self::assertTrue($this->affects($expression, '9.0.0'));
        self::assertFalse($this->affects($expression, '2.9.9'));
    }
}
