<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Candidate;

use PHPUnit\Framework\TestCase;
use Remediate\Engine\Candidate\Strategy;

final class StrategyTest extends TestCase
{
    public function testRanksFollowTheDeclaredOrderFromLeastToMostInvasive(): void
    {
        $ranks = array_map(static fn (Strategy $s): int => $s->rank(), Strategy::cases());
        $sorted = $ranks;
        sort($sorted);
        self::assertSame($sorted, $ranks);
        self::assertSame(count(Strategy::cases()), count(array_unique($ranks)), 'no two strategies share a rank');
        self::assertSame(Strategy::LockRefresh, Strategy::from('lock-refresh'));
        self::assertLessThan(Strategy::DirectRequire->rank(), Strategy::RootConstraintWiden->rank());
    }

    public function testEveryStrategyHasADistinctLabel(): void
    {
        $labels = array_map(static fn (Strategy $s): string => $s->label(), Strategy::cases());
        self::assertSame(count($labels), count(array_unique($labels)));
        foreach ($labels as $label) {
            self::assertNotSame('', $label);
        }
        self::assertSame('update the controlling parent with all dependencies', Strategy::ParentUpdate->label());
    }
}
