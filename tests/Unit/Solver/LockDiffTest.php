<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Solver;

use Composer\Package\Package;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Lock\LockSnapshot;
use Remediate\Engine\Solver\LockDiff;
use Remediate\Engine\Solver\PackageChange;
use Remediate\Engine\Solver\VersionStep;

final class LockDiffTest extends TestCase
{
    public function testClassifiesChanges(): void
    {
        $before = LockSnapshot::fromPackages([
            new Package('a/kept', '1.0.0.0', '1.0.0'),
            new Package('a/patch', '1.0.0.0', '1.0.0'),
            new Package('a/minor', '1.0.0.0', '1.0.0'),
            new Package('a/major', '1.0.0.0', '1.0.0'),
            new Package('a/down', '1.2.0.0', '1.2.0'),
            new Package('a/gone', '1.0.0.0', '1.0.0'),
        ], [new Package('a/devonly', '1.0.0.0', '1.0.0')]);
        $after = LockSnapshot::fromPackages([
            new Package('a/kept', '1.0.0.0', '1.0.0'),
            new Package('a/patch', '1.0.1.0', '1.0.1'),
            new Package('a/minor', '1.1.0.0', '1.1.0'),
            new Package('a/major', '2.0.0.0', '2.0.0'),
            new Package('a/down', '1.1.0.0', '1.1.0'),
            new Package('a/new', '3.0.0.0', '3.0.0'),
        ], [new Package('a/devonly', '1.0.0.0', '1.0.0')]);

        $diff = LockDiff::between($before, $after);

        self::assertSame(['a/down', 'a/gone', 'a/major', 'a/minor', 'a/new', 'a/patch'], $diff->changedNames());
        $down = $diff->changeFor('a/down');
        self::assertNotNull($down);
        self::assertSame(PackageChange::DOWNGRADED, $down->kind);
        self::assertSame(VersionStep::Minor, $down->step);
        self::assertSame(PackageChange::REMOVED, $diff->changeFor('a/gone')?->kind);
        $major = $diff->changeFor('a/major');
        self::assertNotNull($major);
        self::assertSame(VersionStep::Major, $major->step);
        self::assertSame(VersionStep::Patch, $diff->changeFor('a/patch')?->step);
        self::assertSame(PackageChange::ADDED, $diff->changeFor('a/new')?->kind);
        self::assertTrue($diff->hasMajorChange());
        self::assertTrue($diff->hasDowngrade());
        self::assertCount(1, $diff->added());
        self::assertCount(1, $diff->removed());
        self::assertCount(4, $diff->versionChanges());
        self::assertSame('a/major 1.0.0 -> 2.0.0', $major->describe());
        self::assertTrue($after->isDev('a/devonly'));
        self::assertFalse($after->isDev('a/kept'));
    }

    public function testDevBranchChangesAreOther(): void
    {
        $before = LockSnapshot::fromPackages([new Package('a/b', 'dev-main', 'dev-main')], []);
        $after = LockSnapshot::fromPackages([new Package('a/b', '1.0.0.0', '1.0.0')], []);
        $diff = LockDiff::between($before, $after);
        $change = $diff->changeFor('a/b');
        self::assertNotNull($change);
        self::assertSame(VersionStep::Other, $change->step);
        self::assertSame(PackageChange::CHANGED, $change->kind);
        self::assertFalse($diff->hasMajorChange());
    }
}
