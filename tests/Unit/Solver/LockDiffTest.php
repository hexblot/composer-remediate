<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Solver;

use Composer\Package\Package;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Lock\LockSnapshot;
use Remediate\Engine\Solver\CapabilityChange;
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

    public function testAMovedReferenceOnTheSameVersionIsAChangeTheReleaseAgeGuardSees(): void
    {
        $old = new Package('a/b', '1.2.3.0', '1.2.3');
        $old->setDistReference('aaaaaaa1111');
        $new = new Package('a/b', '1.2.3.0', '1.2.3');
        $new->setDistReference('bbbbbbb2222');
        $diff = LockDiff::between(LockSnapshot::fromPackages([$old], []), LockSnapshot::fromPackages([$new], []));
        $change = $diff->changeFor('a/b');
        self::assertNotNull($change, 'same version, different commit: a re-tagged release is a change');
        self::assertSame(PackageChange::CHANGED, $change->kind);
        self::assertSame(VersionStep::Other, $change->step);
        self::assertSame('1.2.3#aaaaaaa', $change->fromPretty);
        self::assertSame('1.2.3#bbbbbbb', $change->toPretty);

        $guard = new \Remediate\Engine\Solver\ReleaseAgeGuard(7);
        $young = $guard->tooYoung($diff, LockSnapshot::fromPackages([$new], []));
        self::assertCount(1, $young, 'the guard refuses it: the release date of the new bytes is unknown');
        self::assertStringContainsString('release date unknown', $young[0]);
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

    public function testCapabilityChangesAreReadFromMetadataTheSnapshotsAlreadyCarry(): void
    {
        $old = new Package('a/lib', '1.0.0.0', '1.0.0');
        $old->setType('library');
        $old->setSourceUrl('https://github.com/a/lib.git');
        $new = new Package('a/lib', '2.0.0.0', '2.0.0');
        $new->setType('composer-plugin');
        $new->setAutoload(['files' => ['src/boot.php'], 'psr-4' => ['A\\' => 'src/']]);
        $new->setBinaries(['bin/a']);
        $new->setSourceUrl('https://git.a.test/lib.git');

        $diff = LockDiff::between(LockSnapshot::fromPackages([$old], []), LockSnapshot::fromPackages([$new], []));

        self::assertSame([
            'a/lib changes type: library -> composer-plugin',
            'a/lib autoloads files on every request: src/boot.php',
            'a/lib installs binaries: bin/a',
            'a/lib is fetched from a different source host: github.com -> git.a.test',
        ], array_map(static fn (CapabilityChange $c): string => $c->describe(), $diff->capabilityChanges));
        self::assertCount(3, $diff->newCodeCapabilities(), 'the host change does not itself run new code');
    }

    public function testAnUnchangedPackageAndAPurelyNumericUpgradeCarryNoCapabilityChange(): void
    {
        $before = new Package('a/lib', '1.0.0.0', '1.0.0');
        $before->setType('library');
        $before->setBinaries(['bin/a']);
        $after = new Package('a/lib', '1.0.1.0', '1.0.1');
        $after->setType('library');
        $after->setBinaries(['bin/a']);

        $diff = LockDiff::between(LockSnapshot::fromPackages([$before], []), LockSnapshot::fromPackages([$after], []));

        self::assertSame([], $diff->capabilityChanges);
    }

    public function testAnAddedPackageIsReportedOnlyForWhatRunsWithoutBeingCalled(): void
    {
        $plugin = new Package('a/plugin', '1.0.0.0', '1.0.0');
        $plugin->setType('composer-plugin');
        $plugin->setAutoload(['files' => ['boot.php']]);
        $plugin->setBinaries(['bin/noisy']);
        $ordinary = new Package('a/ordinary', '1.0.0.0', '1.0.0');
        $ordinary->setType('library');
        $ordinary->setBinaries(['bin/quiet']);

        $diff = LockDiff::between(LockSnapshot::fromPackages([], []), LockSnapshot::fromPackages([$plugin, $ordinary], []));

        self::assertSame([
            'a/plugin is a composer-plugin',
            'a/plugin autoloads files on every request: boot.php',
        ], array_map(static fn (CapabilityChange $c): string => $c->describe(), $diff->capabilityChanges));
    }

    public function testARemovedPackageGainsNothing(): void
    {
        $gone = new Package('a/gone', '1.0.0.0', '1.0.0');
        $gone->setType('composer-plugin');

        $diff = LockDiff::between(LockSnapshot::fromPackages([$gone], []), LockSnapshot::fromPackages([], []));

        self::assertSame([], $diff->capabilityChanges);
    }
}
