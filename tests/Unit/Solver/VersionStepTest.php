<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Solver;

use PHPUnit\Framework\TestCase;
use Remediate\Engine\Solver\VersionStep;

final class VersionStepTest extends TestCase
{
    public function testWeightsOrderPatchBelowMinorBelowUnclassifiedBelowMajor(): void
    {
        self::assertLessThan(VersionStep::Minor->weight(), VersionStep::Patch->weight());
        self::assertLessThan(VersionStep::Other->weight(), VersionStep::Minor->weight());
        self::assertLessThan(VersionStep::Major->weight(), VersionStep::Other->weight());
        self::assertSame(VersionStep::Major, VersionStep::from('major'));
    }
}
