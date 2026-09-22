<?php

declare(strict_types=1);

namespace Remediate\Tests\Contract;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Apply\Applier;
use Remediate\Engine\Planner;
use Remediate\Engine\Solver\SolveResult;
use Remediate\Engine\Solver\SolveStatus;
use Remediate\Tests\Support\FakeSolver;
use Remediate\Tests\Support\ScriptedProject;

/**
 * Invariant: `--apply` runs only against the exact files the plan was computed from, and refuses on
 * any answer other than "these are still those files".
 *
 * `--apply` is the only thing in this tool that writes to a project, so its preconditions are the
 * whole of its safety story. The failure mode this states against is not a wrong answer but a missing
 * one: a comparison that cannot be made is not a comparison that passed. Both defects here were of
 * that shape — hashes taken after the search rather than before it, so an edit during the search
 * matched itself; and the comparison skipped entirely when the file could not be read, so deleting it
 * was safer than changing it.
 *
 * Stated as a contract because each repair was correct about the case it was shown and silent about
 * its neighbour.
 */
final class ApplyPreconditionContractTest extends TestCase
{
    /**
     * Ways the inputs can stop being what the plan was computed from, and the refusal each must draw.
     *
     * @return iterable<string, array{callable(string): void, string}>
     */
    public static function interference(): iterable
    {
        yield 'the manifest is edited while the search runs' => [
            static function (string $dir): void {
                $json = json_decode((string) file_get_contents($dir . '/composer.json'), true);
                $json['description'] = 'changed while planning';
                file_put_contents($dir . '/composer.json', (string) json_encode($json));
            },
            'composer.json changed while the plan was being computed',
        ];

        yield 'the lock is edited while the search runs' => [
            static function (string $dir): void {
                file_put_contents($dir . '/composer.lock', (string) file_get_contents($dir . '/composer.lock') . "\n");
            },
            'composer.lock changed while the plan was being computed',
        ];

        yield 'the manifest is removed while the search runs' => [
            static function (string $dir): void {
                unlink($dir . '/composer.json');
            },
            'composer.json is missing or unreadable',
        ];

        yield 'the lock is removed while the search runs' => [
            static function (string $dir): void {
                unlink($dir . '/composer.lock');
            },
            'composer.lock is missing or unreadable',
        ];
    }

    /**
     * @param callable(string): void $interfere
     */
    #[DataProvider('interference')]
    public function testAnythingButAnExactMatchIsARefusal(callable $interfere, string $expected): void
    {
        $project = new ScriptedProject(['acme/pkg' => '^1.0'], [['acme/pkg', '1.0.0']]);
        try {
            $context = $project->context();
            $plan = (new Planner(
                ScriptedProject::advisories([ScriptedProject::advisory('TEST-1', 'acme/pkg', '<1.1.0')]),
                new FakeSolver(new SolveResult(SolveStatus::Resolved, ScriptedProject::lock([['acme/pkg', '1.1.0']]), '')),
            ))->plan($context, $project->workspace());

            self::assertNotNull($plan->combined, 'there is something to apply, so the guard is the only thing in the way');

            $interfere($project->directory);

            // --apply-allow-dirty, so that git's separate check cannot be what refuses.
            $refusal = (new Applier(['composer']))->refusal($plan, $context, false, true);
            self::assertNotNull($refusal, 'the apply went ahead against inputs that are no longer the ones planned from');
            self::assertStringContainsString($expected, $refusal);
        } finally {
            $project->destroy();
        }
    }

    public function testUntouchedInputsAreNotRefused(): void
    {
        // The other half: a guard that refused everything would satisfy the cases above and be useless.
        $project = new ScriptedProject(['acme/pkg' => '^1.0'], [['acme/pkg', '1.0.0']]);
        try {
            $context = $project->context();
            $plan = (new Planner(
                ScriptedProject::advisories([ScriptedProject::advisory('TEST-1', 'acme/pkg', '<1.1.0')]),
                new FakeSolver(new SolveResult(SolveStatus::Resolved, ScriptedProject::lock([['acme/pkg', '1.1.0']]), '')),
            ))->plan($context, $project->workspace());

            self::assertNull((new Applier(['composer']))->refusal($plan, $context, false, true));
        } finally {
            $project->destroy();
        }
    }
}
