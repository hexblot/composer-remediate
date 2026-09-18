<?php

declare(strict_types=1);

namespace Remediate\Tests\Contract;

use PHPUnit\Framework\TestCase;
use Composer\Semver\Constraint\MatchAllConstraint;
use Remediate\Engine\Advisory\Advisory;
use Remediate\Engine\Advisory\Severity;
use Remediate\Engine\Matching\Finding;
use Remediate\Engine\Plan\FindingPlan;
use Remediate\Engine\Plan\Plan;

/**
 * Invariant: an advisory gates the run exactly when it was not accepted and it meets the threshold.
 *
 * Both filters describe individual advisories, so both have to be applied to the same individual
 * advisory before anything is aggregated up to the package. Asking whether a package as a whole was
 * accepted and then asking whether any of its advisories is severe enough answers about two different
 * sets, and an advisory that was accepted goes on gating the run through a severity it was accepted
 * at, as soon as anything else on that package is new.
 *
 * Checked over every combination of acceptance and threshold rather than the one that first broke,
 * because the property is compositional and that is where a rule like this goes wrong.
 */
final class GatingContractTest extends TestCase
{
    public function testGatingIsTheSameHoweverAcceptanceAndThresholdCompose(): void
    {
        $severities = ['critical', 'high', 'medium', 'low', null];
        $thresholds = [null, 'low', 'medium', 'high', 'critical'];
        $checked = 0;

        // Every pair of advisories on one package, every subset of them accepted, every threshold.
        foreach ($severities as $first) {
            foreach ($severities as $second) {
                $plan = self::packageWith(['ADV-1' => $first, 'ADV-2' => $second]);
                foreach ([[], ['ADV-1@acme/lib'], ['ADV-2@acme/lib'], ['ADV-1@acme/lib', 'ADV-2@acme/lib']] as $accepted) {
                    foreach ($thresholds as $threshold) {
                        $subject = (new Plan([$plan], []))->withBaseline($accepted);
                        if ($threshold !== null) {
                            $subject = $subject->withFailOn($threshold);
                        }

                        self::assertSame(
                            self::shouldGate(['ADV-1' => $first, 'ADV-2' => $second], $accepted, $threshold),
                            $subject->countsForExit($subject->findings[0]),
                            sprintf('severities %s/%s, accepted [%s], threshold %s', $first ?? 'unknown', $second ?? 'unknown', implode(',', $accepted), $threshold ?? 'none'),
                        );
                        ++$checked;
                    }
                }
            }
        }

        self::assertSame(500, $checked, 'the whole matrix has to be walked, not part of it');
    }

    /**
     * The rule, stated once, independently of how the code happens to be arranged.
     *
     * @param array<string, string|null> $advisories
     * @param list<string>               $accepted
     */
    private static function shouldGate(array $advisories, array $accepted, ?string $threshold): bool
    {
        $rank = $threshold === null ? null : (Severity::fromLabel($threshold)?->rank() ?? 0);
        foreach ($advisories as $id => $severity) {
            if (in_array(strtolower($id . '@acme/lib'), array_map('strtolower', $accepted), true)) {
                continue;
            }
            if ($rank === null) {
                return true;
            }
            $own = Severity::fromLabel($severity)?->rank();
            if ($own === null || $own >= $rank) {
                return true;
            }
        }

        return false;
    }

    /** @param array<string, string|null> $advisories */
    private static function packageWith(array $advisories): FindingPlan
    {
        $findings = [];
        foreach ($advisories as $id => $severity) {
            $findings[] = new Finding(
                new Advisory($id, 'acme/lib', new MatchAllConstraint(), 'Synthetic', null, null, $severity),
                'acme/lib',
                '1.0.0.0',
                '1.0.0',
                false,
                false,
            );
        }

        return new FindingPlan($findings[0], [], [], null, [], array_slice($findings, 1));
    }
}
