<?php

declare(strict_types=1);

namespace Remediate\Tests\Contract;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\Db\DatabaseWriter;
use Remediate\Engine\Advisory\Db\Source\PackagistShapeMapper;
use Remediate\Engine\Plan\Plan;
use Remediate\Output\ScanOutcome;
use Remediate\Tests\Support\CommandRunner;
use Remediate\Tests\Support\ScriptedProject;

/**
 * Invariant: advisory input this tool cannot fully read never produces a clean result.
 *
 * A clean result is a claim about a lock file, and the claim is only as good as the data behind it.
 * Anything the build could not interpret has to reach the report as a coverage gap, whatever else in
 * the same document it could interpret. The failure this guards against is silence: a record that
 * survives with the portion that parsed, and no trace of the portion that did not.
 *
 * Stated over a range of malformed shapes rather than the one that first slipped through, because the
 * property is about partial reads in general, not about any particular kind of rubbish. The OSV and
 * FriendsOfPHP readers hold the same property and are checked the same way where they live, in the
 * release channel; the reader kept here serves Packagist's shape, `--advisories-file` and private
 * files.
 */
final class AdvisoryCoverageContractTest extends TestCase
{
    /** @return iterable<string, array{array<mixed>}> */
    public static function partiallyUnreadablePackagistDocuments(): iterable
    {
        $good = ['advisoryId' => 'PKSA-1111-2222-3333-4444', 'affectedVersions' => '>=1.0.0,<1.0.5'];

        yield 'a key that is not a package name' => [['advisories' => ['other/lib' => [$good], 'acme lib' => [$good]]]];
        yield 'a key that is not a string' => [['advisories' => ['other/lib' => [$good], 7 => [$good]]]];
        yield 'a package whose advisories are not a list' => [['advisories' => ['other/lib' => [$good], 'acme/lib' => 'unreadable']]];
        yield 'an entry that is not an entry' => [['advisories' => ['acme/lib' => [$good, 'unreadable']]]];
        yield 'an entry with no version range' => [['advisories' => ['acme/lib' => [$good, ['advisoryId' => 'PKSA-no-range']]]]];
        yield 'an entry whose range cannot be parsed' => [['advisories' => ['acme/lib' => [$good, ['advisoryId' => 'PKSA-bad', 'affectedVersions' => 'unreadable']]]]];
    }

    /**
     * The reader that serves Packagist's API shape, private advisory files and `--advisories-file`:
     * a database is only as complete as the least careful of its readers.
     *
     * @param array<mixed> $document
     */
    #[DataProvider('partiallyUnreadablePackagistDocuments')]
    public function testSomethingUnreadableAlwaysReachesTheReport(array $document): void
    {
        $project = new ScriptedProject(['acme/lib' => '^1'], [['acme/lib', '1.0.0']]);
        try {
            $result = (new PackagistShapeMapper())->mapDocument($document, 'Test');

            self::assertNotSame([], $result['gaps'], 'something in this document was dropped without a word');

            $path = $project->directory . '/packagist.sqlite';
            (new DatabaseWriter())->write($result['records'], [], $path, [], $result['gaps']);
            $run = (new CommandRunner())->run(['command' => 'remediate', '--format' => 'json', '--database-location' => $path], $project->directory);
            self::assertFalse(
                $run->exitCode === 0 && $run->json()['summary']['coverage_gaps'] === 0,
                "a lock was called clean on advisory data that could not be fully read\n" . $run->describe(),
            );
        } finally {
            $project->destroy();
        }
    }

    /**
     * Invariant: a recommendation is never called verified by a source that cannot answer for a lock
     * other than the current one.
     *
     * Eighth adversarial review, finding 2. Completeness was established once, before a package was
     * planned. A source can lose it afterwards — the in-process advisory API breaking on a later
     * lookup switches the provider to `composer audit --locked`, which only knows the current lock —
     * and every acceptance rule after that point, "introduces no new advisories" above all, was then
     * decided by something that could not see advisories on the packages the candidate adds. The run
     * reported a verified fix, a combined command and exit 1, next to a warning admitting it could no
     * longer check.
     */
    public function testAFixIsNotVerifiedByASourceThatStoppedBeingAbleToAnswer(): void
    {
        $project = new ScriptedProject(['acme/pkg' => '^1.0'], [['acme/pkg', '1.0.0']]);
        try {
            $advisory = ScriptedProject::advisory('TEST-1', 'acme/pkg', '<1.1.0');
            // Complete until something asks about the package the fix introduces, which is the moment
            // its answer starts to matter.
            $primary = new class($advisory) implements \Remediate\Engine\Advisory\AdvisoryProvider {
                public function __construct(private \Remediate\Engine\Advisory\Advisory $advisory)
                {
                }

                public function advisoriesFor(array $packageNames): array
                {
                    if (in_array('acme/new', $packageNames, true)) {
                        throw new \TypeError('upstream API changed on uncached lookup');
                    }

                    return ['acme/pkg' => [$this->advisory]];
                }

                public function describe(): string
                {
                    return 'an API that stops answering';
                }

                public function isComplete(): bool
                {
                    return true;
                }
            };
            $provider = new \Remediate\Engine\Advisory\FallbackAdvisoryProvider($primary, ScriptedProject::advisories([$advisory], false));
            $solver = new \Remediate\Tests\Support\FakeSolver(new \Remediate\Engine\Solver\SolveResult(
                \Remediate\Engine\Solver\SolveStatus::Resolved,
                ScriptedProject::lock([['acme/pkg', '1.1.0'], ['acme/new', '1.0.0']]),
                '',
            ));

            $plan = (new \Remediate\Engine\Planner($provider, $solver))->plan($project->context(), $project->workspace());

            self::assertFalse($provider->isComplete(), 'the source degraded, as it must for this test to mean anything');
            self::assertFalse($plan->findings[0]->hasRemediation(), 'a fix cannot be verified against advisories the source can no longer see');
            self::assertNull($plan->combined, 'nor can a combined command');
            // Not exit 2. Exit 2 says "there is a vulnerability and nothing can fix it", which is an
            // answer; the truth here is that the run could not find out, and the exit-code table has
            // always called that 4. At 2, SARIF and GitLab called the scan successful.
            self::assertSame(Plan::EXIT_ADVISORIES_UNAVAILABLE, $plan->exitCode(), 'a source that cannot verify candidates is an advisory failure, not an ordinary no-fix result');
            self::assertFalse(ScanOutcome::succeeded($plan), 'and no format may call that run successful');
        } finally {
            $project->destroy();
        }
    }
}
