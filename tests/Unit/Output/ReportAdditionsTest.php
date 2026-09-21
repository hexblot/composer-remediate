<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Output;

use Composer\DependencyResolver\Request;
use Composer\Package\Package;
use Composer\Semver\VersionParser;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\Advisory;
use Remediate\Engine\Candidate\Candidate;
use Remediate\Engine\Candidate\RootConstraintChange;
use Remediate\Engine\Candidate\Strategy;
use Remediate\Engine\Lock\LockSnapshot;
use Remediate\Engine\Matching\Finding;
use Remediate\Engine\Plan\EvaluatedCandidate;
use Remediate\Engine\Plan\FindingPlan;
use Remediate\Engine\Plan\Plan;
use Remediate\Engine\Solver\LockDiff;
use Remediate\Engine\Solver\SolveResult;
use Remediate\Engine\Solver\SolveStatus;
use Remediate\Output\HtmlRenderer;
use Remediate\Output\JsonRenderer;
use Remediate\Output\TextRenderer;

/**
 * The three report additions asked for in the community feedback: why a widening is the only route,
 * how to make a --with constraint permanent, and what an update changes about what a package can do.
 *
 * They are additions to the text and HTML reports only; the JSON document is unchanged in 0.9.1 and
 * a test here holds it to that.
 */
final class ReportAdditionsTest extends TestCase
{
    /** A fix that can only be had by leaving the locked major behind. */
    private function dragPlan(string $toVersion = '2.0.0'): Plan
    {
        $advisory = new Advisory('PKSA-aaaa', 'acme/lib', (new VersionParser())->parseConstraints('<2.0.0'), 'Bad thing', 'CVE-2026-1', null, 'high');
        $finding = new Finding($advisory, 'acme/lib', '1.4.0.0', '1.4.0', false, true);
        $candidate = new Candidate(
            Strategy::RootConstraintWiden,
            ['acme/lib'],
            Request::UPDATE_LISTED_WITH_TRANSITIVE_DEPS,
            [],
            true,
            ['acme/lib' => new RootConstraintChange('acme/lib', '^1.0', '^2.0', false)],
            'widen the root constraint',
        );
        $before = LockSnapshot::fromPackages([new Package('acme/lib', '1.4.0.0', '1.4.0')], []);
        $after = LockSnapshot::fromPackages([new Package('acme/lib', self::normalize($toVersion), $toVersion)], []);
        $evaluated = new EvaluatedCandidate($candidate, new SolveResult(SolveStatus::Resolved, $after, ''), LockDiff::between($before, $after), true, null);

        return new Plan([new FindingPlan($finding, [$evaluated], [$evaluated])], ['project' => '/p']);
    }

    private static function normalize(string $pretty): string
    {
        return (new VersionParser())->normalize($pretty);
    }

    public function testTheConstraintDragNoteNamesTheBranchAndTheAlternativeThePlannerCannotSee(): void
    {
        $text = (new TextRenderer())->render($this->dragPlan());

        self::assertStringContainsString('No fix on this branch: No fixed release of acme/lib exists within 1.x.', $text);
        self::assertStringContainsString('Advisory ranges are per branch, so a fix on the locked branch would have been preferred over any major bump; none was published.', $text);
        self::assertStringContainsString('maintained fork or a backport carries the fix under a different package name', $text);
        self::assertStringContainsString('the planner cannot find a fix that is published under another name', $text);
    }

    public function testTheNoteIsAbsentWhenTheFixStaysWithinTheLockedMajor(): void
    {
        // Widening ^1.4 to ^1.5 is drag, but the branch has not run out of releases, so the note
        // about forks and backports would be false.
        $plan = $this->dragPlan('1.9.0');
        $findingPlan = $plan->findings[0];

        self::assertNotNull($findingPlan->constraintDrag(), 'the constraint drag itself is still reported');
        self::assertNull($findingPlan->noFixWithinLockedMajor());
        self::assertStringNotContainsString('No fix on this branch', (new TextRenderer())->render($plan));
    }

    public function testTheNoteReachesTheHtmlReportAlongsideTheDragItself(): void
    {
        $html = (new HtmlRenderer())->render($this->dragPlan());

        self::assertStringContainsString('<strong>Constraint drag:</strong>', $html);
        self::assertStringContainsString('<strong>No fix on this branch:</strong> No fixed release of acme/lib exists within 1.x.', $html);
    }

    /** A fix that rests on a --with constraint, which lives for exactly one command. */
    private function withConstraintPlan(): Plan
    {
        $advisory = new Advisory('PKSA-bbbb', 'acme/lib', (new VersionParser())->parseConstraints('<1.5.0'), 'Bad thing', null, null, 'high');
        $finding = new Finding($advisory, 'acme/lib', '1.4.0.0', '1.4.0', false, true);
        $candidate = new Candidate(
            Strategy::WithDependencies,
            ['acme/parent'],
            Request::UPDATE_LISTED_WITH_TRANSITIVE_DEPS,
            ['acme/lib' => '>=1.5.0'],
            true,
            [],
            'force a fixed version',
        );
        $before = LockSnapshot::fromPackages([new Package('acme/lib', '1.4.0.0', '1.4.0')], []);
        $after = LockSnapshot::fromPackages([new Package('acme/lib', '1.5.0.0', '1.5.0')], []);
        $evaluated = new EvaluatedCandidate($candidate, new SolveResult(SolveStatus::Resolved, $after, ''), LockDiff::between($before, $after), true, null);

        return new Plan([new FindingPlan($finding, [$evaluated], [$evaluated])], ['project' => '/p']);
    }

    public function testAWithConstraintComesWithThePersistentConflictEntry(): void
    {
        $text = (new TextRenderer())->render($this->withConstraintPlan());

        self::assertStringContainsString('Keep the fix', $text);
        self::assertStringContainsString('Add to composer.json, so a later update cannot fall back below it:', $text);
        self::assertStringContainsString('"conflict": {', $text);
        self::assertStringContainsString('"acme/lib": "<1.5.0"', $text);
        self::assertStringContainsString('Composer has no subcommand for this', $text);
    }

    public function testTheConflictEntryReachesTheHtmlReport(): void
    {
        $html = (new HtmlRenderer())->render($this->withConstraintPlan());

        self::assertStringContainsString('<h4>Keep the fix</h4>', $html);
        self::assertStringContainsString('&quot;acme/lib&quot;: &quot;&lt;1.5.0&quot;', $html);
    }

    public function testARecommendationWithoutATemporaryConstraintGetsNoConflictAdvice(): void
    {
        self::assertStringNotContainsString('Keep the fix', (new TextRenderer())->render($this->dragPlan()));
    }

    /** An update that changes what the installed code is allowed to do. */
    private function capabilityPlan(): Plan
    {
        $advisory = new Advisory('PKSA-cccc', 'acme/lib', (new VersionParser())->parseConstraints('<1.5.0'), 'Bad thing', null, null, 'high');
        $finding = new Finding($advisory, 'acme/lib', '1.4.0.0', '1.4.0', false, true);
        $candidate = new Candidate(Strategy::LockRefresh, ['acme/lib'], Request::UPDATE_ONLY_LISTED, [], false, [], 'x');

        $old = new Package('acme/lib', '1.4.0.0', '1.4.0');
        $old->setType('library');
        $old->setDistUrl('https://api.github.com/repos/acme/lib/zipball/aaa');
        $new = new Package('acme/lib', '1.5.0.0', '1.5.0');
        $new->setType('composer-plugin');
        $new->setAutoload(['files' => ['src/bootstrap.php']]);
        $new->setBinaries(['bin/acme']);
        $new->setDistUrl('https://downloads.acme.test/lib-1.5.0.zip');

        $before = LockSnapshot::fromPackages([$old], []);
        $after = LockSnapshot::fromPackages([$new], []);
        $evaluated = new EvaluatedCandidate($candidate, new SolveResult(SolveStatus::Resolved, $after, ''), LockDiff::between($before, $after), true, null);

        return new Plan([new FindingPlan($finding, [$evaluated], [$evaluated])], ['project' => '/p']);
    }

    public function testTheTextReportSaysWhatTheUpgradeLetsThePackageDo(): void
    {
        $text = (new TextRenderer())->render($this->capabilityPlan());

        self::assertStringContainsString('Capability changes: what this update changes about what a package can do.', $text);
        self::assertStringContainsString('acme/lib changes type: library -> composer-plugin', $text);
        self::assertStringContainsString('acme/lib autoloads files on every request: src/bootstrap.php', $text);
        self::assertStringContainsString('acme/lib installs binaries: bin/acme', $text);
        self::assertStringContainsString('acme/lib is fetched from a different dist host: api.github.com -> downloads.acme.test', $text);
    }

    public function testTheCapabilityNotesReachTheHtmlReportAndMarkTheOnesThatRunCode(): void
    {
        $html = (new HtmlRenderer())->render($this->capabilityPlan());

        self::assertStringContainsString('<h4>Capability changes</h4>', $html);
        self::assertStringContainsString('<li class="runs-code">acme/lib changes type: library -&gt; composer-plugin</li>', $html);
        self::assertStringContainsString('<li>acme/lib is fetched from a different dist host: api.github.com -&gt; downloads.acme.test</li>', $html);
    }

    public function testTheJsonDocumentIsUnchangedByAllThree(): void
    {
        foreach ([$this->dragPlan(), $this->withConstraintPlan(), $this->capabilityPlan()] as $plan) {
            $data = json_decode((new JsonRenderer())->render($plan), true, 512, JSON_THROW_ON_ERROR);
            self::assertIsArray($data);
            $encoded = json_encode($data, JSON_THROW_ON_ERROR);
            self::assertStringNotContainsString('conflict', $encoded);
            self::assertStringNotContainsString('capability', $encoded);
            self::assertStringNotContainsString('No fix on this branch', $encoded);
        }
    }
}
