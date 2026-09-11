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
use Remediate\Engine\Plan\BaselineFile;
use Remediate\Engine\Plan\EvaluatedCandidate;
use Remediate\Engine\Plan\FindingPlan;
use Remediate\Engine\Plan\Plan;
use Remediate\Engine\Solver\LockDiff;
use Remediate\Engine\Solver\ReleaseAgeGuard;
use Remediate\Engine\Solver\SolveResult;
use Remediate\Engine\Solver\SolveStatus;
use Remediate\Output\GitLabRenderer;
use Remediate\Output\ReportFormat;

final class GitLabRendererTest extends TestCase
{
    private function plan(): Plan
    {
        $parser = new VersionParser();
        $advisory = new Advisory('PKSA-aaaa', 'acme/lib', $parser->parseConstraints('<2.0.0'), 'Bad thing', 'CVE-2026-1', 'https://example.test/a', 'high', null, [['name' => 'GitHub', 'remoteId' => 'GHSA-xxxx-yyyy-zzzz']]);
        $finding = new Finding($advisory, 'acme/lib', '1.4.0.0', '1.4.0', false, false);
        // fix requires widening the parent's root constraint: constraint drag
        $candidate = new Candidate(Strategy::RootConstraintWiden, ['acme/parent'], Request::UPDATE_LISTED_WITH_TRANSITIVE_DEPS, [], true, ['acme/parent' => new RootConstraintChange('acme/parent', '^1.0', '^2.0', false)], 'x');
        $before = LockSnapshot::fromPackages([new Package('acme/lib', '1.4.0.0', '1.4.0'), new Package('acme/parent', '1.0.0.0', '1.0.0')], []);
        $after = LockSnapshot::fromPackages([new Package('acme/lib', '2.0.0.0', '2.0.0'), new Package('acme/parent', '2.0.0.0', '2.0.0')], []);
        $evaluated = new EvaluatedCandidate($candidate, new SolveResult(SolveStatus::Resolved, $after, ''), LockDiff::between($before, $after), true, null);

        return new Plan([new FindingPlan($finding, [$evaluated], [$evaluated])], ['engine_version' => '0.4.0-test'], [], null, null, [['name' => 'acme/lib', 'version' => '1.4.0', 'dev' => false]]);
    }

    public function testReportStructure(): void
    {
        $report = json_decode((new GitLabRenderer(true, '2026-01-01T00:00:00', '2026-01-01T00:00:00'))->render($this->plan()), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($report);
        self::assertSame(GitLabRenderer::SCHEMA_VERSION, $report['version']);
        self::assertSame('dependency_scanning', $report['scan']['type']);
        self::assertSame('composer', $report['dependency_files'][0]['package_manager']);
        self::assertCount(1, $report['vulnerabilities']);
        $v = $report['vulnerabilities'][0];
        self::assertSame(GitLabRenderer::uuid('PKSA-aaaa@acme/lib'), $v['id']);
        self::assertSame('High', $v['severity']);
        self::assertStringContainsString('composer require --no-update acme/parent:^2.0 && composer update acme/parent -W -m', $v['solution']);
        self::assertSame(['cve', 'ghsa', 'packagist_advisory'], array_column($v['identifiers'], 'type'));
        self::assertSame('composer.lock', $v['location']['file']);
        self::assertSame('acme/lib', $v['location']['dependency']['package']['name']);
        self::assertMatchesRegularExpression('{^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$}', $v['id']);
    }

    public function testAScanThatCouldNotEstablishCoverageIsAFailedScanNotAnEmptyOne(): void
    {
        $gap = 'Coverage gap: Upstream record GHSA-bad for acme/lib could not be interpreted at database build (unparsable); acme/lib is treated as unaffected by that record.';
        $plan = new Plan([], ['engine_version' => 'test'], [$gap], null, null, [['name' => 'acme/lib', 'version' => '1.4.0', 'dev' => false]], [], [$gap]);
        self::assertSame(Plan::EXIT_ADVISORIES_UNAVAILABLE, $plan->exitCode());

        $report = json_decode((new GitLabRenderer(true))->render($plan), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($report);
        self::assertSame([], $report['vulnerabilities']);
        self::assertSame('failure', $report['scan']['status'], 'an empty list marked success would read as clean');
        self::assertSame(['warn', 'warn'], array_column($report['scan']['messages'], 'level'));
        self::assertStringContainsString('advisory data unavailable or incomplete for this lock (exit 4)', $report['scan']['messages'][0]['value']);
        self::assertSame($gap, $report['scan']['messages'][1]['value'], 'the coverage warning is carried, not dropped');

        $accepted = json_decode((new GitLabRenderer(true))->render($plan->withAcceptedCoverageGaps()), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($accepted);
        self::assertSame('success', $accepted['scan']['status']);
        self::assertSame([$gap], array_column($accepted['scan']['messages'], 'value'), 'accepted gaps are still disclosed');

        $normal = json_decode((new GitLabRenderer(true))->render($this->plan()), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($normal);
        self::assertSame('success', $normal['scan']['status']);
        self::assertSame([], $normal['scan']['messages']);
    }

    public function testOutputSpecRecognisesGitLabReports(): void
    {
        self::assertSame([ReportFormat::GitLab, 'gl-dependency-scanning-report.json'], ReportFormat::parseOutputSpec('gl-dependency-scanning-report.json'));
        self::assertSame([ReportFormat::GitLab, 'build/gl-dependency-scanning-report.json'], ReportFormat::parseOutputSpec('build/gl-dependency-scanning-report.json'));
        self::assertSame([ReportFormat::GitLab, 'x.json'], ReportFormat::parseOutputSpec('gitlab:x.json'));
    }

    public function testConstraintDragIsExplained(): void
    {
        $fp = $this->plan()->findings[0];
        self::assertNotNull($fp->constraintDrag());
        self::assertStringContainsString('acme/parent ^1.0', $fp->constraintDrag());
        self::assertStringContainsString('widens it to ^2.0', $fp->constraintDrag());
    }

    public function testBaselineExcludesFindingsFromTheExitCode(): void
    {
        $plan = $this->plan();
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $plan->exitCode());
        $baselined = $plan->withBaseline(['PKSA-aaaa@acme/lib']);
        self::assertTrue($baselined->isBaselined($baselined->findings[0]));
        self::assertSame(Plan::EXIT_CLEAN, $baselined->exitCode());
        self::assertSame([], $baselined->gated());

        $path = sys_get_temp_dir() . '/remediate-baseline-' . bin2hex(random_bytes(4)) . '.json';
        try {
            BaselineFile::write($path, $plan);
            self::assertSame(['PKSA-aaaa@acme/lib'], BaselineFile::read($path));
        } finally {
            @unlink($path);
        }
    }

    public function testReleaseAgeGuardRejectsYoungReleases(): void
    {
        $now = new \DateTimeImmutable('2026-06-10T00:00:00Z');
        $old = new Package('acme/old', '1.1.0.0', '1.1.0');
        $old->setReleaseDate(new \DateTime('2026-01-01T00:00:00Z'));
        $young = new Package('acme/young', '1.1.0.0', '1.1.0');
        $young->setReleaseDate(new \DateTime('2026-06-08T00:00:00Z'));
        $unknown = new Package('acme/unknown', '1.1.0.0', '1.1.0');
        $before = LockSnapshot::fromPackages([new Package('acme/old', '1.0.0.0', '1.0.0'), new Package('acme/young', '1.0.0.0', '1.0.0'), new Package('acme/unknown', '1.0.0.0', '1.0.0')], []);
        $after = LockSnapshot::fromPackages([$old, $young, $unknown], []);
        $diff = LockDiff::between($before, $after);

        $tooYoung = (new ReleaseAgeGuard(7, $now))->tooYoung($diff, $after);
        self::assertCount(2, $tooYoung, 'the young release and the one whose age cannot be proven');
        self::assertStringContainsString('acme/unknown 1.1.0 (release date unknown)', $tooYoung[0]);
        self::assertStringContainsString('acme/young 1.1.0 (released 2026-06-08, 2 days ago)', $tooYoung[1]);
        self::assertSame(['acme/unknown 1.1.0 (release date unknown)'], (new ReleaseAgeGuard(1, $now))->tooYoung($diff, $after));
        self::assertSame([], (new ReleaseAgeGuard(0, $now))->tooYoung($diff, $after));
    }
}
