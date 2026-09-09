<?php

declare(strict_types=1);

namespace Remediate\Tests\Support;

use Composer\IO\NullIO;
use Remediate\Engine\Advisory\JsonFileAdvisoryProvider;
use Remediate\Engine\Candidate\CandidateGenerator;
use Remediate\Engine\Plan\Plan;
use Remediate\Engine\Planner;
use Remediate\Engine\Project\ProjectContext;
use Remediate\Engine\Solver\InProcessSolver;
use Remediate\Engine\Solver\ScratchProject;
use Remediate\Engine\Solver\ScratchWorkspace;

/**
 * Runs the planner against a fixture directory with its frozen repository and advisory snapshot,
 * exactly as documented in docs/fixtures.md.
 */
final class FixtureRunner
{
    public const FIXTURE_ROOT = __DIR__ . '/../Fixture';

    /** @var list<ScratchProject> */
    private array $materialized = [];

    /**
     * @return array<string, mixed>
     */
    public static function expected(string $fixtureDir): array
    {
        $raw = file_get_contents($fixtureDir . '/expected.json');
        if ($raw === false) {
            throw new \RuntimeException("Missing expected.json in $fixtureDir");
        }
        $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($decoded)) {
            throw new \RuntimeException("expected.json in $fixtureDir must be an object");
        }
        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /**
     * @return list<string> absolute fixture directories that contain an expected.json
     */
    public static function all(): array
    {
        $dirs = glob(self::FIXTURE_ROOT . '/*/expected.json') ?: [];
        sort($dirs);

        return array_map(static fn (string $f): string => dirname($f), $dirs);
    }

    public function workspace(string $fixtureDir): ScratchWorkspace
    {
        $expected = self::expected($fixtureDir);
        $workspace = ScratchWorkspace::fromFiles($fixtureDir . '/composer.json', $fixtureDir . '/composer.lock');
        $repoDir = realpath($fixtureDir . '/repo');
        if ($repoDir === false) {
            throw new \RuntimeException("Fixture $fixtureDir has no repo/ directory");
        }
        $workspace->overrideRepositories([
            ['type' => 'composer', 'url' => 'file://' . $repoDir],
            ['packagist.org' => false],
        ]);
        $platform = $expected['platform'] ?? [];
        if (is_array($platform)) {
            /** @var array<string, string|false> $platform */
            $workspace->overridePlatform($platform);
        }

        return $workspace;
    }

    public function run(string $fixtureDir, bool $allowDirectRequire = false): Plan
    {
        $workspace = $this->workspace($fixtureDir);
        $project = $workspace->materialize();
        $this->materialized[] = $project;
        $context = ProjectContext::fromDirectory($project->directory(), new NullIO());

        $planner = new Planner(
            new JsonFileAdvisoryProvider($fixtureDir . '/advisories.json'),
            new InProcessSolver(),
            new CandidateGenerator(allowDirectRequire: $allowDirectRequire),
        );

        return $planner->plan($context, $workspace);
    }

    public function cleanup(): void
    {
        foreach ($this->materialized as $project) {
            $project->destroy();
        }
        $this->materialized = [];
    }
}
