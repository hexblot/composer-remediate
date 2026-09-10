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
    /**
     * Fixture manifests are stored as composer.fixture.json / composer.fixture.lock: GitHub's dependency
     * graph parses every composer.json and composer.lock in a repository whatever the directory, and these
     * historical locks are vulnerable on purpose.
     */
    public const FIXTURE_ROOT = __DIR__ . '/../Fixture/third-party';

    /** @var list<ScratchProject> */
    private array $materialized = [];

    /** @var list<string> temporary repository directories to remove */
    private array $repoDirs = [];

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
        $workspace = ScratchWorkspace::fromFiles($fixtureDir . '/composer.fixture.json', $fixtureDir . '/composer.fixture.lock');
        $repoDir = $this->repositoryDirectory($fixtureDir);
        $workspace->overrideRepositories([
            ['type' => 'composer', 'url' => 'file://' . $repoDir],
            ['packagist.org' => false],
        ]);
        $platform = $expected['platform'] ?? [];
        if (is_array($platform)) {
            /** @var array<string, string|false> $platform */
            $workspace->overridePlatform($platform);
        }
        if (is_string($expected['root_version'] ?? null) && $expected['root_version'] !== '') {
            $workspace->overrideRootVersion($expected['root_version']);
        }

        return $workspace;
    }

    /**
     * @param callable(string): void|null $progress
     */
    public function run(string $fixtureDir, bool $allowDirectRequire = false, ?callable $progress = null): Plan
    {
        $workspace = $this->workspace($fixtureDir);
        $project = $workspace->materialize();
        $this->materialized[] = $project;
        $context = ProjectContext::fromDirectory($project->directory(), new NullIO());

        $planner = new Planner(
            new JsonFileAdvisoryProvider($fixtureDir . '/advisories.json'),
            new InProcessSolver(),
            new CandidateGenerator(allowDirectRequire: $allowDirectRequire),
            true,
            10,
            $progress,
        );

        return $planner->plan($context, $workspace);
    }

    public function cleanup(): void
    {
        foreach ($this->materialized as $project) {
            $project->destroy();
        }
        $this->materialized = [];
        foreach ($this->repoDirs as $dir) {
            @unlink($dir . '/packages.json');
            @rmdir($dir);
        }
        $this->repoDirs = [];
    }

    /**
     * Fixtures store the static repository gzip-compressed (repo/packages.json.gz) to keep the git
     * checkout small; Composer needs the plain file, so it is inflated into a temporary directory.
     * A plain repo/packages.json is used as-is when present.
     */
    private function repositoryDirectory(string $fixtureDir): string
    {
        $plain = realpath($fixtureDir . '/repo');
        if ($plain !== false && is_file($plain . '/packages.json')) {
            return $plain;
        }
        $gz = $fixtureDir . '/repo/packages.json.gz';
        if (!is_file($gz)) {
            throw new \RuntimeException("Fixture $fixtureDir has neither repo/packages.json nor repo/packages.json.gz");
        }
        $dir = sys_get_temp_dir() . '/composer-remediate-fixture-repo-' . bin2hex(random_bytes(6));
        if (!@mkdir($dir, 0700, true)) {
            throw new \RuntimeException("Cannot create $dir");
        }
        $data = gzdecode((string) file_get_contents($gz));
        if ($data === false) {
            throw new \RuntimeException("Cannot decompress $gz");
        }
        file_put_contents($dir . '/packages.json', $data);
        $this->repoDirs[] = $dir;

        return $dir;
    }
}
