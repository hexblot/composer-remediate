<?php

declare(strict_types=1);

namespace Remediate\Tests\Integration;

use Composer\DependencyResolver\Request;
use Composer\Util\Platform;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Candidate\Candidate;
use Remediate\Engine\Candidate\Strategy;
use Remediate\Engine\Solver\SolveStatus;
use Remediate\Engine\Solver\SubprocessSolver;
use Remediate\Tests\Support\FixtureRunner;

/**
 * The real subprocess solver against the synthetic fixture: it must solve the scratch copy and
 * only the scratch copy, whatever the COMPOSER environment variable of the parent process says.
 */
final class SubprocessSolverTest extends TestCase
{
    private FixtureRunner $runner;

    private ?string $previousComposerEnv = null;

    /** @var list<string> */
    private array $cleanup = [];

    protected function setUp(): void
    {
        $this->runner = new FixtureRunner();
        $env = Platform::getEnv('COMPOSER');
        $this->previousComposerEnv = is_string($env) ? $env : null;
    }

    protected function tearDown(): void
    {
        $this->runner->cleanup();
        if ($this->previousComposerEnv === null) {
            Platform::clearEnv('COMPOSER');
        } else {
            Platform::putEnv('COMPOSER', $this->previousComposerEnv);
        }
        foreach ($this->cleanup as $path) {
            @unlink($path);
        }
    }

    public function testSolvesTheScratchCopyEvenWhenComposerEnvNamesAnotherManifest(): void
    {
        $fixture = FixtureRunner::FIXTURE_ROOT . '/synthetic-transitive-parent';
        $workspace = $this->runner->workspace($fixture);

        // The analysed project's manifest under a custom name, as COMPOSER=alternate.json would set it.
        $dir = sys_get_temp_dir() . '/composer-remediate-alt-' . bin2hex(random_bytes(4));
        mkdir($dir, 0700);
        $manifest = $dir . '/alternate.json';
        $lock = $dir . '/alternate.lock';
        copy($fixture . '/composer.json', $manifest);
        copy($fixture . '/composer.lock', $lock);
        array_push($this->cleanup, $manifest, $lock, $dir);
        $lockBefore = (string) file_get_contents($lock);
        Platform::putEnv('COMPOSER', $manifest);

        $solver = new SubprocessSolver([PHP_BINARY, dirname(__DIR__, 2) . '/vendor/bin/composer']);
        $candidate = new Candidate(Strategy::ParentUpdate, ['acme/app-framework'], Request::UPDATE_LISTED_WITH_TRANSITIVE_DEPS, ['acme/vuln-lib' => '>=1.1.0'], false, [], 'x');
        $result = $solver->solve($candidate, $workspace);

        self::assertSame(SolveStatus::Resolved, $result->status, $result->output);
        self::assertNotNull($result->after);
        self::assertSame('1.1.1', $result->after->get('acme/vuln-lib')?->getPrettyVersion(), 'the result reflects the scratch solve');
        self::assertStringEqualsFile($lock, $lockBefore, 'the analysed project\'s lock file must not change');
        @rmdir($dir);
    }

    public function testConflictsAreClassified(): void
    {
        $workspace = $this->runner->workspace(FixtureRunner::FIXTURE_ROOT . '/synthetic-transitive-parent');
        $solver = new SubprocessSolver([PHP_BINARY, dirname(__DIR__, 2) . '/vendor/bin/composer']);
        // acme/vuln-lib alone cannot reach 1.1 under the parent's ~1.0.0 pin.
        $candidate = new Candidate(Strategy::WithDependencies, ['acme/vuln-lib'], Request::UPDATE_LISTED_WITH_TRANSITIVE_DEPS_NO_ROOT_REQUIRE, ['acme/vuln-lib' => '>=1.1.0'], false, [], 'x');
        $result = $solver->solve($candidate, $workspace);
        self::assertSame(SolveStatus::Conflict, $result->status, $result->output);
        self::assertTrue($solver->supportsMinimalChanges());
    }
}
