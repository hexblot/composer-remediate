<?php

declare(strict_types=1);

namespace Remediate\Tests\Support;

use Composer\Console\Application;
use Composer\Util\Platform;
use Remediate\Command\CommandProvider;
use Remediate\Engine\Solver\ScratchProject;
use Remediate\Engine\Solver\ScratchWorkspace;
use Symfony\Component\Console\Tester\ApplicationTester;

/**
 * Runs the plugin's commands through Composer's console application, the way `composer remediate`
 * does, against a scratch copy of a fixture whose repositories point at the fixture's frozen package
 * metadata. Composer's application changes process state on every run (error handler, working
 * directory, environment); each run puts it back so tests stay independent of each other.
 */
final class CommandRunner
{
    /** @var list<ScratchProject> */
    private array $projects = [];

    /**
     * Materializes a fixture as an independent project directory (composer.json with the fixture's
     * static repository in place of Packagist, plus its composer.lock) and returns the path.
     */
    public function project(string $fixtureDir): string
    {
        $repo = realpath($fixtureDir . '/repo');
        if ($repo === false || !is_file($repo . '/packages.json')) {
            throw new \RuntimeException("Fixture $fixtureDir needs a plain repo/packages.json to be run through the command layer");
        }
        $workspace = ScratchWorkspace::fromFiles($fixtureDir . '/composer.fixture.json', $fixtureDir . '/composer.fixture.lock');
        $workspace->overrideRepositories([
            ['type' => 'composer', 'url' => 'file://' . $repo],
            ['packagist.org' => false],
        ]);
        $project = $workspace->materialize();
        $this->projects[] = $project;

        return $project->directory();
    }

    /**
     * Rewrites a project's composer.json through a callback (to add `extra` settings and the like).
     *
     * @param callable(array<string, mixed>): array<string, mixed> $edit
     */
    public static function editComposerJson(string $projectDir, callable $edit): void
    {
        $path = $projectDir . '/composer.json';
        $decoded = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($decoded)) {
            throw new \RuntimeException("$path does not contain a JSON object");
        }
        /** @var array<string, mixed> $decoded */
        file_put_contents($path, json_encode($edit($decoded), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n");
    }

    /**
     * Runs one command in the given project directory. $input is the array shape Symfony's ArrayInput
     * takes: ['command' => 'remediate', '--format' => 'json', '--output' => ['a.html']].
     *
     * @param array<string, mixed> $input
     */
    public function run(array $input, string $projectDir): CommandResult
    {
        $application = new Application();
        $application->setAutoExit(false);
        $application->setCatchExceptions(false);
        $application->addCommands((new CommandProvider())->getCommands());
        $tester = new ApplicationTester($application);

        $cwd = getcwd();
        $network = Platform::getEnv('COMPOSER_DISABLE_NETWORK');
        try {
            $exit = $tester->run(
                $input + ['--working-dir' => $projectDir, '--no-plugins' => true],
                ['capture_stderr_separately' => true, 'interactive' => false, 'decorated' => false],
            );
        } finally {
            // Composer's Application registers its own error handler on top of PHPUnit's and never
            // removes it; --offline exports COMPOSER_DISABLE_NETWORK for the rest of the process.
            restore_error_handler();
            if (is_string($cwd)) {
                chdir($cwd);
            }
            if ($network === false) {
                Platform::clearEnv('COMPOSER_DISABLE_NETWORK');
            } else {
                Platform::putEnv('COMPOSER_DISABLE_NETWORK', $network);
            }
        }

        return new CommandResult($exit, $tester->getDisplay(), $tester->getErrorOutput());
    }

    public function cleanup(): void
    {
        foreach ($this->projects as $project) {
            $project->destroy();
        }
        $this->projects = [];
    }
}
