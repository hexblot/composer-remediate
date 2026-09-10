<?php

declare(strict_types=1);

namespace Remediate\Tests\Integration;

use PHPUnit\Framework\TestCase;
use Remediate\Tests\Support\ComposerPhar;
use Symfony\Component\Process\Process;

/**
 * The standalone binary's promise: nothing from the analysed project executes. Installed as a
 * project dependency, the binary sits under <project>/vendor/hexblot/composer-remediate/bin, right
 * next to a vendor/autoload.php whose autoload.files would run project code if it were included.
 */
final class EntryPointTest extends TestCase
{
    private string $project;

    protected function setUp(): void
    {
        $this->project = sys_get_temp_dir() . '/composer-remediate-entry-' . bin2hex(random_bytes(4));
        $plugin = $this->project . '/vendor/hexblot/composer-remediate';
        mkdir($plugin . '/bin', 0700, true);
        copy(dirname(__DIR__, 2) . '/bin/composer-remediate', $plugin . '/bin/composer-remediate');
        symlink(dirname(__DIR__, 2) . '/src', $plugin . '/src');
        // A legitimate-looking project autoloader with an autoload.files probe.
        file_put_contents($this->project . '/vendor/autoload.php', "<?php\nfile_put_contents(__DIR__ . '/../PROBE_EXECUTED', 'project code ran');\nreturn new stdClass();\n");
        file_put_contents($this->project . '/composer.json', '{"name":"victim/project","require":{}}');
        file_put_contents($this->project . '/composer.lock', '{"packages":[],"packages-dev":[],"content-hash":"x"}');
    }

    protected function tearDown(): void
    {
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->project, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $file) {
            $file->isDir() ? @rmdir($file->getPathname()) : @unlink($file->getPathname());
        }
        @rmdir($this->project);
    }

    private function composerPhar(): string
    {
        return ComposerPhar::find() ?? self::markTestSkipped('no Composer phar available to boot the standalone binary');
    }

    /** @param list<string> $args */
    private function runBinary(array $args): Process
    {
        $process = new Process([PHP_BINARY, $this->project . '/vendor/hexblot/composer-remediate/bin/composer-remediate', ...$args], $this->project, [
            'REMEDIATE_COMPOSER_BINARY' => $this->composerPhar(),
            'COMPOSER_HOME' => (string) getenv('COMPOSER_HOME'),
            'COMPOSER_CACHE_DIR' => (string) getenv('COMPOSER_CACHE_DIR'),
        ], null, 120);
        $process->run();

        return $process;
    }

    public function testHelpDoesNotExecuteProjectAutoloadFiles(): void
    {
        $process = $this->runBinary(['--help']);
        self::assertSame(0, $process->getExitCode(), $process->getOutput() . $process->getErrorOutput());
        self::assertStringContainsString('least invasive Composer-verified upgrade', $process->getOutput());
        self::assertFileDoesNotExist($this->project . '/PROBE_EXECUTED', 'the analysed project\'s vendor/autoload.php ran');
    }

    public function testPlanningACleanProjectOfflineDoesNotExecuteProjectCode(): void
    {
        file_put_contents($this->project . '/advisories.json', '{"advisories":{}}');
        $process = $this->runBinary(['--offline', '--advisories-file=advisories.json', '--format=json']);
        self::assertSame(0, $process->getExitCode(), $process->getOutput() . $process->getErrorOutput());
        $report = json_decode($process->getOutput(), true);
        self::assertIsArray($report);
        self::assertSame(0, $report['exit_code']);
        self::assertFileDoesNotExist($this->project . '/PROBE_EXECUTED');
    }
}
