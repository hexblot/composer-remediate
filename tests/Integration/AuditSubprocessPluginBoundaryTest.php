<?php

declare(strict_types=1);

namespace Remediate\Tests\Integration;

use Composer\Util\Platform;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\AdvisoryLookupFailed;
use Remediate\Engine\Advisory\AuditSubprocessAdvisoryProvider;
use Remediate\Tests\Support\ComposerPhar;
use Symfony\Component\Process\Process;

/**
 * The `composer audit` fallback must keep the plugin boundary: a child process does not inherit the
 * parent's --no-plugins, so the adapter has to pass it itself. Proven with a real Composer and a
 * real installed plugin the project allows, whose activate() leaves a marker.
 */
final class AuditSubprocessPluginBoundaryTest extends TestCase
{
    private string $project;
    private string $phar;

    protected function setUp(): void
    {
        $phar = ComposerPhar::find();
        if ($phar === null) {
            self::markTestSkipped('no Composer phar available to run composer audit');
        }
        $this->phar = $phar;
        $this->project = sys_get_temp_dir() . '/composer-remediate-plugin-boundary-' . bin2hex(random_bytes(4));
        mkdir($this->project . '/probe-plugin/src', 0700, true);
        file_put_contents($this->project . '/probe-plugin/composer.json', json_encode([
            'name' => 'acme/probe-plugin',
            'type' => 'composer-plugin',
            'version' => '1.0.0',
            'require' => ['composer-plugin-api' => '^2.0'],
            'autoload' => ['psr-4' => ['Acme\\Probe\\' => 'src/']],
            'extra' => ['class' => 'Acme\\Probe\\Plugin'],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
        file_put_contents($this->project . '/probe-plugin/src/Plugin.php', <<<'PHP'
<?php
namespace Acme\Probe;

use Composer\Composer;
use Composer\IO\IOInterface;
use Composer\Plugin\PluginInterface;

final class Plugin implements PluginInterface
{
    public function activate(Composer $composer, IOInterface $io): void
    {
        file_put_contents(getcwd() . '/PROBE_EXECUTED', 'project plugin ran');
    }

    public function deactivate(Composer $composer, IOInterface $io): void
    {
    }

    public function uninstall(Composer $composer, IOInterface $io): void
    {
    }
}
PHP);
        file_put_contents($this->project . '/composer.json', json_encode([
            'name' => 'victim/project',
            'require' => ['acme/probe-plugin' => '*'],
            'repositories' => [['type' => 'path', 'url' => './probe-plugin'], ['packagist.org' => false]],
            'config' => ['allow-plugins' => ['acme/probe-plugin' => true]],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));

        $install = $this->composer(['install', '--no-plugins', '--no-scripts', '--no-progress']);
        self::assertSame(0, $install->getExitCode(), $install->getOutput() . $install->getErrorOutput());
        self::assertFileExists($this->project . '/composer.lock');
        self::assertFileDoesNotExist($this->project . '/PROBE_EXECUTED', 'the install itself ran without plugins');
    }

    protected function tearDown(): void
    {
        if (!isset($this->project) || !is_dir($this->project)) {
            return;
        }
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->project, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $file) {
            $file->isDir() || $file->isLink() ? @rmdir($file->getPathname()) || @unlink($file->getPathname()) : @unlink($file->getPathname());
        }
        @rmdir($this->project);
    }

    /** @param list<string> $args */
    private function composer(array $args): Process
    {
        $process = new Process([PHP_BINARY, $this->phar, ...$args, '--no-interaction'], $this->project, [
            'COMPOSER_HOME' => Platform::getEnv('COMPOSER_HOME'),
            'COMPOSER_CACHE_DIR' => Platform::getEnv('COMPOSER_CACHE_DIR'),
        ], null, 120);
        $process->run();

        return $process;
    }

    public function testTheAuditChildDoesNotActivateTheProjectsPlugins(): void
    {
        // Control: a plain `composer audit` in this project does activate the allowed plugin.
        $this->composer(['audit', '--locked', '--format=json']);
        self::assertFileExists($this->project . '/PROBE_EXECUTED', 'the control run proves the probe plugin is installed, allowed and active');
        unlink($this->project . '/PROBE_EXECUTED');

        $provider = new AuditSubprocessAdvisoryProvider($this->project, [PHP_BINARY, $this->phar]);
        try {
            $provider->advisoriesFor(['acme/probe-plugin']);
        } catch (AdvisoryLookupFailed) {
            // With packagist.org disabled some Composer releases refuse to audit; the boundary must hold either way.
        }
        self::assertFileDoesNotExist($this->project . '/PROBE_EXECUTED', 'the fallback adapter ran the analysed project\'s plugin');
    }
}
