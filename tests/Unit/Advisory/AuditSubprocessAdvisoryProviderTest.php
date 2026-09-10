<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Advisory;

use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\AdvisoryLookupFailed;
use Remediate\Engine\Advisory\AuditSubprocessAdvisoryProvider;

/**
 * The `composer audit --locked --format=json` fallback, driven with a stand-in Composer binary so
 * the test controls what the subprocess prints.
 */
final class AuditSubprocessAdvisoryProviderTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        if (PHP_OS_FAMILY === 'Windows') {
            self::markTestSkipped('the stand-in binary is a shell script');
        }
        $this->dir = sys_get_temp_dir() . '/composer-remediate-audit-' . bin2hex(random_bytes(4));
        mkdir($this->dir, 0700, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->dir);
    }

    /** Writes an executable that records its arguments and working directory, then runs $body. */
    private function composer(string $body): string
    {
        $path = $this->dir . '/composer';
        file_put_contents($path, "#!/bin/sh\necho \"\$PWD \$*\" >> \"" . $this->dir . "/calls\"\n" . $body . "\n");
        chmod($path, 0700);

        return $path;
    }

    /** @return list<string> */
    private function calls(): array
    {
        $raw = @file_get_contents($this->dir . '/calls');

        return $raw === false ? [] : array_values(array_filter(explode("\n", $raw)));
    }

    public function testParsesTheAuditOutputAfterAnyLeadingNoiseAndRunsComposerOnce(): void
    {
        $json = json_encode(['advisories' => ['acme/lib' => [[
            'advisoryId' => 'PKSA-9',
            'packageName' => 'acme/lib',
            'affectedVersions' => '<1.0',
            'title' => 'Synthetic',
            'cve' => 'CVE-2026-50001',
            'link' => 'https://example.invalid/pksa-9',
            'reportedAt' => '2026-01-01 00:00:00',
            'sources' => [],
        ]]], 'abandoned' => []], JSON_THROW_ON_ERROR);
        $binary = $this->composer("echo 'Warning: something about the platform'\necho '" . $json . "'");
        $provider = new AuditSubprocessAdvisoryProvider($this->dir, $binary);

        $result = $provider->advisoriesFor(['acme/lib', 'acme/other']);
        self::assertSame(['acme/lib'], array_keys($result));
        self::assertSame('PKSA-9', $result['acme/lib'][0]->id);
        self::assertSame('CVE-2026-50001', $result['acme/lib'][0]->cve);
        self::assertTrue($result['acme/lib'][0]->affectsVersion('0.9.0.0'));

        self::assertSame([], $provider->advisoriesFor(['acme/other']));
        self::assertSame([realpath($this->dir) . ' audit --locked --format=json --no-interaction --no-plugins --no-scripts'], $this->calls(), 'the audit runs once, in the project directory, with the analysed project\'s plugins and scripts disabled');

        self::assertFalse($provider->isComplete(), 'composer audit only knows the advisories of the current lock');
        self::assertSame(sprintf('`%s audit --locked` (current-lock advisories only)', $binary), $provider->describe());
    }

    public function testACommandPrefixRunsComposerThroughAnInterpreter(): void
    {
        $script = $this->dir . '/composer.phar';
        file_put_contents($script, "<?php\nfile_put_contents(__DIR__ . '/calls', getcwd() . ' ' . implode(' ', array_slice(\$argv, 1)) . PHP_EOL, FILE_APPEND);\necho json_encode(['advisories' => []]);\n");
        $provider = new AuditSubprocessAdvisoryProvider($this->dir, [PHP_BINARY, $script]);

        self::assertSame([], $provider->advisoriesFor(['acme/lib']));
        self::assertSame([realpath($this->dir) . ' audit --locked --format=json --no-interaction --no-plugins --no-scripts'], $this->calls());
        self::assertSame(sprintf('`%s %s audit --locked` (current-lock advisories only)', PHP_BINARY, $script), $provider->describe());
    }

    public function testNoJsonInTheOutputIsALookupFailureThatQuotesStderr(): void
    {
        $binary = $this->composer("echo 'boom' >&2\nexit 1");
        $provider = new AuditSubprocessAdvisoryProvider($this->dir, $binary);
        $this->expectException(AdvisoryLookupFailed::class);
        $this->expectExceptionMessage('`composer audit` produced no JSON (exit 1): boom');
        $provider->advisoriesFor(['acme/lib']);
    }

    public function testUndecodableJsonIsALookupFailure(): void
    {
        $binary = $this->composer("echo '{\"advisories\": '");
        $provider = new AuditSubprocessAdvisoryProvider($this->dir, $binary);
        $this->expectException(AdvisoryLookupFailed::class);
        $this->expectExceptionMessage('`composer audit` JSON could not be decoded');
        $provider->advisoriesFor(['acme/lib']);
    }
}
