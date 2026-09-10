<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory;

use Symfony\Component\Process\Process;

/**
 * Fallback adapter: runs `composer audit --locked --format=json` in the project directory. It only
 * returns advisories matching the *current* lock, so it cannot prove that a candidate lock is free
 * of advisories the current lock does not have. The planner warns when this provider is in use.
 *
 * The child runs with `--no-plugins --no-scripts`: a subprocess does not inherit the parent's
 * switches, and without them Composer would activate the analysed project's allowed plugins, which
 * is project code (see docs/design-decisions.md, the plugin boundary).
 */
final class AuditSubprocessAdvisoryProvider implements AdvisoryProvider
{
    /** @var array<string, list<Advisory>>|null */
    private ?array $advisories = null;

    /** @var list<string> */
    private readonly array $composerCommand;

    /**
     * @param list<string>|string $composer the Composer executable, or the command prefix that runs it (e.g. [php, composer.phar])
     */
    public function __construct(
        private readonly string $projectDirectory,
        array|string $composer = 'composer',
        private readonly PackagistAdvisoryJsonParser $parser = new PackagistAdvisoryJsonParser(),
        private readonly float $timeout = 120.0,
    ) {
        $this->composerCommand = is_string($composer) ? [$composer] : $composer;
    }

    public function advisoriesFor(array $packageNames): array
    {
        $all = $this->load();
        $wanted = [];
        foreach ($packageNames as $name) {
            $wanted[strtolower($name)] = true;
        }

        return array_intersect_key($all, $wanted);
    }

    public function describe(): string
    {
        return sprintf('`%s audit --locked` (current-lock advisories only)', implode(' ', $this->composerCommand));
    }

    public function isComplete(): bool
    {
        return false;
    }

    /** @return array<string, list<Advisory>> */
    private function load(): array
    {
        if ($this->advisories !== null) {
            return $this->advisories;
        }
        $process = new Process(
            [...$this->composerCommand, 'audit', '--locked', '--format=json', '--no-interaction', '--no-plugins', '--no-scripts'],
            $this->projectDirectory,
            ['COMPOSER_NO_INTERACTION' => '1'],
            null,
            $this->timeout,
        );
        $process->run();
        $stdout = $process->getOutput();
        $start = strpos($stdout, '{');
        if ($start === false) {
            throw new AdvisoryLookupFailed(sprintf('`composer audit` produced no JSON (exit %d): %s', $process->getExitCode() ?? -1, trim($process->getErrorOutput())));
        }
        try {
            $decoded = json_decode(substr($stdout, $start), true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new AdvisoryLookupFailed('`composer audit` JSON could not be decoded: ' . $e->getMessage(), 0, $e);
        }
        if (!is_array($decoded)) {
            throw new AdvisoryLookupFailed('`composer audit` JSON is not an object.');
        }
        /** @var array<string, mixed> $decoded */
        return $this->advisories = $this->parser->parseDocument($decoded);
    }
}
