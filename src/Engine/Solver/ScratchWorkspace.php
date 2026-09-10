<?php

declare(strict_types=1);

namespace Remediate\Engine\Solver;

use Remediate\Engine\Project\ProjectContext;

/**
 * Template for scratch copies of a project. Holds the composer.json document (possibly with
 * overrides such as fixture repositories), the lock file contents and an optional auth.json, and
 * materializes a fresh temporary directory per candidate so no candidate can affect another or the
 * user's working tree.
 */
final class ScratchWorkspace
{
    /**
     * @param array<string, mixed> $composerJson
     */
    private function __construct(
        private array $composerJson,
        private readonly string $lockContents,
        private readonly ?string $authJsonContents,
        private readonly string $tempRoot,
    ) {
    }

    public static function fromProject(ProjectContext $context, ?string $tempRoot = null): self
    {
        return self::fromFiles($context->composerJsonPath(), $context->lockPath(), $context->authJsonPath(), $tempRoot);
    }

    public static function fromFiles(string $composerJsonPath, string $lockPath, ?string $authJsonPath = null, ?string $tempRoot = null): self
    {
        $json = self::readJson($composerJsonPath);
        $lock = @file_get_contents($lockPath);
        if ($lock === false) {
            throw new \RuntimeException(sprintf('Cannot read %s', $lockPath));
        }
        $auth = null;
        if ($authJsonPath !== null && is_file($authJsonPath)) {
            $auth = (string) file_get_contents($authJsonPath);
        }

        return new self($json, $lock, $auth, $tempRoot ?? sys_get_temp_dir());
    }

    /**
     * Replace the repositories block entirely (used by fixtures to pin package metadata).
     *
     * @param list<array<string, mixed>> $repositories
     */
    public function overrideRepositories(array $repositories): void
    {
        $this->composerJson['repositories'] = $repositories;
    }

    /**
     * Pins the root package's version. Outside a git checkout Composer cannot guess it and uses
     * "1.0.0+no-version-set", which a dependency's `conflict` with the root can then match; a fixture
     * records the version the project's checkout would have had (a branch name such as dev-develop).
     */
    public function overrideRootVersion(string $version): void
    {
        $this->composerJson['version'] = $version;
    }

    /**
     * @param array<string, string|false> $platform config.platform overrides
     */
    public function overridePlatform(array $platform): void
    {
        $config = $this->composerJson['config'] ?? [];
        if (!is_array($config)) {
            $config = [];
        }
        $config['platform'] = $platform;
        $this->composerJson['config'] = $config;
    }

    /** @return array<string, mixed> */
    public function composerJson(): array
    {
        return $this->composerJson;
    }

    public function materialize(): ScratchProject
    {
        $dir = $this->tempRoot . '/composer-remediate-' . bin2hex(random_bytes(6));
        if (!@mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new \RuntimeException(sprintf('Cannot create scratch directory %s', $dir));
        }
        $project = new ScratchProject($dir, $this->composerJson);
        file_put_contents($dir . '/composer.lock', $this->lockContents);
        if ($this->authJsonContents !== null) {
            file_put_contents($dir . '/auth.json', $this->authJsonContents);
        }
        $project->flush();

        return $project;
    }

    /** @return array<string, mixed> */
    private static function readJson(string $path): array
    {
        $raw = @file_get_contents($path);
        if ($raw === false) {
            throw new \RuntimeException(sprintf('Cannot read %s', $path));
        }
        $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($decoded)) {
            throw new \RuntimeException(sprintf('%s does not contain a JSON object', $path));
        }
        /** @var array<string, mixed> $decoded */
        return $decoded;
    }
}
