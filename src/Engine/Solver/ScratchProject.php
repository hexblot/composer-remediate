<?php

declare(strict_types=1);

namespace Remediate\Engine\Solver;

/**
 * A materialized temporary project directory. Root requirement changes are applied here so the
 * candidate can be solved without ever touching the real composer.json.
 */
final class ScratchProject
{
    /**
     * @param array<string, mixed> $composerJson
     */
    public function __construct(
        private readonly string $directory,
        private array $composerJson,
    ) {
    }

    public function directory(): string
    {
        return $this->directory;
    }

    public function composerJsonPath(): string
    {
        return $this->directory . '/composer.json';
    }

    public function changeRootRequirement(string $packageName, string $constraint, bool $dev): void
    {
        $key = $dev ? 'require-dev' : 'require';
        $section = $this->composerJson[$key] ?? [];
        if (!is_array($section)) {
            $section = [];
        }
        $section[$packageName] = $constraint;
        $this->composerJson[$key] = $section;
        $this->flush();
    }

    public function flush(): void
    {
        file_put_contents(
            $this->composerJsonPath(),
            json_encode($this->composerJson, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR) . "\n",
        );
    }

    public function destroy(): void
    {
        self::removeDirectory($this->directory);
    }

    private static function removeDirectory(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $items = scandir($dir);
        if ($items === false) {
            return;
        }
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir . '/' . $item;
            if (is_dir($path) && !is_link($path)) {
                self::removeDirectory($path);
            } else {
                @unlink($path);
            }
        }
        @rmdir($dir);
    }
}
