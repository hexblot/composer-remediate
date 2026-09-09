<?php

declare(strict_types=1);

namespace Remediate\Output;

/**
 * Line numbers of package entries in composer.lock, so SARIF results can point at the exact line.
 */
final class LockLineIndex
{
    /**
     * @param array<string, int> $lines package name => 1-based line of its "name" entry
     */
    public function __construct(private readonly array $lines = [], public readonly string $relativePath = 'composer.lock')
    {
    }

    public static function empty(): self
    {
        return new self();
    }

    public static function fromFile(string $lockPath, string $relativePath = 'composer.lock'): self
    {
        $contents = @file_get_contents($lockPath);
        if ($contents === false) {
            return self::empty();
        }
        $lines = [];
        foreach (explode("\n", $contents) as $index => $line) {
            if (preg_match('{^\s*"name":\s*"([a-z0-9_.-]+/[a-z0-9_.-]+)"}i', $line, $m) === 1) {
                $lines[strtolower($m[1])] ??= $index + 1;
            }
        }

        return new self($lines, $relativePath);
    }

    public function lineOf(string $packageName): ?int
    {
        return $this->lines[strtolower($packageName)] ?? null;
    }
}
