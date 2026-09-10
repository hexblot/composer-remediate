<?php

declare(strict_types=1);

namespace Remediate\Tests\Support;

/**
 * Locates a real Composer phar for tests that must run the actual `composer` binary
 * (REMEDIATE_COMPOSER_BINARY first, then `composer` / `composer.phar` on PATH).
 */
final class ComposerPhar
{
    public static function find(): ?string
    {
        $env = getenv('REMEDIATE_COMPOSER_BINARY');
        $candidates = is_string($env) && $env !== '' ? [$env] : [];
        foreach (explode(PATH_SEPARATOR, (string) getenv('PATH')) as $dir) {
            $candidates[] = rtrim($dir, '/') . '/composer';
            $candidates[] = rtrim($dir, '/') . '/composer.phar';
        }
        foreach ($candidates as $candidate) {
            if (is_file($candidate) && str_contains((string) file_get_contents($candidate, false, null, 0, 4096), 'phar://')) {
                return $candidate;
            }
        }

        return null;
    }
}
