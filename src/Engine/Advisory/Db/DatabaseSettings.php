<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db;

use Composer\Composer;

/**
 * Where the advisory database lives and where it comes from, as three independent settings, each
 * resolved as option, then environment variable, then `extra.remediate` in composer.json, then the
 * default. Giving one never changes another: a project that points at its own mirror keeps the default
 * path, a project that moves the path keeps the default source.
 *
 * - path: the file the tool keeps current and reads (default: `<composer cache dir>/remediate/advisories.sqlite`)
 * - sources: https URLs tried in order to confirm the file is current or to replace it (default: the
 *   database this project publishes); `composer` or `none` means no database at all, so advisories come
 *   from the configured repositories as `composer audit` would; a single local path means "read this
 *   file as it is" (the pre-0.7 meaning of --database-location)
 * - maxAge: how old a copy may be when it cannot be confirmed current, before the run fails instead of
 *   warning (default: no limit)
 */
final class DatabaseSettings
{
    public const DEFAULT_SOURCE = 'https://github.com/hexblot/composer-remediate/releases/download/advisory-db-latest/advisories.sqlite';
    public const ENV_LOCATION = 'REMEDIATE_DATABASE';
    public const ENV_PATH = 'REMEDIATE_DATABASE_PATH';
    public const ENV_MAX_AGE = 'REMEDIATE_DATABASE_MAX_AGE';
    public const NO_DATABASE = ['composer', 'none'];

    /**
     * @param list<string> $sources
     */
    private function __construct(
        public readonly string $path,
        public readonly array $sources,
        public readonly ?int $maxAgeSeconds,
        public readonly bool $pathConfigured,
        public readonly bool $sourcesConfigured,
    ) {
    }

    /**
     * @param string|null $location   --database-location: URL(s), `composer`/`none`, or one local path
     * @param string|null $path       --database-path
     * @param string|null $maxAge     --database-max-age: hours, or a number with an h or d suffix
     * @param bool        $noDatabase --no-database
     *
     * @throws \InvalidArgumentException for a max age that is not a duration
     */
    public static function resolve(Composer $composer, string $defaultPath, ?string $location, ?string $path, ?string $maxAge, bool $noDatabase = false): self
    {
        $extra = $composer->getPackage()->getExtra();
        $remediate = isset($extra['remediate']) && is_array($extra['remediate']) ? $extra['remediate'] : [];

        $locationValue = $noDatabase ? 'none' : self::first($location, self::ENV_LOCATION, $remediate['database'] ?? null);
        $pathValue = self::first($path, self::ENV_PATH, $remediate['database_path'] ?? null);
        $maxAgeValue = self::first($maxAge, self::ENV_MAX_AGE, $remediate['database_max_age'] ?? null);

        return new self(
            $pathValue ?? $defaultPath,
            $locationValue === null ? [self::DEFAULT_SOURCE] : self::sourcesFrom($locationValue),
            $maxAgeValue === null ? null : self::parseMaxAge($maxAgeValue),
            $pathValue !== null,
            $locationValue !== null,
        );
    }

    /** False when the configured repositories are to be asked instead of any database. */
    public function usesDatabase(): bool
    {
        return $this->sources !== [];
    }

    /** The one local file to read as it is, when --database-location names a path rather than URLs. */
    public function localSource(): ?string
    {
        if (count($this->sources) !== 1 || preg_match('{^[a-z][a-z0-9+.-]*://}i', $this->sources[0]) === 1) {
            return null;
        }

        return $this->sources[0];
    }

    /**
     * @param string|list<mixed>|mixed $extraValue
     */
    private static function first(?string $option, string $env, mixed $extraValue): ?string
    {
        if ($option !== null && $option !== '') {
            return $option;
        }
        $fromEnv = getenv($env);
        if (is_string($fromEnv) && $fromEnv !== '') {
            return $fromEnv;
        }
        if (is_string($extraValue) && $extraValue !== '') {
            return $extraValue;
        }
        if (is_array($extraValue)) {
            $items = array_values(array_filter($extraValue, static fn (mixed $v): bool => is_string($v) && $v !== ''));
            if ($items !== []) {
                return implode(',', $items);
            }
        }

        return null;
    }

    /** @return list<string> */
    private static function sourcesFrom(string $value): array
    {
        $items = array_values(array_filter(array_map('trim', explode(',', $value)), static fn (string $v): bool => $v !== ''));
        if (count($items) === 1 && in_array(strtolower($items[0]), self::NO_DATABASE, true)) {
            return [];
        }

        return $items;
    }

    private static function parseMaxAge(string $value): int
    {
        if (preg_match('{^\s*(\d+)\s*([hd]?)\s*$}i', $value, $m) !== 1) {
            throw new \InvalidArgumentException(sprintf('--database-max-age must be a number of hours (or a number with an h or d suffix), got "%s".', $value));
        }

        return (int) $m[1] * (strtolower($m[2]) === 'd' ? 86400 : 3600);
    }
}
