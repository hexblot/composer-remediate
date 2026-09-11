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
     * @param list<string> $notes   facts about how the settings were resolved that belong in the report, such as a
     *                              source chosen by the analysed project's composer.json rather than by the operator
     */
    private function __construct(
        public readonly string $path,
        public readonly array $sources,
        public readonly ?int $maxAgeSeconds,
        public readonly bool $pathConfigured,
        public readonly bool $sourcesConfigured,
        public readonly bool $sourcesFromProject = false,
        public readonly array $notes = [],
        /** The path came from the analysed project's composer.json: whatever is there is the project's content, not the operator's. */
        public readonly bool $pathFromProject = false,
    ) {
    }

    /**
     * The analysed project's composer.json is untrusted input: it may be a repository the operator is
     * scanning precisely because they do not trust it. Its `extra.remediate` settings are therefore
     * honoured with limits. A source it names is kept in a file of its own under the cache directory,
     * never in the shared default file another project's scan reads, and the report says the project
     * chose the source. A path it names must be relative and stay inside the project directory, so a
     * scan can only ever write inside the checkout being scanned.
     *
     * @param string|null $location   --database-location: URL(s), `composer`/`none`, or one local path
     * @param string|null $path       --database-path
     * @param string|null $maxAge     --database-max-age: hours, or a number with an h or d suffix
     * @param bool        $noDatabase --no-database
     * @param string|null $projectDir the directory of the composer.json being analysed; null when there is none
     *
     * @throws \InvalidArgumentException for a max age that is not a duration, or a project path outside the project
     */
    public static function resolve(Composer $composer, string $defaultPath, ?string $location, ?string $path, ?string $maxAge, bool $noDatabase = false, ?string $projectDir = null): self
    {
        $extra = $composer->getPackage()->getExtra();
        $remediate = isset($extra['remediate']) && is_array($extra['remediate']) ? $extra['remediate'] : [];
        $notes = [];

        $operatorLocation = $noDatabase ? 'none' : self::first($location, self::ENV_LOCATION, null);
        $projectLocation = $operatorLocation === null ? self::first(null, '', $remediate['database'] ?? null) : null;
        $locationValue = $operatorLocation ?? $projectLocation;
        $sources = $locationValue === null ? [self::DEFAULT_SOURCE] : self::sourcesFrom($locationValue);
        if ($projectLocation !== null && $sources !== []) {
            $notes[] = sprintf('Advisory source chosen by the analysed project\'s composer.json (extra.remediate.database): %s. Pass --database-location or set REMEDIATE_DATABASE to override it.', DatabaseLocator::redact(implode(', ', $sources)));
        }

        $operatorPath = self::first($path, self::ENV_PATH, null);
        // Without a project directory (a run from Composer's global configuration) there is no project
        // whose path could be honoured, and nothing to confine it to: the setting is ignored.
        $projectPath = $operatorPath === null && $projectDir !== null ? self::first(null, '', $remediate['database_path'] ?? null) : null;
        if ($projectPath !== null && $projectDir !== null) {
            $pathValue = self::projectPath($projectPath, $projectDir);
        } elseif ($operatorPath !== null) {
            $pathValue = $operatorPath;
        } elseif ($projectLocation !== null && $sources !== [] && self::localSourceOf($sources) === null) {
            // A project-chosen source must not write over the shared default file.
            $pathValue = dirname($defaultPath) . '/sources/' . sha1(implode("\n", $sources)) . '.sqlite';
        } else {
            $pathValue = $defaultPath;
        }

        $maxAgeValue = self::first($maxAge, self::ENV_MAX_AGE, $remediate['database_max_age'] ?? null);

        return new self(
            $pathValue,
            $sources,
            $maxAgeValue === null ? null : self::parseMaxAge($maxAgeValue),
            $operatorPath !== null || $projectPath !== null,
            $locationValue !== null,
            $projectLocation !== null,
            $notes,
            $projectPath !== null && $projectDir !== null,
        );
    }

    /**
     * A database path from the project's composer.json: relative, without parent segments, and with
     * no symbolic link among the directories that already exist on the way (a link out of the project
     * would make a relative path resolve elsewhere). Nothing is created here: the check runs before any
     * filesystem change, and the locator creates the parent directory afterwards, inside the project.
     */
    private static function projectPath(string $value, string $projectDir): string
    {
        $segments = array_values(array_filter(preg_split('{[\\\\/]+}', $value) ?: [], static fn (string $s): bool => $s !== '' && $s !== '.'));
        if (str_starts_with($value, '/') || preg_match('{^[A-Za-z]:[\\\\/]}', $value) === 1 || $segments === [] || in_array('..', $segments, true)) {
            throw new \InvalidArgumentException(sprintf('extra.remediate.database_path must be a relative path inside the project, got "%s"; use --database-path or REMEDIATE_DATABASE_PATH for a path elsewhere.', $value));
        }
        $root = realpath($projectDir);
        if ($root === false) {
            throw new \InvalidArgumentException(sprintf('extra.remediate.database_path cannot be resolved: %s is not a directory.', $projectDir));
        }
        $current = $root;
        foreach ($segments as $segment) {
            $next = $current . '/' . $segment;
            if (is_link($next)) {
                throw new \InvalidArgumentException(sprintf('extra.remediate.database_path "%s" passes through a symbolic link (%s); a path inside the project must not.', $value, $next));
            }
            if (!file_exists($next)) {
                break; // the rest does not exist yet and will be created under $current, inside the project
            }
            $real = realpath($next);
            if ($real === false || ($real !== $root && !str_starts_with($real, $root . '/'))) {
                throw new \InvalidArgumentException(sprintf('extra.remediate.database_path "%s" resolves outside the project directory.', $value));
            }
            $current = $real;
        }

        return $root . '/' . implode('/', $segments);
    }

    /** @param list<string> $sources */
    private static function localSourceOf(array $sources): ?string
    {
        if (count($sources) !== 1 || preg_match('{^[a-z][a-z0-9+.-]*://}i', $sources[0]) === 1) {
            return null;
        }

        return $sources[0];
    }

    /** False when the configured repositories are to be asked instead of any database. */
    public function usesDatabase(): bool
    {
        return $this->sources !== [];
    }

    /** The one local file to read as it is, when --database-location names a path rather than URLs. */
    public function localSource(): ?string
    {
        return self::localSourceOf($this->sources);
    }

    /**
     * @param string|list<mixed>|mixed $extraValue
     */
    private static function first(?string $option, string $env, mixed $extraValue): ?string
    {
        if ($option !== null && $option !== '') {
            return $option;
        }
        $fromEnv = $env === '' ? false : getenv($env);
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
