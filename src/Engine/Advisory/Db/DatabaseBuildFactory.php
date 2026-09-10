<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db;

use Composer\Util\HttpDownloader;
use Remediate\Engine\Advisory\Db\Enrichment\EnrichmentSourceInterface;
use Remediate\Engine\Advisory\Db\Enrichment\EpssSource;
use Remediate\Engine\Advisory\Db\Enrichment\KevSource;
use Remediate\Engine\Advisory\Db\Source\AdvisorySourceInterface;
use Remediate\Engine\Advisory\Db\Source\FriendsOfPhpSource;
use Remediate\Engine\Advisory\Db\Source\JsonFileSource;
use Remediate\Engine\Advisory\Db\Source\OsvDumpSource;
use Remediate\Engine\Advisory\Db\Source\PackagistApiSource;

/**
 * Assembles the feeds and enrichments of a database build. `remediate:db-build` and the
 * `--rebuild-database` path of `remediate` share it, and the published database is built with the
 * defaults, so a build with no options reproduces what this project distributes.
 */
final class DatabaseBuildFactory
{
    public const SOURCES = ['packagist', 'osv', 'friendsofphp'];
    public const ENRICHMENTS = ['epss', 'kev'];

    /**
     * @param list<string> $names    feed names from SOURCES; empty means all
     * @param list<string> $includes JSON files in the Packagist API shape with private advisories
     *
     * @return list<AdvisorySourceInterface>
     *
     * @throws \InvalidArgumentException for an unknown feed name
     */
    public static function sources(HttpDownloader $downloader, string $tempDir, array $names = [], ?string $friendsOfPhpPath = null, array $includes = []): array
    {
        $selected = $names === [] ? self::SOURCES : array_map('strtolower', $names);
        $unknown = array_diff($selected, self::SOURCES);
        if ($unknown !== []) {
            throw new \InvalidArgumentException(sprintf('Unknown source(s) %s; choose from %s.', implode(', ', $unknown), implode(', ', self::SOURCES)));
        }
        $sources = [];
        foreach (self::SOURCES as $name) {
            if (!in_array($name, $selected, true)) {
                continue;
            }
            $sources[] = match ($name) {
                'packagist' => new PackagistApiSource($downloader),
                'osv' => new OsvDumpSource($downloader, $tempDir),
                'friendsofphp' => new FriendsOfPhpSource($downloader, $tempDir, $friendsOfPhpPath),
            };
        }
        foreach ($includes as $file) {
            $sources[] = new JsonFileSource($file);
        }

        return $sources;
    }

    /**
     * @param list<string> $names enrichment names from ENRICHMENTS, or `none`; empty means all
     *
     * @return list<EnrichmentSourceInterface>
     *
     * @throws \InvalidArgumentException for an unknown enrichment name
     */
    public static function enrichments(HttpDownloader $downloader, string $tempDir, array $names = [], ?string $epssFile = null, ?string $kevFile = null): array
    {
        $selected = $names === [] ? self::ENRICHMENTS : array_map('strtolower', $names);
        $unknown = array_diff($selected, [...self::ENRICHMENTS, 'none']);
        if ($unknown !== []) {
            throw new \InvalidArgumentException(sprintf('Unknown enrichment(s) %s; choose from %s or none.', implode(', ', $unknown), implode(', ', self::ENRICHMENTS)));
        }
        if (in_array('none', $selected, true)) {
            return [];
        }
        $enrichments = [];
        if (in_array('epss', $selected, true)) {
            $enrichments[] = new EpssSource($downloader, $tempDir, $epssFile);
        }
        if (in_array('kev', $selected, true)) {
            $enrichments[] = new KevSource($downloader, $kevFile);
        }

        return $enrichments;
    }

    /** The build this project publishes: every feed, both enrichments. */
    public static function defaultBuilder(HttpDownloader $downloader, string $tempDir): DatabaseBuilder
    {
        return new DatabaseBuilder(self::sources($downloader, $tempDir), new Merger(), new DatabaseWriter(), self::enrichments($downloader, $tempDir));
    }
}
