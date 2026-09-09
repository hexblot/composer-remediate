<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db\Source;

use Composer\Util\HttpDownloader;
use Remediate\Engine\Advisory\Db\AffectedRange;
use Remediate\Engine\Advisory\Db\NormalizedAdvisory;
use Remediate\Engine\Advisory\Db\RangeNormalizer;
use Remediate\Engine\Advisory\Db\SourceRecord;
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

/**
 * FriendsOfPHP/security-advisories: one YAML file per advisory under <vendor>/<package>/. Read from
 * a local checkout when given, otherwise from GitHub's zip of the default branch.
 */
final class FriendsOfPhpSource implements AdvisorySourceInterface
{
    public const URL = 'https://codeload.github.com/FriendsOfPHP/security-advisories/zip/refs/heads/master';

    public function __construct(
        private readonly HttpDownloader $downloader,
        private readonly string $tempDir,
        private readonly ?string $localCheckout = null,
        private readonly RangeNormalizer $ranges = new RangeNormalizer(),
        private readonly string $url = self::URL,
    ) {
    }

    public function name(): string
    {
        return 'FriendsOfPHP';
    }

    public function fetch(callable $log): array
    {
        $records = [];
        $skipped = 0;
        $visit = function (string $path, string $contents) use (&$records, &$skipped): void {
            $record = $this->record($path, $contents);
            if ($record === null) {
                ++$skipped;

                return;
            }
            $records[] = $record;
        };

        if ($this->localCheckout !== null) {
            $log('FriendsOfPHP: reading ' . $this->localCheckout);
            $root = rtrim($this->localCheckout, '/');
            $files = glob($root . '/*/*/*.yaml') ?: [];
            foreach ($files as $file) {
                $visit(substr($file, strlen($root) + 1), (string) file_get_contents($file));
            }
            $count = count($files);
        } else {
            $log('FriendsOfPHP: downloading the repository archive…');
            $reader = new ZipArchiveReader($this->downloader, $this->tempDir);
            $count = $reader->each(
                $this->url,
                static fn (string $name): bool => str_ends_with($name, '.yaml') && preg_match('{^[^/]+/[^/]+/[^/]+/[^/]+\.yaml$}', $name) === 1,
                static function (string $name, string $contents) use ($visit): void {
                    // strip the archive's top-level directory (security-advisories-master/)
                    $visit(substr($name, strpos($name, '/') + 1), $contents);
                },
            );
        }
        $log(sprintf('FriendsOfPHP: %d files, %d records%s', $count, count($records), $skipped > 0 ? sprintf(', %d skipped', $skipped) : ''));

        return $records;
    }

    private function record(string $path, string $contents): ?NormalizedAdvisory
    {
        try {
            $doc = Yaml::parse($contents);
        } catch (ParseException) {
            return null;
        }
        if (!is_array($doc)) {
            return null;
        }
        $reference = $doc['reference'] ?? null;
        if (!is_string($reference) || !str_starts_with($reference, 'composer://')) {
            return null;
        }
        $package = strtolower(substr($reference, strlen('composer://')));
        $branches = is_array($doc['branches'] ?? null) ? $doc['branches'] : [];
        $expression = $this->ranges->fromFriendsOfPhp($branches);
        if ($expression === null) {
            return null;
        }

        $aliases = [$path];
        $base = basename($path, '.yaml');
        if ($base !== '') {
            $aliases[] = $base;
        }
        if (is_string($doc['cve'] ?? null) && $doc['cve'] !== '') {
            $aliases[] = $doc['cve'];
        }
        $ids = array_values(array_unique($aliases));
        usort($ids, static fn (string $a, string $b): int => [NormalizedAdvisory::rankId($a), $a] <=> [NormalizedAdvisory::rankId($b), $b]);

        $reportedAt = null;
        foreach ($branches as $branch) {
            if (is_array($branch) && isset($branch['time'])) {
                try {
                    $time = new \DateTimeImmutable((string) (is_scalar($branch['time']) ? $branch['time'] : ''), new \DateTimeZone('UTC'));
                    if ($reportedAt === null || $time < $reportedAt) {
                        $reportedAt = $time;
                    }
                } catch (\Exception) {
                }
            }
        }

        return new NormalizedAdvisory(
            $ids[0],
            $ids,
            is_string($doc['title'] ?? null) ? $doc['title'] : null,
            is_string($doc['link'] ?? null) ? $doc['link'] : null,
            null,
            $reportedAt,
            null,
            [new AffectedRange($package, $expression, 'FriendsOfPHP')],
            [new SourceRecord('FriendsOfPHP/security-advisories', $path, 'https://github.com/FriendsOfPHP/security-advisories/blob/master/' . $path)],
        );
    }
}
