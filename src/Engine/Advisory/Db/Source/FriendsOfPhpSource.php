<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db\Source;

use Composer\Util\HttpDownloader;
use Remediate\Engine\Advisory\Db\AffectedRange;
use Remediate\Engine\Advisory\Db\CoverageGap;
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

    /** @var list<CoverageGap> */
    private array $gaps = [];

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
        $this->gaps = [];
        $skipped = 0;
        $visit = function (string $path, string $contents) use (&$records, &$skipped): void {
            $record = $this->record($path, $contents, $gap);
            if ($record === null) {
                ++$skipped;
                if ($gap !== null) {
                    $this->gaps[] = $gap;
                }

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
        $log(sprintf('FriendsOfPHP: %d files, %d records%s', $count, count($records), $skipped > 0 ? sprintf(', %d skipped (recorded as coverage gaps)', $skipped) : ''));

        if ($this->localCheckout === null) {
            // Only the downloaded feed is held to this. A checkout the operator pointed at is their
            // own directory, and an empty one is a statement about their machine, not an outage.
            self::refuseEmpty($records, $this->gaps, 'FriendsOfPHP');
        }

        return $records;
    }

    /**
     * A public advisory feed always has thousands of records. Nothing at all means the feed answered
     * without its data: an empty document, an archive with nothing inside, a mirror serving a
     * placeholder. That is an outage wearing a success, and accepting it would build a database
     * missing a whole source, publish it checksum-verified and attested, and report locks clean that
     * are not.
     *
     * Records the source read and could not interpret are a different thing: they come back as
     * coverage gaps, which are reported and gate a clean result on their own. A feed is only refused
     * when it produced neither.
     *
     * @param list<\Remediate\Engine\Advisory\Db\NormalizedAdvisory> $records
     * @param list<\Remediate\Engine\Advisory\Db\CoverageGap>        $gaps
     */
    private static function refuseEmpty(array $records, array $gaps, string $source): void
    {
        if ($records === [] && $gaps === []) {
            throw new \RuntimeException(sprintf('%s returned no advisories at all, and nothing it could not read either. A feed that answers successfully with no data is an outage, not an empty world; the build stops rather than publish a database missing this source.', $source));
        }
    }

    public function gaps(): array
    {
        return $this->gaps;
    }

    /** @param-out CoverageGap|null $gap */
    private function record(string $path, string $contents, ?CoverageGap &$gap = null): ?NormalizedAdvisory
    {
        $gap = null;
        // The directory layout names the package even when the file cannot be read.
        $fromPath = preg_match('{^([^/]+/[^/]+)/}', $path, $m) === 1 ? strtolower($m[1]) : null;
        try {
            $doc = Yaml::parse($contents);
        } catch (ParseException $e) {
            $gap = new CoverageGap('FriendsOfPHP', $path, $fromPath, 'invalid YAML', $e->getMessage());

            return null;
        }
        if (!is_array($doc)) {
            $gap = new CoverageGap('FriendsOfPHP', $path, $fromPath, 'document is not a map');

            return null;
        }
        $reference = $doc['reference'] ?? null;
        if (!is_string($reference) || !str_starts_with($reference, 'composer://')) {
            return null; // not a Composer package (e.g. a Drupal or WordPress advisory): not a gap
        }
        $package = strtolower(substr($reference, strlen('composer://')));
        $branches = is_array($doc['branches'] ?? null) ? $doc['branches'] : [];
        $expression = $this->ranges->fromFriendsOfPhp($branches);
        if ($expression === null) {
            $gap = new CoverageGap('FriendsOfPHP', $path, $package, 'no usable version range in branches', json_encode($branches, JSON_UNESCAPED_SLASHES) ?: null);

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
                $time = self::time($branch['time']);
                if ($time !== null && ($reportedAt === null || $time < $reportedAt)) {
                    $reportedAt = $time;
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

    /**
     * A branch's `time: 2024-05-01 10:00:00` is unquoted in the upstream files, so the YAML parser
     * hands it over as a Unix timestamp (integer), not as text; quoted or unusual values arrive as strings.
     */
    private static function time(mixed $value): ?\DateTimeImmutable
    {
        if (is_int($value) || is_float($value)) {
            return (new \DateTimeImmutable('@' . (int) $value))->setTimezone(new \DateTimeZone('UTC'));
        }
        if (!is_string($value) || trim($value) === '') {
            return null;
        }
        try {
            return new \DateTimeImmutable($value, new \DateTimeZone('UTC'));
        } catch (\Exception) {
            return null;
        }
    }
}
