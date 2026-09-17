<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db\Source;

use Composer\Util\HttpDownloader;
use Remediate\Engine\Advisory\Db\CoverageGap;

/**
 * Packagist's full advisory dump: GET /api/security-advisories/?updatedSince=1 returns every
 * advisory Packagist aggregates (FriendsOfPHP and GitHub), already keyed by package.
 */
final class PackagistApiSource implements AdvisorySourceInterface
{
    public const URL = 'https://packagist.org/api/security-advisories/?updatedSince=1';

    /** @var list<CoverageGap> */
    private array $gaps = [];

    public function __construct(
        private readonly HttpDownloader $downloader,
        private readonly PackagistShapeMapper $mapper = new PackagistShapeMapper(),
        private readonly string $url = self::URL,
    ) {
    }

    public function name(): string
    {
        return 'Packagist';
    }

    public function fetch(callable $log): array
    {
        $log('Packagist: downloading the advisory dump…');
        $data = $this->downloader->get($this->url)->decodeJson();
        if (!is_array($data)) {
            throw new \RuntimeException('Packagist advisory dump is not a JSON object');
        }
        $result = $this->mapper->mapDocument($data, 'Packagist');
        $this->gaps = $result['gaps'];
        $log(sprintf('Packagist: %d records%s', count($result['records']), $result['skipped'] > 0 ? sprintf(', %d skipped (recorded as coverage gaps)', $result['skipped']) : ''));

        self::refuseEmpty($result['records'], $this->gaps, 'Packagist');

        return $result['records'];
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
}
