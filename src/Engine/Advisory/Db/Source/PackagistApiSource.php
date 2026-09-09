<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db\Source;

use Composer\Util\HttpDownloader;

/**
 * Packagist's full advisory dump: GET /api/security-advisories/?updatedSince=1 returns every
 * advisory Packagist aggregates (FriendsOfPHP and GitHub), already keyed by package.
 */
final class PackagistApiSource implements AdvisorySourceInterface
{
    public const URL = 'https://packagist.org/api/security-advisories/?updatedSince=1';

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
        $log(sprintf('Packagist: %d records%s', count($result['records']), $result['skipped'] > 0 ? sprintf(', %d skipped (unparsable ranges)', $result['skipped']) : ''));

        return $result['records'];
    }
}
