<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db\Source;

/**
 * Private or organisational advisories from a JSON file in the Packagist API shape:
 *
 *   {"advisories": {"company/internal": [{"advisoryId": "COMPANY-2026-001", "affectedVersions": "<2.1.4",
 *                                           "title": "…", "link": "…", "severity": "high", "reportedAt": "2026-01-15 10:00:00"}]}}
 *
 * Records merge with public ones when they share an identifier (for example a CVE).
 */
final class JsonFileSource implements AdvisorySourceInterface
{
    public function __construct(private readonly string $path, private readonly PackagistShapeMapper $mapper = new PackagistShapeMapper())
    {
    }

    public function name(): string
    {
        return 'local:' . basename($this->path);
    }

    public function fetch(callable $log): array
    {
        $raw = @file_get_contents($this->path);
        if ($raw === false) {
            throw new \RuntimeException(sprintf('Cannot read %s', $this->path));
        }
        $document = json_decode($raw, true);
        if (!is_array($document)) {
            throw new \RuntimeException(sprintf('%s is not a JSON object', $this->path));
        }
        $result = $this->mapper->mapDocument($document, $this->name());
        $log(sprintf('%s: %d records%s', $this->name(), count($result['records']), $result['skipped'] > 0 ? sprintf(', %d skipped', $result['skipped']) : ''));

        return $result['records'];
    }
}
