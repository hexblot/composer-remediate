<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db\Source;

use Remediate\Engine\Advisory\Db\CoverageGap;

/**
 * Private or organisational advisories from a JSON file in the Packagist API shape:
 *
 *   {"advisories": {"company/internal": [{"advisoryId": "COMPANY-2026-001", "affectedVersions": "<2.1.4",
 *                                           "title": "…", "link": "…", "severity": "high", "reportedAt": "2026-01-15 10:00:00"}]}}
 *
 * Records merge with public ones when they share an identifier (for example a CVE). Private data is
 * the user's own: a record that cannot be interpreted fails the build instead of being dropped, the
 * same way an unparsable --advisories-file fails a run.
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
        if ($result['gaps'] !== []) {
            throw new \RuntimeException(sprintf('%s: %d record%s cannot be interpreted: %s', $this->path, count($result['gaps']), count($result['gaps']) === 1 ? '' : 's', implode('; ', array_map(static fn (CoverageGap $g): string => $g->describe(), array_slice($result['gaps'], 0, 5)))));
        }
        $log(sprintf('%s: %d records', $this->name(), count($result['records'])));

        return $result['records'];
    }

    public function gaps(): array
    {
        return []; // a gap fails the build; see fetch()
    }
}
