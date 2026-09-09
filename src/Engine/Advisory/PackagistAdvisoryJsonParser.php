<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory;

use Composer\Semver\Constraint\ConstraintInterface;
use Composer\Semver\VersionParser;

/**
 * Parses advisory records in the shape of Packagist's /api/security-advisories/ response and of
 * `composer audit --format=json`: {"advisories": {"vendor/pkg": [ {advisoryId, affectedVersions, ...} ]}}.
 */
final class PackagistAdvisoryJsonParser
{
    private VersionParser $versionParser;

    public function __construct(?VersionParser $versionParser = null)
    {
        $this->versionParser = $versionParser ?? new VersionParser();
    }

    /**
     * @param array<string, mixed> $document
     *
     * @return array<string, list<Advisory>>
     */
    public function parseDocument(array $document): array
    {
        $result = [];
        if (!array_key_exists('advisories', $document)) {
            // An error payload or an unrelated document must not read as "no advisories".
            throw new AdvisoryLookupFailed('Advisory document has no "advisories" map' . (isset($document['error']) && is_scalar($document['error']) ? ' (error: ' . $document['error'] . ')' : '') . '.');
        }
        $advisories = $document['advisories'];
        if (!is_array($advisories)) {
            throw new AdvisoryLookupFailed('Advisory document field "advisories" is not a map.');
        }
        foreach ($advisories as $packageName => $records) {
            if (!is_string($packageName)) {
                throw new AdvisoryLookupFailed('Advisory document keys must be package names.');
            }
            if (!is_array($records)) {
                throw new AdvisoryLookupFailed(sprintf('Advisory entries for %s are not a list.', $packageName));
            }
            foreach ($records as $record) {
                if (!is_array($record)) {
                    throw new AdvisoryLookupFailed(sprintf('An advisory entry for %s is not an object.', $packageName));
                }
                /** @var array<string, mixed> $record */
                $result[strtolower($packageName)][] = $this->parseRecord($packageName, $record);
            }
        }

        return $result;
    }

    /**
     * @param array<string, mixed> $data
     */
    public function parseRecord(string $packageName, array $data): Advisory
    {
        $id = $data['advisoryId'] ?? null;
        if (!is_string($id) || $id === '') {
            throw new AdvisoryLookupFailed(sprintf('Advisory for %s has no advisoryId.', $packageName));
        }
        $affected = $data['affectedVersions'] ?? null;
        if (!is_string($affected)) {
            throw new AdvisoryLookupFailed(sprintf('Advisory %s has no affectedVersions.', $id));
        }

        $reportedAt = null;
        if (isset($data['reportedAt']) && is_string($data['reportedAt'])) {
            try {
                $reportedAt = new \DateTimeImmutable($data['reportedAt'], new \DateTimeZone('UTC'));
            } catch (\Exception) {
                $reportedAt = null;
            }
        }

        $sources = [];
        if (isset($data['sources']) && is_array($data['sources'])) {
            foreach ($data['sources'] as $source) {
                if (is_array($source) && isset($source['name'], $source['remoteId']) && is_string($source['name']) && is_string($source['remoteId'])) {
                    $sources[] = ['name' => $source['name'], 'remoteId' => $source['remoteId']];
                }
            }
        }

        $pkg = isset($data['packageName']) && is_string($data['packageName']) ? $data['packageName'] : $packageName;

        return new Advisory(
            $id,
            strtolower($pkg),
            $this->parseAffectedVersionsStrict($affected, $id),
            self::optionalString($data, 'title'),
            self::optionalString($data, 'cve'),
            self::optionalString($data, 'link'),
            self::optionalString($data, 'severity'),
            $reportedAt,
            $sources,
        );
    }

    /**
     * A range that cannot be parsed must fail loudly: silently turning it into an impossible constraint
     * would make the advisory match nothing and read as a clean result.
     */
    public function parseAffectedVersionsStrict(string $expression, string $advisoryId): ConstraintInterface
    {
        try {
            return $this->versionParser->parseConstraints($expression);
        } catch (\UnexpectedValueException $e) {
            throw new AdvisoryLookupFailed(sprintf('Advisory %s has an unparsable affectedVersions "%s": %s', $advisoryId, $expression, $e->getMessage()), 0, $e);
        }
    }

    /** @param array<string, mixed> $data */
    private static function optionalString(array $data, string $key): ?string
    {
        return isset($data[$key]) && is_string($data[$key]) && $data[$key] !== '' ? $data[$key] : null;
    }
}
