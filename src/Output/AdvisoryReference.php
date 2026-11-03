<?php

declare(strict_types=1);

namespace Remediate\Output;

use Remediate\Engine\Advisory\Advisory;

/**
 * Where an advisory is published, read off its identifier. The advisory database merges four feeds
 * and names each advisory by its best-ranked alias, so a canonical id can be a CVE, a GitHub, a
 * Packagist, a Drupal.org or an OSV identifier, and only the identifier says which site has a page
 * for it. One place decides, so no report can send a reader to a Packagist page for an advisory that
 * Packagist never published.
 */
final class AdvisoryReference
{
    /**
     * The site that publishes the advisory under this identifier, and the page there, when the
     * identifier says which site that is. Otherwise the advisory's own link, attributed to the feed
     * that carried it, and no URL when there is none to give.
     *
     * @return array{name: string, url?: string}
     */
    public static function source(Advisory $advisory): array
    {
        $home = self::home($advisory->id);
        if ($home !== null) {
            return $home;
        }
        $name = $advisory->sources[0]['name'] ?? 'advisory';

        return $advisory->link === null ? ['name' => $name] : ['name' => $name, 'url' => $advisory->link];
    }

    /** The page for the advisory: the publisher's when the identifier names one, else the feed's link. */
    public static function url(Advisory $advisory): ?string
    {
        return self::source($advisory)['url'] ?? null;
    }

    /**
     * The kind of identifier, in the vocabulary GitLab's dependency-scanning report uses, or null when
     * the identifier belongs to no known publisher.
     */
    public static function identifierType(string $id): ?string
    {
        return match (true) {
            preg_match('{^CVE-}i', $id) === 1 => 'cve',
            preg_match('{^GHSA-}i', $id) === 1 => 'ghsa',
            preg_match('{^PKSA-}i', $id) === 1 => 'packagist_advisory',
            preg_match('{^SA-(CORE|CONTRIB)-}i', $id) === 1 => 'drupal_advisory',
            preg_match('{^DRUPAL-}i', $id) === 1 => 'osv',
            default => null,
        };
    }

    /** @return array{name: string, url: string}|null */
    private static function home(string $id): ?array
    {
        return match (self::identifierType($id)) {
            'cve' => ['name' => 'NVD', 'url' => 'https://nvd.nist.gov/vuln/detail/' . $id],
            'ghsa' => ['name' => 'GitHub', 'url' => 'https://github.com/advisories/' . $id],
            'packagist_advisory' => ['name' => 'Packagist', 'url' => 'https://packagist.org/security-advisories/' . $id],
            'drupal_advisory' => ['name' => 'Drupal.org', 'url' => 'https://www.drupal.org/' . strtolower($id)],
            'osv' => ['name' => 'OSV', 'url' => 'https://osv.dev/vulnerability/' . $id],
            default => null,
        };
    }
}
