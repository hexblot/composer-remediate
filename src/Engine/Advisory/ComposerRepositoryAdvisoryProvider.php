<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory;

use Composer\Advisory\PartialSecurityAdvisory;
use Composer\Advisory\SecurityAdvisory;
use Composer\Downloader\TransportException;
use Composer\Repository\AdvisoryProviderInterface;
use Composer\Repository\RepositoryInterface;
use Composer\Repository\RepositoryManager;
use Composer\Semver\Constraint\MatchAllConstraint;

/**
 * The one adapter that talks to Composer's @internal advisory API. It asks every configured
 * repository that advertises advisories (Packagist by default) for all advisories of the given
 * package names and converts them to engine-owned Advisory objects.
 *
 * Privacy note: for Packagist this results in the same POST of package names that `composer audit`
 * performs. Versions are not sent; matching happens locally.
 */
final class ComposerRepositoryAdvisoryProvider implements AdvisoryProvider
{
    /** @var array<string, list<Advisory>> */
    private array $cache = [];

    /** @var array<string, true> */
    private array $fetched = [];

    /**
     * @param array<RepositoryInterface> $repositories
     */
    public function __construct(private readonly array $repositories)
    {
    }

    public static function fromRepositoryManager(RepositoryManager $manager): self
    {
        return new self($manager->getRepositories());
    }

    public function advisoriesFor(array $packageNames): array
    {
        $wanted = [];
        $missing = [];
        foreach ($packageNames as $name) {
            $name = strtolower($name);
            $wanted[$name] = true;
            if (!isset($this->fetched[$name])) {
                $missing[$name] = new MatchAllConstraint();
            }
        }

        if ($missing !== []) {
            $this->fetch($missing);
        }

        return array_intersect_key($this->cache, $wanted);
    }

    public function describe(): string
    {
        $names = [];
        foreach ($this->repositories as $repository) {
            if ($repository instanceof AdvisoryProviderInterface && $repository->hasSecurityAdvisories()) {
                $names[] = $repository->getRepoName();
            }
        }

        return $names === [] ? 'no repository provides advisories' : 'advisories from ' . implode(', ', $names);
    }

    public function isComplete(): bool
    {
        return true;
    }

    /**
     * @param array<string, MatchAllConstraint> $constraintMap
     */
    private function fetch(array $constraintMap): void
    {
        $providers = 0;
        foreach ($this->repositories as $repository) {
            if (!$repository instanceof AdvisoryProviderInterface || !$repository->hasSecurityAdvisories()) {
                continue;
            }
            ++$providers;
            try {
                $result = $repository->getSecurityAdvisories($constraintMap, false);
            } catch (TransportException $e) {
                throw new AdvisoryLookupFailed(sprintf('Could not fetch advisories from %s: %s', $repository->getRepoName(), $e->getMessage()), 0, $e);
            }
            foreach ($result['advisories'] as $packageName => $advisories) {
                foreach ($advisories as $advisory) {
                    $converted = self::convert($advisory);
                    $key = strtolower((string) $packageName);
                    foreach ($this->cache[$key] ?? [] as $existing) {
                        if ($existing->id === $converted->id) {
                            continue 2;
                        }
                    }
                    $this->cache[$key][] = $converted;
                }
            }
        }
        if ($providers === 0) {
            // A repository set without any advisory source cannot produce a clean result, only an unknown one.
            throw new AdvisoryLookupFailed('None of the configured repositories provides security advisories (packagist.org is disabled or replaced). Use --database-location or --advisories-file to supply advisory data.');
        }
        foreach (array_keys($constraintMap) as $name) {
            $this->fetched[$name] = true;
        }
    }

    private static function convert(PartialSecurityAdvisory $advisory): Advisory
    {
        if ($advisory instanceof SecurityAdvisory) {
            // `severity` was added to Composer's SecurityAdvisory after 2.4; read it defensively.
            $severity = property_exists($advisory, 'severity') && is_string($advisory->severity) ? $advisory->severity : null; // @phpstan-ignore function.alreadyNarrowedType

            return new Advisory(
                $advisory->advisoryId,
                strtolower($advisory->packageName),
                $advisory->affectedVersions,
                $advisory->title,
                $advisory->cve,
                $advisory->link,
                $severity,
                $advisory->reportedAt,
                array_values($advisory->sources),
            );
        }

        return new Advisory($advisory->advisoryId, strtolower($advisory->packageName), $advisory->affectedVersions);
    }
}
