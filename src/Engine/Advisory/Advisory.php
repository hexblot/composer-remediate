<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory;

use Composer\Semver\Constraint\Constraint;
use Composer\Semver\Constraint\ConstraintInterface;

/**
 * Engine-owned advisory record. Composer's own advisory classes are @internal and change between
 * releases, so everything downstream of the adapters works with this object instead.
 */
final class Advisory
{
    /**
     * @param list<array{name: string, remoteId: string}> $sources
     * @param float|null                                  $epss           FIRST EPSS probability (0..1) that the CVE is exploited in the next 30 days
     * @param float|null                                  $epssPercentile the score's percentile among all scored CVEs (0..1)
     * @param \DateTimeImmutable|null                     $kevAdded       when CISA added the CVE to the Known Exploited Vulnerabilities catalogue
     */
    public function __construct(
        public readonly string $id,
        public readonly string $packageName,
        public readonly ConstraintInterface $affectedVersions,
        public readonly ?string $title = null,
        public readonly ?string $cve = null,
        public readonly ?string $link = null,
        public readonly ?string $severity = null,
        public readonly ?\DateTimeImmutable $reportedAt = null,
        public readonly array $sources = [],
        public readonly ?float $epss = null,
        public readonly ?float $epssPercentile = null,
        public readonly ?\DateTimeImmutable $kevAdded = null,
    ) {
    }

    /** Listed in CISA's Known Exploited Vulnerabilities catalogue: exploitation in the wild is confirmed. */
    public function isKnownExploited(): bool
    {
        return $this->kevAdded !== null;
    }

    /**
     * Sort key, smaller is more urgent: known-exploited first, then by exploit probability (unknown
     * after every known score), then by severity label (unknown after low).
     *
     * @return array{int, float, int}
     */
    public function urgency(): array
    {
        $severity = \Remediate\Engine\Plan\Plan::SEVERITIES[strtolower((string) $this->severity)] ?? 0;

        return [$this->isKnownExploited() ? 0 : 1, $this->epss !== null ? -$this->epss : 1.0, -$severity];
    }

    /** The identifier a developer would search for: the CVE when known, otherwise the source id. */
    public function displayId(): string
    {
        return $this->cve ?? $this->id;
    }

    /** @param string $normalizedVersion A Composer-normalized version such as 6.4.21.0 */
    public function affectsVersion(string $normalizedVersion): bool
    {
        return $this->affectedVersions->matches(new Constraint(Constraint::STR_OP_EQ, $normalizedVersion));
    }

    /** True when any version permitted by $constraint is affected (conservative intersection test). */
    public function affectsConstraint(ConstraintInterface $constraint): bool
    {
        return $this->affectedVersions->matches($constraint);
    }
}
