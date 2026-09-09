<?php

declare(strict_types=1);

namespace Remediate\Output;

use Remediate\Engine\Advisory\Advisory;
use Remediate\Engine\Plan\FindingPlan;
use Remediate\Engine\Plan\Plan;

/**
 * CycloneDX 1.6 JSON: every locked package as a component (purl pkg:composer/...), every advisory as a
 * vulnerability affecting its component, with the verified command in the CycloneDX `recommendation`
 * field so SBOM and VEX tooling can consume the plan.
 */
final class CycloneDxRenderer
{
    public const SPEC_VERSION = '1.6';

    public function __construct(private readonly bool $minimalChangesSupported = true, private readonly ?string $serialNumber = null, private readonly ?string $timestamp = null)
    {
    }

    public function render(Plan $plan): string
    {
        return json_encode($this->toArray($plan), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR) . "\n";
    }

    /** @return array<string, mixed> */
    public function toArray(Plan $plan): array
    {
        $components = [];
        $refs = [];
        foreach ($plan->inventory as $entry) {
            $ref = self::purl($entry['name'], $entry['version']);
            $refs[$entry['name']] = $ref;
            $components[] = [
                'type' => 'library',
                'bom-ref' => $ref,
                'group' => explode('/', $entry['name'], 2)[0],
                'name' => explode('/', $entry['name'], 2)[1] ?? $entry['name'],
                'version' => $entry['version'],
                'purl' => $ref,
                'scope' => $entry['dev'] ? 'excluded' : 'required',
            ];
        }
        // Findings on packages absent from the inventory (should not happen) still get a component.
        foreach ($plan->findings as $fp) {
            if (!isset($refs[$fp->finding->packageName])) {
                $ref = self::purl($fp->finding->packageName, $fp->finding->prettyVersion);
                $refs[$fp->finding->packageName] = $ref;
                $components[] = ['type' => 'library', 'bom-ref' => $ref, 'name' => $fp->finding->packageName, 'version' => $fp->finding->prettyVersion, 'purl' => $ref];
            }
        }

        $vulnerabilities = [];
        foreach ($plan->findings as $fp) {
            foreach ($fp->allFindings() as $finding) {
                $vulnerabilities[] = $this->vulnerability($fp, $finding->advisory, $refs[$finding->packageName]);
            }
        }

        return [
            'bomFormat' => 'CycloneDX',
            'specVersion' => self::SPEC_VERSION,
            'serialNumber' => $this->serialNumber ?? 'urn:uuid:' . self::uuid(),
            'version' => 1,
            'metadata' => [
                'timestamp' => $this->timestamp ?? gmdate(DATE_ATOM),
                'tools' => ['components' => [[
                    'type' => 'application',
                    'name' => 'composer-remediate',
                    'version' => $plan->metadata['engine_version'] ?? 'dev',
                ]]],
                'properties' => array_values(array_filter([
                    self::property('composer-remediate:composer_version', $plan->metadata['composer_version'] ?? null),
                    self::property('composer-remediate:advisory_source', $plan->metadata['advisory_source'] ?? null),
                    self::property('composer-remediate:composer_lock_sha256', $plan->metadata['composer_lock_sha256'] ?? null),
                    self::property('composer-remediate:combined_command', $plan->combined?->candidate->commandLine($this->minimalChangesSupported)),
                    self::property('composer-remediate:exit_code', (string) $plan->exitCode()),
                ])),
            ],
            'components' => $components,
            'vulnerabilities' => $vulnerabilities,
        ];
    }

    /** @return array<string, mixed> */
    private function vulnerability(FindingPlan $plan, Advisory $advisory, string $ref): array
    {
        $recommended = $plan->recommended();
        $command = $recommended?->candidate->commandLine($this->minimalChangesSupported);
        $source = ['name' => 'Packagist', 'url' => 'https://packagist.org/security-advisories/' . $advisory->id];
        if (preg_match('{^GHSA-}i', $advisory->id) === 1) {
            $source = ['name' => 'GitHub', 'url' => 'https://github.com/advisories/' . $advisory->id];
        }
        $references = [];
        if ($advisory->cve !== null && $advisory->cve !== $advisory->id) {
            $references[] = ['id' => $advisory->cve, 'source' => ['name' => 'NVD', 'url' => 'https://nvd.nist.gov/vuln/detail/' . $advisory->cve]];
        }
        if ($advisory->link !== null) {
            $references[] = ['id' => $advisory->displayId(), 'source' => ['name' => 'advisory', 'url' => $advisory->link]];
        }
        $entry = [
            'bom-ref' => 'vuln:' . $advisory->id . '@' . $ref,
            'id' => $advisory->id,
            'source' => $source,
            'references' => $references,
            'ratings' => [['severity' => self::severity($advisory->severity), 'method' => 'other', 'source' => $source]],
            'description' => $advisory->title ?? $advisory->displayId(),
            'detail' => sprintf('Affected versions: %s', $advisory->affectedVersions->getPrettyString()),
            'recommendation' => $command !== null
                ? sprintf('Run: %s', $command)
                : 'No verified remediation found' . ($plan->blocker !== null ? ': ' . $plan->blocker : '.'),
            'affects' => [['ref' => $ref]],
            'properties' => array_values(array_filter([
                self::property('composer-remediate:remediation_status', $command !== null ? 'verified' : 'none'),
                self::property('composer-remediate:command', $command),
                self::property('composer-remediate:direct', $plan->finding->isRootRequirement ? 'true' : 'false'),
                self::property('composer-remediate:dev', $plan->finding->isDev ? 'true' : 'false'),
            ])),
        ];
        if ($advisory->reportedAt !== null) {
            $entry['published'] = $advisory->reportedAt->format(DATE_ATOM);
        }
        if ($recommended?->diff !== null) {
            $entry['analysis'] = ['state' => 'exploitable', 'response' => ['update'], 'detail' => sprintf('%d package change(s) verified by Composer\'s solver.', $recommended->diff->count())];
        }

        return $entry;
    }

    private static function severity(?string $severity): string
    {
        return match (strtolower((string) $severity)) {
            'critical' => 'critical',
            'high' => 'high',
            'medium', 'moderate' => 'medium',
            'low' => 'low',
            default => 'unknown',
        };
    }

    /** @return array{name: string, value: string}|null */
    private static function property(string $name, ?string $value): ?array
    {
        return $value === null || $value === '' ? null : ['name' => $name, 'value' => $value];
    }

    public static function purl(string $name, string $version): string
    {
        $parts = explode('/', $name, 2);
        $version = ltrim($version, 'v');
        if (!isset($parts[1])) {
            return 'pkg:composer/' . rawurlencode($parts[0]) . '@' . rawurlencode($version);
        }

        return 'pkg:composer/' . rawurlencode($parts[0]) . '/' . rawurlencode($parts[1]) . '@' . rawurlencode($version);
    }

    private static function uuid(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
    }
}
