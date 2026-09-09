<?php

declare(strict_types=1);

namespace Remediate\Output;

use Remediate\Engine\Advisory\Advisory;
use Remediate\Engine\Matching\Finding;
use Remediate\Engine\Plan\FindingPlan;
use Remediate\Engine\Plan\Plan;

/**
 * GitLab dependency-scanning report (security report schema 15.x). Declared as
 * `artifacts: reports: dependency_scanning:` in .gitlab-ci.yml, it feeds the merge request security
 * widget and the vulnerability report; the verified command goes into each vulnerability's `solution`.
 */
final class GitLabRenderer
{
    public const SCHEMA_VERSION = '15.2.1';

    public function __construct(
        private readonly bool $minimalChangesSupported = true,
        private readonly ?string $startTime = null,
        private readonly ?string $endTime = null,
    ) {
    }

    public function render(Plan $plan): string
    {
        return json_encode($this->toArray($plan), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR) . "\n";
    }

    /** @return array<string, mixed> */
    public function toArray(Plan $plan): array
    {
        $vulnerabilities = [];
        foreach ($plan->findings as $fp) {
            foreach ($fp->allFindings() as $finding) {
                $vulnerabilities[] = $this->vulnerability($fp, $finding);
            }
        }
        $version = $plan->metadata['engine_version'] ?? 'dev';
        $now = gmdate('Y-m-d\TH:i:s');
        $tool = ['id' => 'composer-remediate', 'name' => 'Composer Remediate', 'version' => $version, 'vendor' => ['name' => 'composer-remediate'], 'url' => 'https://hexblot.github.io/composer-remediate/'];

        return [
            'version' => self::SCHEMA_VERSION,
            'vulnerabilities' => $vulnerabilities,
            'dependency_files' => [[
                'path' => 'composer.lock',
                'package_manager' => 'composer',
                'dependencies' => array_map(static fn (array $entry): array => ['package' => ['name' => $entry['name']], 'version' => $entry['version']], $plan->inventory),
            ]],
            'scan' => [
                'analyzer' => $tool,
                'scanner' => $tool,
                'type' => 'dependency_scanning',
                'start_time' => $this->startTime ?? $now,
                'end_time' => $this->endTime ?? $now,
                'status' => 'success',
            ],
        ];
    }

    /** @return array<string, mixed> */
    private function vulnerability(FindingPlan $plan, Finding $finding): array
    {
        $advisory = $finding->advisory;
        $recommended = $plan->recommended();
        $command = $recommended?->candidate->commandLine($this->minimalChangesSupported);
        $identifiers = [];
        if ($advisory->cve !== null) {
            $identifiers[] = ['type' => 'cve', 'name' => $advisory->cve, 'value' => $advisory->cve, 'url' => 'https://nvd.nist.gov/vuln/detail/' . $advisory->cve];
        }
        foreach ($advisory->sources as $source) {
            if (preg_match('{^GHSA-}i', $source['remoteId']) === 1) {
                $identifiers[] = ['type' => 'ghsa', 'name' => $source['remoteId'], 'value' => $source['remoteId'], 'url' => 'https://github.com/advisories/' . $source['remoteId']];
            }
        }
        if (preg_match('{^GHSA-}i', $advisory->id) === 1 && !in_array($advisory->id, array_column($identifiers, 'value'), true)) {
            $identifiers[] = ['type' => 'ghsa', 'name' => $advisory->id, 'value' => $advisory->id, 'url' => 'https://github.com/advisories/' . $advisory->id];
        }
        $identifiers[] = ['type' => 'packagist_advisory', 'name' => $advisory->id, 'value' => $advisory->id, 'url' => 'https://packagist.org/security-advisories/' . $advisory->id];

        $links = [];
        if ($advisory->link !== null) {
            $links[] = ['url' => $advisory->link];
        }

        return [
            'id' => self::uuid($advisory->id . '@' . $finding->packageName),
            'category' => 'dependency_scanning',
            'name' => sprintf('%s: %s', $advisory->displayId(), $advisory->title ?? $finding->packageName),
            'description' => sprintf('%s %s is affected by %s (affected versions %s).', $finding->packageName, $finding->prettyVersion, $advisory->displayId(), $advisory->affectedVersions->getPrettyString()),
            'severity' => self::severity($advisory->severity),
            'solution' => $command !== null
                ? sprintf('Run `%s` (verified with Composer\'s solver%s).', $command, $recommended?->diff !== null ? sprintf(', %d package change(s)', $recommended->diff->count()) : '')
                : 'No verified remediation found' . ($plan->blocker !== null ? ': ' . $plan->blocker : '.'),
            'identifiers' => $identifiers,
            'links' => $links,
            'location' => [
                'file' => 'composer.lock',
                'dependency' => [
                    'package' => ['name' => $finding->packageName],
                    'version' => $finding->prettyVersion,
                    'direct' => $finding->isRootRequirement,
                ],
            ],
        ];
    }

    private static function severity(?string $severity): string
    {
        return match (strtolower((string) $severity)) {
            'critical' => 'Critical',
            'high' => 'High',
            'medium', 'moderate' => 'Medium',
            'low' => 'Low',
            default => 'Unknown',
        };
    }

    /** Deterministic UUID (version 5 style) from the finding key, so re-runs report the same id. */
    public static function uuid(string $key): string
    {
        $hash = sha1('composer-remediate:' . $key);
        $hex = substr($hash, 0, 32);
        $hex[12] = '5';
        $hex[16] = dechex((hexdec($hex[16]) & 0x3) | 0x8);

        return vsprintf('%s-%s-%s-%s-%s', [substr($hex, 0, 8), substr($hex, 8, 4), substr($hex, 12, 4), substr($hex, 16, 4), substr($hex, 20, 12)]);
    }
}
