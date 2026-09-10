<?php

declare(strict_types=1);

namespace Remediate\Output;

use Remediate\Engine\Advisory\Advisory;
use Remediate\Engine\Matching\Finding;
use Remediate\Engine\Plan\FindingPlan;
use Remediate\Engine\Plan\Plan;

/**
 * SARIF 2.1.0 for GitHub Code Scanning and other SARIF consumers. One rule per advisory, one result
 * per (package, advisory) pointing at the package's line in composer.lock, with the verified command
 * in the message.
 */
final class SarifRenderer
{
    public const SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';

    public function __construct(
        private readonly bool $minimalChangesSupported = true,
        private readonly LockLineIndex $lines = new LockLineIndex(),
    ) {
    }

    public function render(Plan $plan): string
    {
        return json_encode($this->toArray($plan), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR) . "\n";
    }

    /** @return array<string, mixed> */
    public function toArray(Plan $plan): array
    {
        $rules = [];
        $ruleIndex = [];
        $results = [];
        foreach ($plan->findings as $findingPlan) {
            foreach ($findingPlan->allFindings() as $finding) {
                $advisory = $finding->advisory;
                if (!isset($ruleIndex[$advisory->id])) {
                    $ruleIndex[$advisory->id] = count($rules);
                    $rules[] = self::rule($advisory);
                }
                $results[] = $this->result($findingPlan, $finding, $ruleIndex[$advisory->id]);
            }
        }

        return [
            '$schema' => self::SCHEMA,
            'version' => '2.1.0',
            'runs' => [[
                'tool' => [
                    'driver' => [
                        'name' => 'composer-remediate',
                        'version' => $plan->metadata['engine_version'] ?? 'dev',
                        'informationUri' => 'https://hexblot.github.io/composer-remediate/',
                        'rules' => $rules,
                    ],
                ],
                'invocations' => [[
                    'executionSuccessful' => true,
                    'exitCode' => $plan->exitCode(),
                    'properties' => array_filter([
                        'composer_version' => $plan->metadata['composer_version'] ?? null,
                        'advisory_source' => $plan->metadata['advisory_source'] ?? null,
                        'combined_command' => $plan->combined?->candidate->commandLine($this->minimalChangesSupported),
                    ], static fn ($v): bool => $v !== null),
                ]],
                'results' => $results,
            ]],
        ];
    }

    /** @return array<string, mixed> */
    private static function rule(Advisory $advisory): array
    {
        $title = $advisory->title ?? $advisory->displayId();

        return [
            'id' => $advisory->id,
            'name' => preg_replace('{[^A-Za-z0-9]}', '', $advisory->displayId()) ?? $advisory->id,
            'shortDescription' => ['text' => self::truncate($title, 200)],
            'fullDescription' => ['text' => sprintf('%s. Affected versions of %s: %s.', $title, $advisory->packageName, $advisory->affectedVersions->getPrettyString())],
            'helpUri' => $advisory->link ?? 'https://packagist.org/security-advisories/' . $advisory->id,
            'help' => ['text' => sprintf('Advisory %s%s affects %s %s. Run composer remediate for the smallest verified upgrade.', $advisory->id, $advisory->cve !== null && $advisory->cve !== $advisory->id ? ' (' . $advisory->cve . ')' : '', $advisory->packageName, $advisory->affectedVersions->getPrettyString())],
            'defaultConfiguration' => ['level' => self::level($advisory->severity)],
            'properties' => array_filter([
                'security-severity' => self::securitySeverity($advisory->severity),
                'tags' => array_values(array_filter(['security', 'vulnerability', $advisory->severity !== null ? strtolower($advisory->severity) : null, $advisory->isKnownExploited() ? 'known-exploited' : null])),
                'epss' => $advisory->epss,
                'epss_percentile' => $advisory->epssPercentile,
                'kev_added' => $advisory->kevAdded?->format('Y-m-d'),
            ], static fn ($v): bool => $v !== null),
        ];
    }

    /** @return array<string, mixed> */
    private function result(FindingPlan $plan, Finding $finding, int $ruleIndex): array
    {
        $advisory = $finding->advisory;
        $recommended = $plan->recommended();
        $command = $recommended?->candidate->commandLine($this->minimalChangesSupported);
        $message = sprintf('%s %s is affected by %s%s.', $finding->packageName, $finding->prettyVersion, $advisory->displayId(), $advisory->title !== null ? ': ' . $advisory->title : '');
        $message .= $command !== null
            ? sprintf(' Verified fix: %s', $command)
            : ' No verified remediation found' . ($plan->blocker !== null ? ' (' . $plan->blocker . ')' : '') . '.';

        $location = ['physicalLocation' => ['artifactLocation' => ['uri' => $this->lines->relativePath, 'uriBaseId' => '%SRCROOT%']]];
        $line = $this->lines->lineOf($finding->packageName);
        if ($line !== null) {
            $location['physicalLocation']['region'] = ['startLine' => $line];
        }

        return [
            'ruleId' => $advisory->id,
            'ruleIndex' => $ruleIndex,
            'level' => self::level($advisory->severity),
            'message' => ['text' => $message],
            'locations' => [$location],
            'partialFingerprints' => ['advisoryPackage/v1' => $advisory->id . '@' . $finding->packageName],
            'properties' => array_filter([
                'package' => $finding->packageName,
                'version' => $finding->prettyVersion,
                'direct' => $finding->isRootRequirement,
                'dev' => $finding->isDev,
                'cve' => $advisory->cve,
                'severity' => $advisory->severity,
                'remediation_status' => $command !== null ? 'verified' : 'none',
                'command' => $command,
                'known_exploited' => $advisory->isKnownExploited() ? true : null,
                'epss' => $advisory->epss,
                'abandoned' => $finding->abandoned !== [] ? array_keys($finding->abandoned) : null,
            ], static fn ($v): bool => $v !== null),
        ];
    }

    private static function level(?string $severity): string
    {
        return match (strtolower((string) $severity)) {
            'critical', 'high' => 'error',
            'low' => 'note',
            default => 'warning',
        };
    }

    private static function securitySeverity(?string $severity): string
    {
        return match (strtolower((string) $severity)) {
            'critical' => '9.5',
            'high' => '7.5',
            'medium', 'moderate' => '5.0',
            'low' => '2.5',
            default => '5.0',
        };
    }

    private static function truncate(string $text, int $max): string
    {
        return mb_strlen($text) <= $max ? $text : mb_substr($text, 0, $max - 1) . '…';
    }
}
