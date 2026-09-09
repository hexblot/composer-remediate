<?php

declare(strict_types=1);

namespace Remediate\Engine\Plan;

/**
 * A committed list of accepted findings (advisory@package keys). Findings in the baseline are still
 * reported but do not affect the exit code, so a gate can be introduced on an existing project and
 * tightened over time ("ratcheting"): remove entries as you fix them, and new findings fail the build.
 */
final class BaselineFile
{
    public const VERSION = 1;

    /**
     * @return list<string> finding keys
     */
    public static function read(string $path): array
    {
        $raw = @file_get_contents($path);
        if ($raw === false) {
            throw new \RuntimeException(sprintf('Cannot read baseline %s', $path));
        }
        $decoded = json_decode($raw, true);
        if (!is_array($decoded) || !is_array($decoded['findings'] ?? null)) {
            throw new \RuntimeException(sprintf('%s is not a baseline file (expected {"findings": [...]})', $path));
        }
        $keys = [];
        foreach ($decoded['findings'] as $entry) {
            if (is_string($entry)) {
                $keys[] = $entry;
            } elseif (is_array($entry) && is_string($entry['key'] ?? null)) {
                $keys[] = $entry['key'];
            }
        }

        return $keys;
    }

    public static function write(string $path, Plan $plan): void
    {
        $findings = [];
        foreach ($plan->findings as $fp) {
            foreach ($fp->allFindings() as $finding) {
                $findings[] = [
                    'key' => $finding->key(),
                    'package' => $finding->packageName,
                    'version' => $finding->prettyVersion,
                    'advisory' => $finding->advisory->displayId(),
                    'remediation' => $fp->hasRemediation() ? 'verified' : 'none',
                ];
            }
        }
        usort($findings, static fn (array $a, array $b): int => strcmp($a['key'], $b['key']));
        $document = [
            'version' => self::VERSION,
            'generated_at' => gmdate(DATE_ATOM),
            'note' => 'Findings listed here are accepted and do not affect the exit code of composer remediate --baseline. Remove entries as you fix them.',
            'findings' => $findings,
        ];
        if (@file_put_contents($path, json_encode($document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n") === false) {
            throw new \RuntimeException(sprintf('Cannot write baseline %s', $path));
        }
    }
}
