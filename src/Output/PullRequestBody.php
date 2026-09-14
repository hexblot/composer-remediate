<?php

declare(strict_types=1);

namespace Remediate\Output;

/**
 * The description of one batched pull request: what was vulnerable before the run, what the applied
 * command was, and what is left afterwards.
 *
 * It reads two JSON reports rather than a plan, because the two states come from two runs of the
 * command, one before `--apply` and one after it. A reviewer of the pull request should be able to
 * answer "what did this fix, what did it move, and what is still open" without leaving the page, and
 * should be able to see when the answer is "less than you would hope".
 */
final class PullRequestBody
{
    /**
     * @param array<string, mixed> $before the report from the run that planned the fix
     * @param array<string, mixed> $after  the report from the run that applied it
     * @param list<string>         $commands the commands that ran, as the applying run recorded them
     */
    public static function render(array $before, array $after, array $commands = []): string
    {
        $beforeSummary = self::summary($before);
        $afterSummary = self::summary($after);
        $fixed = self::advisoryIds($before);
        $remaining = self::advisoryIds($after);
        $closed = array_values(array_diff($fixed, $remaining));
        sort($closed);

        $lines = [];
        $lines[] = sprintf(
            '%s of %s advisories closed, on %s of %s packages.',
            count($closed),
            count($fixed),
            max(0, (int) $beforeSummary['packages'] - (int) $afterSummary['packages']),
            $beforeSummary['packages'],
        );
        $lines[] = '';

        if ($commands !== []) {
            $lines[] = '## What ran';
            $lines[] = '';
            $lines[] = '```bash';
            foreach ($commands as $command) {
                $lines[] = $command;
            }
            $lines[] = '```';
            $lines[] = '';
        }

        $lines[] = '## Closed';
        $lines[] = '';
        if ($closed === []) {
            $lines[] = 'Nothing. The command resolved and changed the lock, but every advisory that was';
            $lines[] = 'present before it is present after it. Read this pull request carefully.';
        } else {
            $lines[] = '| Advisory | Package | Severity | Was |';
            $lines[] = '|---|---|---|---|';
            foreach (self::advisoryRows($before, $closed) as $row) {
                $lines[] = $row;
            }
        }
        $lines[] = '';

        $stillOpen = self::advisoryRows($after, $remaining);
        if ($stillOpen !== []) {
            $lines[] = '## Still open';
            $lines[] = '';
            $lines[] = sprintf('%d advisor%s survived this run.', count($stillOpen), count($stillOpen) === 1 ? 'y' : 'ies');
            $lines[] = '';
            $lines[] = '| Advisory | Package | Severity | Fix |';
            $lines[] = '|---|---|---|---|';
            foreach (self::openRows($after) as $row) {
                $lines[] = $row;
            }
            $lines[] = '';
        }

        $warnings = is_array($after['warnings'] ?? null) ? $after['warnings'] : [];
        if ($warnings !== []) {
            $lines[] = '## Warnings from the run that applied it';
            $lines[] = '';
            foreach ($warnings as $warning) {
                $lines[] = '- ' . self::text($warning);
            }
            $lines[] = '';
        }

        $lines[] = sprintf(
            'Exit code %s before, %s after. Every command here was verified by Composer\'s own solver in a dry run before it was applied, and the state above is the project as the run left it, not a prediction.',
            $before['exit_code'] ?? '?',
            $after['exit_code'] ?? '?',
        );

        return implode("\n", $lines) . "\n";
    }

    /**
     * @param array<string, mixed> $report
     *
     * @return array{packages: mixed, advisories: mixed}
     */
    private static function summary(array $report): array
    {
        $summary = is_array($report['summary'] ?? null) ? $report['summary'] : [];

        return ['packages' => $summary['packages'] ?? 0, 'advisories' => $summary['advisories'] ?? 0];
    }

    /**
     * @param array<string, mixed> $report
     *
     * @return list<string> advisory keys (id@package), which is what "the same advisory" means here
     */
    private static function advisoryIds(array $report): array
    {
        $keys = [];
        foreach (is_array($report['findings'] ?? null) ? $report['findings'] : [] as $finding) {
            if (!is_array($finding)) {
                continue;
            }
            foreach (is_array($finding['advisories'] ?? null) ? $finding['advisories'] : [] as $advisory) {
                if (is_array($advisory) && is_string($advisory['id'] ?? null)) {
                    $keys[] = $advisory['id'] . '@' . (is_string($finding['package'] ?? null) ? $finding['package'] : '?');
                }
            }
        }

        return $keys;
    }

    /**
     * @param array<string, mixed> $report
     * @param list<string>         $keys
     *
     * @return list<string>
     */
    private static function advisoryRows(array $report, array $keys): array
    {
        $wanted = array_flip($keys);
        $rows = [];
        foreach (is_array($report['findings'] ?? null) ? $report['findings'] : [] as $finding) {
            if (!is_array($finding)) {
                continue;
            }
            $package = is_string($finding['package'] ?? null) ? $finding['package'] : '?';
            foreach (is_array($finding['advisories'] ?? null) ? $finding['advisories'] : [] as $advisory) {
                if (!is_array($advisory) || !is_string($advisory['id'] ?? null) || !isset($wanted[$advisory['id'] . '@' . $package])) {
                    continue;
                }
                $rows[] = sprintf(
                    '| %s | `%s` | %s | %s |',
                    self::identifier($advisory),
                    self::text($package),
                    self::text(is_string($advisory['severity'] ?? null) ? $advisory['severity'] : 'unknown'),
                    self::text(is_string($finding['version'] ?? null) ? $finding['version'] : '?'),
                );
            }
        }

        return $rows;
    }

    /**
     * @param array<string, mixed> $report
     *
     * @return list<string>
     */
    private static function openRows(array $report): array
    {
        $rows = [];
        foreach (is_array($report['findings'] ?? null) ? $report['findings'] : [] as $finding) {
            if (!is_array($finding)) {
                continue;
            }
            $remediation = is_array($finding['remediation'] ?? null) ? $finding['remediation'] : [];
            $fix = ($remediation['status'] ?? null) === 'verified' && is_string($remediation['command'] ?? null)
                ? '`' . self::text($remediation['command']) . '`'
                : 'none found (' . self::text(is_string($remediation['outcome'] ?? null) ? $remediation['outcome'] : 'see the report') . ')';
            $package = is_string($finding['package'] ?? null) ? $finding['package'] : '?';
            foreach (is_array($finding['advisories'] ?? null) ? $finding['advisories'] : [] as $advisory) {
                if (!is_array($advisory)) {
                    continue;
                }
                $rows[] = sprintf('| %s | `%s` | %s | %s |', self::identifier($advisory), self::text($package), self::text(is_string($advisory['severity'] ?? null) ? $advisory['severity'] : 'unknown'), $fix);
            }
        }

        return $rows;
    }

    /** @param array<string, mixed> $advisory */
    private static function identifier(array $advisory): string
    {
        $id = is_string($advisory['cve'] ?? null) && $advisory['cve'] !== '' ? $advisory['cve'] : (is_string($advisory['id'] ?? null) ? $advisory['id'] : '?');
        $link = is_string($advisory['link'] ?? null) && preg_match('{^https?://}i', $advisory['link']) === 1 ? $advisory['link'] : null;

        return $link === null ? self::text($id) : sprintf('[%s](%s)', self::text($id), self::text($link));
    }

    /**
     * Advisory text is upstream data. It reaches a pull request description, which is Markdown that
     * GitHub renders, so the characters that would end a table cell, start a link or open a tag are
     * escaped rather than trusted.
     */
    private static function text(mixed $value): string
    {
        $text = is_scalar($value) ? (string) $value : '';
        $text = ConsoleText::stripControls($text);

        return str_replace(['|', '<', '>', '[', ']', '`'], ['\|', '&lt;', '&gt;', '\[', '\]', '\`'], $text);
    }
}
