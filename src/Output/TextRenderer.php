<?php

declare(strict_types=1);

namespace Remediate\Output;

use Remediate\Engine\Graph\DependencyPath;
use Remediate\Engine\Plan\EvaluatedCandidate;
use Remediate\Engine\Plan\FindingPlan;
use Remediate\Engine\Plan\Plan;

final class TextRenderer
{
    public function __construct(private readonly bool $minimalChangesSupported = true)
    {
    }

    public function render(Plan $plan): string
    {
        $out = [];
        $out[] = sprintf('Composer Remediate — %d finding%s in %s', count($plan->findings), count($plan->findings) === 1 ? '' : 's', $plan->metadata['project'] ?? '');
        $out[] = sprintf('Advisories: %s', $plan->metadata['advisory_source'] ?? '');
        $out[] = sprintf('Solver: %s', $plan->metadata['solver'] ?? '');
        foreach ($plan->warnings as $warning) {
            $out[] = 'Warning: ' . $warning;
        }
        $out[] = '';

        if ($plan->findings === []) {
            $out[] = 'No known vulnerabilities in the locked dependencies.';

            return implode("\n", $out) . "\n";
        }

        foreach ($plan->findings as $findingPlan) {
            array_push($out, ...$this->renderFinding($findingPlan));
            $out[] = '';
        }

        return implode("\n", $out) . "\n";
    }

    /** @return list<string> */
    private function renderFinding(FindingPlan $plan): array
    {
        $f = $plan->finding;
        $out = [];
        $out[] = implode(', ', array_map(static fn ($finding): string => $finding->advisory->displayId(), $plan->allFindings()));
        $out[] = str_repeat('─', 60);
        $out[] = 'Affected';
        $out[] = sprintf('  %s %s%s', $f->packageName, $f->prettyVersion, $f->viaReplacedName !== null ? sprintf(' (replaces %s)', $f->viaReplacedName) : '');
        foreach ($plan->allFindings() as $finding) {
            $a = $finding->advisory;
            $out[] = sprintf('  %s%s: %s', $a->displayId(), $a->cve !== null && $a->cve !== $a->id ? sprintf(' (%s)', $a->id) : '', $a->title ?? '(no title)');
            if ($a->link !== null) {
                $out[] = '    ' . $a->link;
            }
            $out[] = '    affected versions: ' . $a->affectedVersions->getPrettyString();
        }

        $out[] = 'Introduced by';
        if ($f->paths === []) {
            $out[] = '  (no path to the root package found)';
        }
        foreach (array_slice($f->paths, 0, 5) as $path) {
            array_push($out, ...$this->renderPath($f->packageName, $f->prettyVersion, $path));
        }
        if (count($f->paths) > 5) {
            $out[] = sprintf('  … and %d more path%s', count($f->paths) - 5, count($f->paths) - 5 === 1 ? '' : 's');
        }

        $out[] = 'Current state';
        $out[] = '  ' . ($f->isRootRequirement ? 'Direct dependency.' : 'Transitive dependency.') . ($f->isDev ? ' Development requirement only.' : '');

        $recommended = $plan->recommended();
        if ($recommended === null || $recommended->diff === null) {
            $out[] = 'Recommended remediation';
            $out[] = '  No verified remediation found.';
            if ($plan->blocker !== null) {
                $out[] = '  ' . $plan->blocker;
            }
        } else {
            $diff = $recommended->diff;
            $target = $diff->changeFor($f->packageName);
            $out[] = 'Recommended remediation';
            foreach ($recommended->candidate->allowList as $name) {
                $change = $diff->changeFor($name);
                if ($change !== null) {
                    $out[] = '  ' . $change->describe();
                }
            }
            if ($target !== null && !in_array($f->packageName, $recommended->candidate->allowList, true)) {
                $out[] = '  ' . $target->describe();
            }
            foreach ($recommended->candidate->rootConstraintChanges as $change) {
                $out[] = sprintf('  composer.json: %s %s -> %s', $change->packageName, $change->fromConstraint ?? '(new)', $change->toConstraint);
            }
            $out[] = 'Composer validation';
            $out[] = sprintf(
                '  PASS  %d package%s changed, %d added, %d removed, %d root constraint%s changed%s',
                count($diff->versionChanges()),
                count($diff->versionChanges()) === 1 ? '' : 's',
                count($diff->added()),
                count($diff->removed()),
                count($recommended->candidate->rootConstraintChanges),
                count($recommended->candidate->rootConstraintChanges) === 1 ? '' : 's',
                $diff->hasMajorChange() ? ', includes a major version change' : '',
            );
            $out[] = 'Expected changes';
            foreach (array_slice($diff->changes, 0, 30) as $change) {
                $out[] = '  ' . $change->describe();
            }
            if ($diff->count() > 30) {
                $out[] = sprintf('  … and %d more', $diff->count() - 30);
            }
            $out[] = 'Recommended command';
            $out[] = '  ' . $recommended->candidate->commandLine($this->minimalChangesSupported);
        }

        $others = array_values(array_filter($plan->evaluated, static fn (EvaluatedCandidate $c): bool => $c !== $recommended));
        if ($others !== [] || $plan->skipped !== []) {
            $out[] = 'Other candidates';
            $rank = 2;
            foreach ($plan->ranked as $candidate) {
                if ($candidate === $recommended) {
                    continue;
                }
                $out[] = sprintf('  valid, rank %d: %s  (%d changes)', $rank++, $candidate->candidate->commandLine($this->minimalChangesSupported), $candidate->diff?->count() ?? 0);
            }
            foreach ($others as $candidate) {
                if ($candidate->valid) {
                    continue;
                }
                $out[] = sprintf('  rejected: %s', $candidate->candidate->commandLine($this->minimalChangesSupported));
                $reason = $candidate->rejectionReason ?? '';
                foreach (array_slice(explode("\n", $reason), 0, 6) as $line) {
                    $out[] = '      ' . $line;
                }
            }
            foreach ($plan->skipped as $candidate) {
                $out[] = sprintf('  not tried (a better candidate already exists): %s', $candidate->commandLine($this->minimalChangesSupported));
            }
        }

        return $out;
    }

    /** @return list<string> */
    private function renderPath(string $package, string $version, DependencyPath $path): array
    {
        $chain = array_reverse($path->segments);
        $lines = [];
        $indent = '  ';
        $first = true;
        foreach ($chain as $segment) {
            if ($segment->isRoot) {
                $lines[] = $indent . 'root';
                $first = false;
                continue;
            }
            $lines[] = $indent . ($first ? '' : '└── ') . sprintf('%s %s', $segment->packageName, $segment->prettyVersion);
            $indent .= $first ? '' : '    ';
            $first = false;
        }
        $last = $chain[count($chain) - 1] ?? null;
        $requires = $last !== null ? sprintf('  (requires %s)', $last->requiresConstraint) : '';
        $lines[] = $indent . '└── ' . sprintf('%s %s%s', $package, $version, $requires);
        if ($path->cyclic) {
            $lines[] = $indent . '    (dependency cycle detected above)';
        }

        return $lines;
    }
}
