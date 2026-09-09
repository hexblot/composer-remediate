<?php

declare(strict_types=1);

namespace Remediate\Output;

use Remediate\Engine\Graph\DependencyPath;
use Remediate\Engine\Plan\EvaluatedCandidate;
use Remediate\Engine\Plan\FindingPlan;
use Remediate\Engine\Plan\Plan;
use Symfony\Component\Console\Formatter\OutputFormatter;

final class TextRenderer
{
    /**
     * @param bool $decorated emit Symfony console formatting tags (colours) for terminal output;
     *                        keep false when the text goes to a file
     */
    public function __construct(
        private readonly bool $minimalChangesSupported = true,
        private readonly bool $decorated = false,
    ) {
    }

    private function tag(string $text, string $style): string
    {
        if (!$this->decorated) {
            return $text;
        }

        return sprintf('<%s>%s</>', $style, OutputFormatter::escape($text));
    }

    private ?Plan $currentPlan = null;

    public function render(Plan $plan): string
    {
        $this->currentPlan = $plan;
        $out = [];
        $out[] = $this->tag(sprintf('Composer Remediate — %d finding%s in %s', count($plan->findings), count($plan->findings) === 1 ? '' : 's', $plan->metadata['project'] ?? ''), 'options=bold');
        $out[] = sprintf('Advisories: %s', $plan->metadata['advisory_source'] ?? '');
        $out[] = sprintf('Solver: %s', $plan->metadata['solver'] ?? '');
        foreach ($plan->warnings as $warning) {
            $out[] = $this->tag('Warning: ' . $warning, 'fg=yellow');
        }
        $out[] = '';

        if ($plan->findings === []) {
            $out[] = $this->tag('No known vulnerabilities in the locked dependencies.', 'fg=green');

            return implode("\n", $out) . "\n";
        }

        foreach ($plan->findings as $findingPlan) {
            array_push($out, ...$this->renderFinding($findingPlan));
            $out[] = '';
        }
        array_push($out, ...$this->renderSummary($plan));

        return implode("\n", $out) . "\n";
    }

    /** @return list<string> */
    private function renderSummary(Plan $plan): array
    {
        $out = [];
        $out[] = $this->tag('Summary', 'options=bold;options=underscore');
        $advisories = $plan->advisoryCount();
        $packages = count($plan->findings);
        $fixable = count($plan->findings) - count($plan->unsolved());
        $out[] = sprintf('  Findings: %d advisor%s on %d package%s, %d package%s with a verified fix', $advisories, $advisories === 1 ? 'y' : 'ies', $packages, $packages === 1 ? '' : 's', $fixable, $fixable === 1 ? '' : 's');

        $combined = $plan->combined;
        if ($combined === null && $fixable === 0) {
            $out[] = '  ' . $this->tag('No verified way to fix any of these findings.', 'fg=red');
        } elseif ($combined === null) {
            $out[] = '  No single command fixes everything; run the per-package commands above separately:';
            foreach ($plan->findings as $fp) {
                $rec = $fp->recommended();
                if ($rec !== null) {
                    $out[] = '    ' . $this->tag($rec->candidate->commandLine($this->minimalChangesSupported), 'fg=cyan');
                }
            }
        } elseif ($combined->fixesAll()) {
            $out[] = sprintf('  You can fix all %d finding%s with:', $advisories, $advisories === 1 ? '' : 's');
            $out[] = '    ' . $this->tag($combined->candidate->commandLine($this->minimalChangesSupported), 'fg=cyan;options=bold');
            $out[] = sprintf('    (%d package%s changed, verified by Composer)', $combined->diff->count(), $combined->diff->count() === 1 ? '' : 's');
        } else {
            $out[] = sprintf('  %s fixes %d of %d findings', $this->tag($combined->candidate->commandLine($this->minimalChangesSupported), 'fg=cyan;options=bold'), $combined->fixedCount(), $combined->totalCount());
            $out[] = sprintf('    (%d package%s changed, verified by Composer)', $combined->diff->count(), $combined->diff->count() === 1 ? '' : 's');
        }

        $unsolved = $plan->unsolved();
        if ($unsolved !== []) {
            $out[] = '  ' . $this->tag('No verified fix:', 'fg=red') . ' ' . implode('; ', array_map(static fn (FindingPlan $p): string => implode(', ', array_map(static fn ($f): string => $f->advisory->displayId(), $p->allFindings())) . ' on ' . $p->finding->packageName, $unsolved));
        }
        $dragged = array_filter($plan->findings, static fn (FindingPlan $p): bool => $p->constraintDrag() !== null);
        if ($dragged !== []) {
            $out[] = sprintf('  Constraint drag: %d fix%s require%s widening a constraint in composer.json.', count($dragged), count($dragged) === 1 ? '' : 'es', count($dragged) === 1 ? 's' : '');
        }
        $baselined = $plan->baselined();
        if ($baselined !== []) {
            $out[] = sprintf('  Baseline: %d package%s accepted earlier and excluded from the exit code (%s).', count($baselined), count($baselined) === 1 ? '' : 's', implode(', ', array_map(static fn (FindingPlan $p): string => $p->finding->packageName, $baselined)));
        }
        if ($plan->failOn !== null || $baselined !== []) {
            $gated = count($plan->gated());
            $out[] = sprintf('  Gate: %s%d of %d package%s count towards the exit code (%d).', $plan->failOn !== null ? '--fail-on ' . $plan->failOn . ', ' : '', $gated, $packages, $packages === 1 ? '' : 's', $plan->exitCode());
        }

        return $out;
    }

    /** @return list<string> */
    private function renderFinding(FindingPlan $plan): array
    {
        $f = $plan->finding;
        $out = [];
        $out[] = $this->tag(implode(', ', array_map(static fn ($finding): string => $finding->advisory->displayId(), $plan->allFindings())), 'fg=red;options=bold') . ($this->currentPlan?->isBaselined($plan) === true ? '  ' . $this->tag('[baselined]', 'fg=gray') : '');
        $out[] = str_repeat('─', 60);
        $out[] = $this->heading('Affected');
        $out[] = sprintf('  %s %s%s', $f->packageName, $f->prettyVersion, $f->viaReplacedName !== null ? sprintf(' (replaces %s)', $f->viaReplacedName) : '');
        foreach ($plan->allFindings() as $finding) {
            $a = $finding->advisory;
            $out[] = sprintf('  %s%s: %s', $a->displayId(), $a->cve !== null && $a->cve !== $a->id ? sprintf(' (%s)', $a->id) : '', $a->title ?? '(no title)');
            if ($a->link !== null) {
                $out[] = '    ' . $a->link;
            }
            $out[] = '    affected versions: ' . $a->affectedVersions->getPrettyString();
        }

        $out[] = $this->heading('Introduced by');
        if ($f->paths === []) {
            $out[] = '  (no path to the root package found)';
        }
        foreach (array_slice($f->paths, 0, 5) as $path) {
            array_push($out, ...$this->renderPath($f->packageName, $f->prettyVersion, $path));
        }
        if (count($f->paths) > 5) {
            $out[] = sprintf('  … and %d more path%s', count($f->paths) - 5, count($f->paths) - 5 === 1 ? '' : 's');
        }

        $out[] = $this->heading('Current state');
        $out[] = '  ' . ($f->isRootRequirement ? 'Direct dependency.' : 'Transitive dependency.') . ($f->isDev ? ' Development requirement only.' : '');

        $recommended = $plan->recommended();
        if ($recommended === null || $recommended->diff === null) {
            $out[] = $this->heading('Recommended remediation');
            $out[] = $this->tag(sprintf('  No verified remediation found (%s).', $plan->outcome()), 'fg=red');
            if ($plan->blocker !== null) {
                $out[] = '  ' . $plan->blocker;
            }
        } else {
            $diff = $recommended->diff;
            $target = $diff->changeFor($f->packageName);
            $out[] = $this->heading('Recommended remediation');
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
            $drag = $plan->constraintDrag();
            if ($drag !== null) {
                $out[] = '  ' . $this->tag('Constraint drag:', 'fg=yellow') . ' ' . $drag;
            }
            if ($recommended->blockingRisk !== []) {
                $out[] = '  ' . $this->tag('Blocking risk:', 'fg=yellow') . sprintf(' %s still carr%s another advisory after this update; Composer 2.10+ may refuse the command until that advisory is ignored in config.policy or blocking is disabled.', implode(', ', $recommended->blockingRisk), count($recommended->blockingRisk) === 1 ? 'ies' : 'y');
            }
            if ($diff->prereleaseTargets() !== []) {
                $out[] = '  Note: installs pre-release versions (' . implode(', ', array_map(static fn ($c): string => $c->packageName . ' ' . $c->toPretty, $diff->prereleaseTargets())) . '); no stable release satisfies the constraints yet.';
            }
            $out[] = $this->heading('Composer validation');
            $out[] = $this->tag('  PASS', 'fg=green;options=bold') . sprintf(
                '  %d package%s changed, %d added, %d removed, %d root constraint%s changed%s',
                count($diff->versionChanges()),
                count($diff->versionChanges()) === 1 ? '' : 's',
                count($diff->added()),
                count($diff->removed()),
                count($recommended->candidate->rootConstraintChanges),
                count($recommended->candidate->rootConstraintChanges) === 1 ? '' : 's',
                $diff->hasMajorChange() ? ', includes a major version change' : '',
            );
            $out[] = $this->heading('Expected changes');
            foreach (array_slice($diff->changes, 0, 30) as $change) {
                $out[] = '  ' . $change->describe();
            }
            if ($diff->count() > 30) {
                $out[] = sprintf('  … and %d more', $diff->count() - 30);
            }
            $out[] = $this->heading('Recommended command');
            $out[] = '  ' . $this->tag($recommended->candidate->commandLine($this->minimalChangesSupported), 'fg=cyan;options=bold');
        }

        $others = array_values(array_filter($plan->evaluated, static fn (EvaluatedCandidate $c): bool => $c !== $recommended));
        if ($others !== [] || $plan->skipped !== []) {
            $out[] = $this->heading('Other candidates');
            $rank = 2;
            foreach ($plan->ranked as $candidate) {
                if ($candidate === $recommended) {
                    continue;
                }
                $out[] = '  ' . $this->tag(sprintf('valid, rank %d:', $rank++), 'fg=green') . sprintf(' %s  (%d changes)', $candidate->candidate->commandLine($this->minimalChangesSupported), $candidate->diff?->count() ?? 0);
            }
            foreach ($others as $candidate) {
                if ($candidate->valid) {
                    continue;
                }
                $out[] = '  ' . $this->tag('rejected:', 'fg=yellow') . ' ' . $candidate->candidate->commandLine($this->minimalChangesSupported);
                $reason = $candidate->rejectionReason ?? '';
                foreach (array_slice(explode("\n", $reason), 0, 6) as $line) {
                    $out[] = '      ' . $line;
                }
            }
            foreach ($plan->skipped as $candidate) {
                $out[] = '  ' . $this->tag('not tried (a better candidate already exists):', 'fg=gray') . ' ' . $candidate->commandLine($this->minimalChangesSupported);
            }
        }

        return $out;
    }

    private function heading(string $text): string
    {
        return $this->tag($text, 'options=underscore');
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
