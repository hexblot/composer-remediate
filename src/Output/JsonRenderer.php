<?php

declare(strict_types=1);

namespace Remediate\Output;

use Remediate\Engine\Graph\DependencyPath;
use Remediate\Engine\Matching\Finding;
use Remediate\Engine\Plan\EvaluatedCandidate;
use Remediate\Engine\Plan\FindingPlan;
use Remediate\Engine\Plan\Plan;
use Remediate\Engine\Solver\LockDiff;

/**
 * Machine-readable report with the same content as the text and HTML reports.
 * Schema version is bumped on incompatible changes.
 */
final class JsonRenderer
{
    public const SCHEMA_VERSION = 1;

    /** Dependency paths listed per finding; the total is always reported in paths_total. */
    public const MAX_PATHS = 10;

    public function __construct(private readonly bool $minimalChangesSupported = true)
    {
    }

    public function render(Plan $plan): string
    {
        return json_encode($this->toArray($plan), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR) . "\n";
    }

    /** @return array<string, mixed> */
    public function toArray(Plan $plan): array
    {
        $findings = [];
        $unsolved = [];
        foreach ($plan->findings as $fp) {
            $findings[] = $this->findingPlan($fp);
            if (!$fp->hasRemediation()) {
                $unsolved[] = $fp->finding->packageName;
            }
        }

        $combined = $plan->combined;

        return [
            'schema_version' => self::SCHEMA_VERSION,
            'analysis_metadata' => $plan->metadata,
            'exit_code' => $plan->exitCode(),
            'warnings' => $plan->warnings,
            'summary' => [
                'advisories' => $plan->advisoryCount(),
                'packages' => count($plan->findings),
                'packages_with_fix' => count($plan->findings) - count($plan->unsolved()),
                'combined_command' => $combined?->candidate->commandLine($this->minimalChangesSupported),
                'combined_fixes' => $combined?->fixedCount(),
                'combined_total' => $combined?->totalCount(),
                'combined_fixes_all' => $combined?->fixesAll(),
                'combined_changes' => $combined === null ? null : self::summary($combined->diff),
            ],
            'findings' => $findings,
            'unsolved_findings' => $unsolved,
        ];
    }

    /** @return array<string, mixed> */
    private function findingPlan(FindingPlan $fp): array
    {
        $f = $fp->finding;
        $rec = $fp->recommended();
        $candidates = [];
        $rank = 1;
        foreach ($fp->ranked as $c) {
            $candidates[] = $this->candidate($c, 'valid', $rank++);
        }
        foreach ($fp->evaluated as $c) {
            if (!$c->valid) {
                $candidates[] = $this->candidate($c, 'rejected', null);
            }
        }
        foreach ($fp->skipped as $c) {
            $candidates[] = [
                'command' => $c->commandLine($this->minimalChangesSupported),
                'strategy' => $c->strategy->value,
                'outcome' => 'skipped',
                'reason' => 'a better candidate already exists',
            ];
        }

        return [
            'package' => $f->packageName,
            'version' => $f->prettyVersion,
            'version_normalized' => $f->version,
            'direct' => $f->isRootRequirement,
            'dev' => $f->isDev,
            'via_replaced_package' => $f->viaReplacedName,
            'advisories' => array_map(static fn (Finding $x): array => [
                'id' => $x->advisory->id,
                'cve' => $x->advisory->cve,
                'title' => $x->advisory->title,
                'link' => $x->advisory->link,
                'severity' => $x->advisory->severity,
                'reported_at' => $x->advisory->reportedAt?->format(DATE_RFC3339),
                'affected_versions' => $x->advisory->affectedVersions->getPrettyString(),
                'sources' => $x->advisory->sources,
            ], $fp->allFindings()),
            'paths_total' => count($f->paths),
            'paths' => array_map(static fn (DependencyPath $p): array => [
                'cyclic' => $p->cyclic,
                'chain' => array_map(static fn ($s): array => ['package' => $s->isRoot ? 'root' : $s->packageName, 'version' => $s->isRoot ? null : $s->prettyVersion, 'requires' => $s->requiresConstraint], array_reverse($p->segments)),
                'target' => ['package' => $f->packageName, 'version' => $f->prettyVersion],
            ], array_slice($f->paths, 0, self::MAX_PATHS)),
            'remediation' => $rec === null ? ['status' => 'none', 'blocker' => $fp->blocker] : [
                'status' => 'verified',
                'command' => $rec->candidate->commandLine($this->minimalChangesSupported),
                'strategy' => $rec->candidate->strategy->value,
                'root_constraint_changes' => array_values(array_map(static fn ($c): array => ['package' => $c->packageName, 'from' => $c->fromConstraint, 'to' => $c->toConstraint, 'dev' => $c->isDev], $rec->candidate->rootConstraintChanges)),
                'summary' => $rec->diff === null ? null : self::summary($rec->diff),
                'changes' => $rec->diff === null ? [] : self::changes($rec->diff),
            ],
            'candidates' => $candidates,
        ];
    }

    /** @return array<string, mixed> */
    private function candidate(EvaluatedCandidate $c, string $outcome, ?int $rank): array
    {
        $data = [
            'command' => $c->candidate->commandLine($this->minimalChangesSupported),
            'strategy' => $c->candidate->strategy->value,
            'outcome' => $outcome,
        ];
        if ($rank !== null) {
            $data['rank'] = $rank;
        }
        if ($c->rejectionReason !== null) {
            $data['reason'] = $c->rejectionReason;
        }
        if ($c->diff !== null) {
            $data['summary'] = self::summary($c->diff);
        }
        $data['solver_status'] = $c->result->status->value;

        return $data;
    }

    /** @return array<string, int|bool> */
    private static function summary(LockDiff $diff): array
    {
        return [
            'changed' => count($diff->versionChanges()),
            'added' => count($diff->added()),
            'removed' => count($diff->removed()),
            'total' => $diff->count(),
            'major_change' => $diff->hasMajorChange(),
            'downgrade' => $diff->hasDowngrade(),
            'prerelease' => $diff->prereleaseTargets() !== [],
        ];
    }

    /** @return list<array<string, string|null>> */
    private static function changes(LockDiff $diff): array
    {
        return array_map(static fn ($c): array => [
            'package' => $c->packageName,
            'kind' => $c->kind,
            'step' => $c->step?->value,
            'from' => $c->fromPretty,
            'to' => $c->toPretty,
        ], $diff->changes);
    }
}
