<?php

declare(strict_types=1);

namespace Remediate\Output;

use Remediate\Engine\Graph\DependencyPath;
use Remediate\Engine\Plan\CombinedOutcome;
use Remediate\Engine\Plan\EvaluatedCandidate;
use Remediate\Engine\Plan\FindingPlan;
use Remediate\Engine\Plan\Plan;

/**
 * Self-contained HTML report: inline CSS, no scripts, no external resources, so it can be stored as
 * a CI artifact or attached to a ticket and opened anywhere.
 */
final class HtmlRenderer
{
    public function __construct(private readonly bool $minimalChangesSupported = true)
    {
    }

    public function render(Plan $plan): string
    {
        $m = $plan->metadata;
        $count = count($plan->findings);
        $title = sprintf('Composer Remediate — %d finding%s', $count, $count === 1 ? '' : 's');

        $h = [];
        $h[] = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">';
        $h[] = '<title>' . self::e($title) . '</title>';
        $h[] = '<style>' . self::css() . '</style></head><body>';
        $h[] = '<header><h1>Composer Remediate</h1><p class="sub">' . self::e($title) . ' in <code>' . self::e($m['project'] ?? '') . '</code></p></header>';
        $h[] = '<main>';

        foreach ($plan->warnings as $warning) {
            $h[] = '<p class="warning">' . self::e($warning) . '</p>';
        }

        if ($plan->findings === []) {
            $h[] = '<p class="clean">No known vulnerabilities in the locked dependencies.</p>';
        } else {
            $h[] = $this->summary($plan);
            foreach ($plan->findings as $index => $findingPlan) {
                $h[] = $this->finding($findingPlan, $index + 1);
            }
        }

        $h[] = '<section class="meta"><h2>Analysis metadata</h2><dl>';
        foreach ($m as $key => $value) {
            $h[] = '<dt>' . self::e(str_replace('_', ' ', $key)) . '</dt><dd>' . self::e($value) . '</dd>';
        }
        $h[] = '</dl></section>';
        $h[] = '</main></body></html>';

        return implode("\n", $h) . "\n";
    }

    private function summary(Plan $plan): string
    {
        $rows = [];
        foreach ($plan->findings as $index => $fp) {
            $rec = $fp->recommended();
            $advisories = implode(', ', array_map(static fn ($f): string => $f->advisory->displayId(), $fp->allFindings()));
            $status = $rec === null ? '<span class="badge none">no verified fix</span>' : '<span class="badge ok">verified</span>';
            $command = $rec === null ? '—' : '<code>' . self::e($rec->candidate->commandLine($this->minimalChangesSupported)) . '</code>';
            $rows[] = sprintf(
                '<tr><td><a href="#finding-%d">%s %s</a>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>',
                $index + 1,
                self::e($fp->finding->packageName),
                self::e($fp->finding->prettyVersion),
                $fp->finding->isDev ? ' <span class="badge dev">dev</span>' : '',
                self::e($advisories),
                $status,
                $command,
            );
        }

        $combined = $plan->combined;
        $advisories = $plan->advisoryCount();
        $lead = sprintf('<p>%d advisor%s on %d package%s.</p>', $advisories, $advisories === 1 ? 'y' : 'ies', count($plan->findings), count($plan->findings) === 1 ? '' : 's');
        if ($combined !== null && $combined->fixesAll()) {
            $lead .= '<p class="command"><span class="badge ok">fixes all ' . $advisories . '</span> <code>' . self::e($combined->candidate->commandLine($this->minimalChangesSupported)) . '</code></p>';
        } elseif ($combined !== null) {
            $lead .= '<p class="command"><span class="badge ok">fixes ' . $combined->fixedCount() . ' of ' . $combined->totalCount() . '</span> <code>' . self::e($combined->candidate->commandLine($this->minimalChangesSupported)) . '</code></p>';
        } elseif (count($plan->unsolved()) === count($plan->findings)) {
            $lead .= '<p class="none-box">No verified way to fix any of these findings.</p>';
        } else {
            $lead .= '<p>No single command fixes everything; run the per-package commands below separately.</p>';
        }

        if (count($plan->combinedAttempts) > 1) {
            $items = [];
            foreach ($plan->combinedAttempts as $attempt) {
                $verdict = match ($attempt->outcome) {
                    CombinedOutcome::Accepted => $attempt->chosen ? 'fixes all, chosen' : 'fixes all, a smaller command was found',
                    CombinedOutcome::Partial => sprintf('fixes %d of %d', $attempt->fixed, $attempt->total),
                    CombinedOutcome::Unresolved => 'does not resolve',
                    default => 'rejected',
                };
                $items[] = '<li>' . self::e($attempt->note) . ': <code>' . self::e($attempt->candidate->commandLine($this->minimalChangesSupported)) . '</code> <span class="badge ' . ($attempt->chosen ? 'ok' : 'skipped') . '">' . self::e($verdict) . '</span>' . ($attempt->reason !== null && $attempt->outcome !== CombinedOutcome::Partial ? '<br><small>' . self::e(explode("\n", trim($attempt->reason))[0]) . '</small>' : '') . '</li>';
            }
            $lead .= '<details><summary>Combined command search (' . count($items) . ' solves)</summary><ul class="search">' . implode('', $items) . '</ul></details>';
        }

        return '<section><h2>Summary</h2>' . $lead . '<table class="summary"><thead><tr><th>Package</th><th>Advisories</th><th>Status</th><th>Recommended command</th></tr></thead><tbody>' . implode('', $rows) . '</tbody></table></section>';
    }

    private function finding(FindingPlan $plan, int $number): string
    {
        $f = $plan->finding;
        $h = [];
        $h[] = sprintf('<section class="finding" id="finding-%d">', $number);
        $h[] = '<h2>' . self::e($f->packageName) . ' <span class="version">' . self::e($f->prettyVersion) . '</span>' . ($f->viaReplacedName !== null ? ' <small>replaces ' . self::e($f->viaReplacedName) . '</small>' : '') . '</h2>';
        $h[] = '<p class="state">' . ($f->isRootRequirement ? 'Direct dependency.' : 'Transitive dependency.') . ($f->isDev ? ' Development requirement only.' : '') . '</p>';
        if ($f->abandoned !== []) {
            $h[] = '<p class="abandoned"><strong>Abandoned:</strong> ' . self::e(TextRenderer::abandonedLine($f)) . '</p>';
        }

        $h[] = '<h3>Advisories</h3><ul class="advisories">';
        foreach ($plan->allFindings() as $finding) {
            $a = $finding->advisory;
            $label = self::e($a->displayId()) . ($a->cve !== null && $a->cve !== $a->id ? ' <small>(' . self::e($a->id) . ')</small>' : '');
            $safeLink = self::safeUrl($a->link);
            $h[] = '<li><strong>' . ($safeLink !== null ? '<a href="' . self::e($safeLink) . '" rel="noopener noreferrer">' . $label . '</a>' : $label) . '</strong>'
                . ($a->severity !== null ? ' <span class="badge sev-' . self::e(strtolower($a->severity)) . '">' . self::e($a->severity) . '</span>' : '')
                . ($a->isKnownExploited() ? ' <span class="badge kev">KEV</span>' : '')
                . ($a->epss !== null ? ' <span class="badge epss">EPSS ' . self::e(sprintf('%.2f', $a->epss)) . '</span>' : '')
                . ($a->title !== null ? '<br>' . self::e($a->title) : '')
                . '<br><small>affected versions: <code>' . self::e($a->affectedVersions->getPrettyString()) . '</code></small>'
                . (TextRenderer::exploitLine($a) !== null ? '<br><small>' . self::e((string) TextRenderer::exploitLine($a)) . '</small>' : '')
                . '</li>';
        }
        $h[] = '</ul>';

        $h[] = '<h3>Introduced by</h3>';
        if ($f->paths === []) {
            $h[] = '<p>(no path to the root package found)</p>';
        } else {
            $h[] = '<pre class="tree">' . self::e(implode("\n\n", array_map(fn (DependencyPath $p): string => $this->path($f->packageName, $f->prettyVersion, $p), array_slice($f->paths, 0, 5)))) . '</pre>';
            if (count($f->paths) > 5) {
                $h[] = sprintf('<p><small>… and %d more path%s</small></p>', count($f->paths) - 5, count($f->paths) - 5 === 1 ? '' : 's');
            }
        }

        $rec = $plan->recommended();
        if ($rec === null || $rec->diff === null) {
            $h[] = '<h3>Recommended remediation</h3><p class="none-box">No verified remediation found (' . self::e($plan->outcome()) . ').' . ($plan->blocker !== null ? ' ' . self::e($plan->blocker) : '') . '</p>';
        } else {
            $diff = $rec->diff;
            $h[] = '<h3>Recommended remediation</h3>';
            $h[] = '<p class="command"><code>' . self::e($rec->candidate->commandLine($this->minimalChangesSupported)) . '</code></p>';
            $h[] = sprintf(
                '<p class="validation"><span class="badge ok">Composer validation: PASS</span> %d package%s changed, %d added, %d removed, %d root constraint%s changed%s.</p>',
                count($diff->versionChanges()),
                count($diff->versionChanges()) === 1 ? '' : 's',
                count($diff->added()),
                count($diff->removed()),
                count($rec->candidate->rootConstraintChanges),
                count($rec->candidate->rootConstraintChanges) === 1 ? '' : 's',
                $diff->hasMajorChange() ? ', <strong>includes a major version change</strong>' : '',
            );
            foreach ($rec->candidate->rootConstraintChanges as $change) {
                $h[] = '<p>composer.json: <code>' . self::e($change->packageName) . '</code> ' . self::e($change->fromConstraint ?? '(new)') . ' → <code>' . self::e($change->toConstraint) . '</code></p>';
            }
            if ($diff->prereleaseTargets() !== []) {
                $h[] = '<p class="warning">Installs pre-release versions: ' . self::e(implode(', ', array_map(static fn ($c): string => $c->packageName . ' ' . $c->toPretty, $diff->prereleaseTargets()))) . '. No stable release satisfies the constraints yet.</p>';
            }
            $h[] = '<details open><summary>Expected changes (' . $diff->count() . ')</summary><table class="changes"><thead><tr><th>Package</th><th>From</th><th>To</th><th>Kind</th></tr></thead><tbody>';
            foreach ($diff->changes as $change) {
                $h[] = '<tr><td>' . self::e($change->packageName) . '</td><td>' . self::e($change->fromPretty ?? '—') . '</td><td>' . self::e($change->toPretty ?? '—') . '</td><td>' . self::e($change->kind . ($change->step !== null ? ', ' . $change->step->value : '')) . '</td></tr>';
            }
            $h[] = '</tbody></table></details>';
        }

        $others = array_values(array_filter($plan->evaluated, static fn (EvaluatedCandidate $c): bool => $c !== $rec));
        if ($others !== [] || $plan->skipped !== []) {
            $h[] = '<details><summary>Other candidates (' . (count($others) + count($plan->skipped)) . ')</summary><table class="candidates"><thead><tr><th>Outcome</th><th>Command</th><th>Detail</th></tr></thead><tbody>';
            $rank = 2;
            foreach ($plan->ranked as $c) {
                if ($c === $rec) {
                    continue;
                }
                $h[] = '<tr><td><span class="badge ok">valid, rank ' . $rank++ . '</span></td><td><code>' . self::e($c->candidate->commandLine($this->minimalChangesSupported)) . '</code></td><td>' . ($c->diff?->count() ?? 0) . ' changes</td></tr>';
            }
            foreach ($others as $c) {
                if ($c->valid) {
                    continue;
                }
                $h[] = '<tr><td><span class="badge rejected">rejected</span></td><td><code>' . self::e($c->candidate->commandLine($this->minimalChangesSupported)) . '</code></td><td><pre class="reason">' . self::e((string) $c->rejectionReason) . '</pre></td></tr>';
            }
            foreach ($plan->skipped as $c) {
                $h[] = '<tr><td><span class="badge skipped">not tried</span></td><td><code>' . self::e($c->commandLine($this->minimalChangesSupported)) . '</code></td><td>a better candidate already exists</td></tr>';
            }
            $h[] = '</tbody></table></details>';
        }
        $h[] = '</section>';

        return implode("\n", $h);
    }

    private function path(string $package, string $version, DependencyPath $path): string
    {
        $chain = array_reverse($path->segments);
        $lines = [];
        $indent = '';
        $first = true;
        foreach ($chain as $segment) {
            if ($segment->isRoot) {
                $lines[] = 'root';
                $first = false;
                continue;
            }
            $lines[] = $indent . ($first ? '' : '└── ') . $segment->packageName . ' ' . $segment->prettyVersion;
            $indent .= $first ? '' : '    ';
            $first = false;
        }
        $last = $chain[count($chain) - 1] ?? null;
        $lines[] = $indent . '└── ' . $package . ' ' . $version . ($last !== null ? '  (requires ' . $last->requiresConstraint . ')' : '');
        if ($path->cyclic) {
            $lines[] = $indent . '    (dependency cycle detected above)';
        }

        return implode("\n", $lines);
    }

    private static function e(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    }

    /**
     * Advisory links are untrusted data. Only http(s) URLs become anchors; anything else (javascript:,
     * data:, vbscript:, relative paths) is dropped and the id is shown as plain text.
     */
    public static function safeUrl(?string $url): ?string
    {
        if ($url === null) {
            return null;
        }
        $url = trim($url);
        if (preg_match('{^https?://[^\s<>"\']+$}i', $url) !== 1) {
            return null;
        }

        return $url;
    }

    private static function css(): string
    {
        return <<<'CSS'
:root{color-scheme:light dark;--bg:#fff;--fg:#1c1e21;--muted:#5f6b7a;--border:#d9dee5;--panel:#f6f8fa;--ok:#1a7f37;--bad:#b42318;--warn:#9a6700;--accent:#0f6b8a}
@media(prefers-color-scheme:dark){:root{--bg:#0f1418;--fg:#e6edf3;--muted:#9aa7b4;--border:#2b3640;--panel:#161c22;--ok:#3fb950;--bad:#f0665b;--warn:#d4a72c;--accent:#58b8d8}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{padding:1.5rem 2rem;border-bottom:1px solid var(--border)}header h1{margin:0;font-size:1.4rem}.sub{margin:.25rem 0 0;color:var(--muted)}
main{max-width:70rem;margin:0 auto;padding:1rem 2rem 3rem}
section{margin:1.5rem 0}.finding{border:1px solid var(--border);border-radius:8px;padding:1rem 1.25rem;background:var(--panel)}
h2{font-size:1.15rem;margin:.25rem 0 .5rem}h3{font-size:.95rem;margin:1rem 0 .35rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.version{font-weight:400;color:var(--muted)}.state{margin:0;color:var(--muted)}
code{font:.9em ui-monospace,SFMono-Regular,Menlo,monospace;background:rgba(127,127,127,.12);padding:.1em .35em;border-radius:4px;word-break:break-all}
pre{font:.85rem ui-monospace,SFMono-Regular,Menlo,monospace;background:rgba(127,127,127,.1);padding:.75rem 1rem;border-radius:6px;overflow-x:auto;margin:.25rem 0}
pre.reason{white-space:pre-wrap;margin:0;background:none;padding:0}
.command code{display:block;padding:.6rem .8rem;font-size:.95rem;border-left:4px solid var(--accent)}
table{border-collapse:collapse;width:100%;font-size:.92rem}th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid var(--border);vertical-align:top}th{color:var(--muted);font-weight:600}
.badge{display:inline-block;font-size:.75rem;font-weight:600;padding:.1rem .5rem;border-radius:999px;border:1px solid currentColor;white-space:nowrap}
.badge.ok{color:var(--ok)}.badge.none,.badge.rejected{color:var(--bad)}.badge.skipped,.badge.dev{color:var(--muted)}
.badge.sev-critical,.badge.sev-high{color:var(--bad)}.badge.sev-medium{color:var(--warn)}.badge.sev-low{color:var(--muted)}
.badge.kev{color:#fff;background:var(--bad);border-color:var(--bad)}.badge.epss{color:var(--warn)}.abandoned{color:var(--warn)}
.warning{border-left:4px solid var(--warn);padding:.5rem .8rem;background:rgba(212,167,44,.1)}.clean{color:var(--ok);font-weight:600}
.none-box{border-left:4px solid var(--bad);padding:.5rem .8rem;background:rgba(180,35,24,.08)}
.advisories{padding-left:1.2rem}.advisories li{margin:.4rem 0}
details summary{cursor:pointer;color:var(--accent);margin:.5rem 0}
.meta dl{display:grid;grid-template-columns:max-content 1fr;gap:.2rem 1rem;font-size:.85rem;color:var(--muted)}.meta dt{font-weight:600}.meta dd{margin:0;word-break:break-all}
CSS;
    }
}
