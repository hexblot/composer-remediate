<?php

declare(strict_types=1);

namespace Remediate\Output;

use Remediate\Engine\Plan\Plan;

enum ReportFormat: string
{
    case Text = 'text';
    case Html = 'html';
    case Json = 'json';
    case Sarif = 'sarif';
    case CycloneDx = 'cyclonedx';
    case None = 'none';

    /**
     * Accepts "html", "report.html", "report.sarif", "results.sarif.json", "sbom.cdx.json",
     * "json:build/report.json" and returns [format, path|null].
     *
     * @return array{self, string|null}
     */
    public static function parseOutputSpec(string $spec): array
    {
        if (preg_match('{^(text|html|json|sarif|cyclonedx):(.+)$}i', $spec, $m) === 1) {
            return [self::from(strtolower($m[1])), $m[2]];
        }
        $lower = strtolower($spec);
        if (str_ends_with($lower, '.sarif.json')) {
            return [self::Sarif, $spec];
        }
        if (str_ends_with($lower, '.cdx.json') || str_ends_with($lower, '.bom.json') || basename($lower) === 'bom.json') {
            return [self::CycloneDx, $spec];
        }
        $extension = strtolower(pathinfo($spec, PATHINFO_EXTENSION));
        $format = match ($extension) {
            'html', 'htm' => self::Html,
            'json' => self::Json,
            'sarif' => self::Sarif,
            'cdx' => self::CycloneDx,
            'txt', 'text', 'log', 'md' => self::Text,
            default => null,
        };
        if ($format === null) {
            throw new \InvalidArgumentException(sprintf('Cannot infer a report format from "%s"; use a .html/.json/.sarif/.cdx.json/.txt extension or prefix with html:, json:, sarif:, cyclonedx: or text:.', $spec));
        }

        return [$format, $spec];
    }

    public function render(Plan $plan, bool $minimalChangesSupported, bool $decorated = false, ?LockLineIndex $lockLines = null): string
    {
        return match ($this) {
            self::Text => (new TextRenderer($minimalChangesSupported, $decorated))->render($plan),
            self::Html => (new HtmlRenderer($minimalChangesSupported))->render($plan),
            self::Json => (new JsonRenderer($minimalChangesSupported))->render($plan),
            self::Sarif => (new SarifRenderer($minimalChangesSupported, $lockLines ?? LockLineIndex::empty()))->render($plan),
            self::CycloneDx => (new CycloneDxRenderer($minimalChangesSupported))->render($plan),
            self::None => '',
        };
    }
}
