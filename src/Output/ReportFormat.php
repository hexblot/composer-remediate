<?php

declare(strict_types=1);

namespace Remediate\Output;

use Remediate\Engine\Plan\Plan;

enum ReportFormat: string
{
    case Text = 'text';
    case Html = 'html';
    case Json = 'json';
    case None = 'none';

    /**
     * Accepts "html", "report.html", "json:build/report.json" and returns [format, path|null].
     *
     * @return array{self, string|null}
     */
    public static function parseOutputSpec(string $spec): array
    {
        if (preg_match('{^(text|html|json):(.+)$}i', $spec, $m) === 1) {
            return [self::from(strtolower($m[1])), $m[2]];
        }
        $extension = strtolower(pathinfo($spec, PATHINFO_EXTENSION));
        $format = match ($extension) {
            'html', 'htm' => self::Html,
            'json' => self::Json,
            'txt', 'text', 'log', 'md' => self::Text,
            default => null,
        };
        if ($format === null) {
            throw new \InvalidArgumentException(sprintf('Cannot infer a report format from "%s"; use a .html/.json/.txt extension or prefix with html:, json: or text:.', $spec));
        }

        return [$format, $spec];
    }

    public function render(Plan $plan, bool $minimalChangesSupported): string
    {
        return match ($this) {
            self::Text => (new TextRenderer($minimalChangesSupported))->render($plan),
            self::Html => (new HtmlRenderer($minimalChangesSupported))->render($plan),
            self::Json => (new JsonRenderer($minimalChangesSupported))->render($plan),
            self::None => '',
        };
    }
}
