<?php

declare(strict_types=1);

namespace Remediate\Output;

use Symfony\Component\Console\Formatter\OutputFormatter;

/**
 * Text that came from outside the tool (advisory titles and links, upstream record ids, solver
 * output, file names) and is about to reach a terminal. Control characters and ANSI escape
 * sequences are removed so a crafted advisory cannot rewrite the line above it or hide text, and
 * Symfony console tags are escaped so it cannot restyle the report.
 */
final class ConsoleText
{
    /** Removes ANSI CSI sequences and every C0/C1 control character except tab and newline. */
    public static function stripControls(string $text): string
    {
        $text = preg_replace('/\x1B\[[0-?]*[ -\/]*[@-~]/', '', $text) ?? $text;

        return preg_replace('/[\x00-\x08\x0B-\x1F\x7F]|\xC2[\x80-\x9F]/', '', $text) ?? $text;
    }

    /** stripControls() plus escaping of console formatting tags, for text written through a formatter. */
    public static function safe(string $text): string
    {
        return OutputFormatter::escape(self::stripControls($text));
    }
}
