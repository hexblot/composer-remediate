<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Output;

use PHPUnit\Framework\TestCase;
use Remediate\Output\ConflictEntry;

/**
 * Inverting a fixed range into the `conflict` entry that keeps a later update above it.
 */
final class ConflictEntryTest extends TestCase
{
    /**
     * @return array<string, array{string, string|null}>
     */
    public static function constraints(): array
    {
        return [
            'a simple lower bound' => ['>=1.5.0', '<1.5.0'],
            'an exclusive lower bound keeps the boundary version out of the fix' => ['>1.2.3', '<=1.2.3'],
            'a pin' => ['1.2.3', '<1.2.3'],
            'a caret range' => ['^3.14.0', '<3.14.0'],
            'several branches are cut at the lowest one' => ['>=1.5.0 || >=2.1.0', '<1.5.0'],
            'a bounded branch plus an open one' => ['>=1.5.0,<2.0.0 || >=2.1.0', '<1.5.0'],
            'a range reaching down to zero excludes nothing' => ['*', null],
            'an upper bound alone has no lower bound to invert' => ['<2.0.0', null],
            'an unparseable constraint' => ['not a constraint', null],
        ];
    }

    /**
     * @dataProvider constraints
     */
    public function testTheEntryIsEverythingBelowTheFix(string $constraint, ?string $expected): void
    {
        self::assertSame($expected, ConflictEntry::forConstraint($constraint));
    }

    public function testEntriesAreWrittenAsComposerJsonLines(): void
    {
        self::assertSame(
            ['"acme/lib": "<1.5.0"', '"acme/other": "<2.0.0"'],
            ConflictEntry::asJsonLines(['acme/lib' => '<1.5.0', 'acme/other' => '<2.0.0']),
        );
    }
}
