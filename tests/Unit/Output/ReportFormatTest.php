<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Output;

use PHPUnit\Framework\TestCase;
use Remediate\Output\ReportFormat;

final class ReportFormatTest extends TestCase
{
    public function testInfersFormatFromExtension(): void
    {
        self::assertSame([ReportFormat::Html, 'build/report.html'], ReportFormat::parseOutputSpec('build/report.html'));
        self::assertSame([ReportFormat::Json, 'r.json'], ReportFormat::parseOutputSpec('r.json'));
        self::assertSame([ReportFormat::Text, 'r.txt'], ReportFormat::parseOutputSpec('r.txt'));
        self::assertSame([ReportFormat::Json, 'out/no-extension'], ReportFormat::parseOutputSpec('json:out/no-extension'));
    }

    public function testRejectsUnknownExtension(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        ReportFormat::parseOutputSpec('report.pdf');
    }
}
