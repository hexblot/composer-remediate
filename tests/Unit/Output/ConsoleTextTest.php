<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Output;

use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\Advisory;
use Remediate\Engine\Matching\Finding;
use Remediate\Engine\Plan\FindingPlan;
use Remediate\Engine\Plan\Plan;
use Remediate\Output\ConsoleText;
use Remediate\Output\TextRenderer;

/**
 * Advisory text is attacker-influenced (anyone can file an advisory); it must not be able to
 * restyle the report or rewrite the terminal.
 */
final class ConsoleTextTest extends TestCase
{
    public function testStripsControlCharactersAndAnsiSequencesButKeepsTabsAndNewlines(): void
    {
        self::assertSame('clean text', ConsoleText::stripControls("clean\x1B[31m text\x07\x00"));
        self::assertSame("a\tb\nc", ConsoleText::stripControls("a\tb\r\nc\x08"));
        self::assertSame('PASS  all good', ConsoleText::stripControls("PASS\x1B[2K\x1B[1G  all good"));
    }

    public function testEscapesConsoleTags(): void
    {
        self::assertSame('a \<error\>b\</\> c', ConsoleText::safe("a <error>b</> c\x1B[0m"));
    }

    public function testDecoratedTextReportCannotBeRestyledByAnAdvisoryTitle(): void
    {
        $advisory = new Advisory('PKSA-1', 'acme/lib', (new \Composer\Semver\VersionParser())->parseConstraints('<1.1.0'), "<fg=green>PASS</> everything fine\x1B[2K\r", null, "https://example.test/<info>x</info>");
        $plan = new Plan([new FindingPlan(new Finding($advisory, 'acme/lib', '1.0.0.0', '1.0.0', false, true), [], [], "solver said <error>\x1B[31mboom</error>")], [], ["upstream <bg=red>warning</>\x07"]);

        $decorated = (new TextRenderer(true, true))->render($plan);
        self::assertStringContainsString('\<fg=green\>PASS\</\> everything fine', $decorated, 'tags in the title are escaped');
        self::assertStringContainsString('https://example.test/\<info\>x\</info\>', $decorated);
        self::assertStringContainsString('solver said \<error\>boom\</error\>', $decorated);
        self::assertStringContainsString('upstream \<bg=red\>warning\</\>', $decorated);
        self::assertStringNotContainsString("\x1B", $decorated);
        self::assertStringNotContainsString("\x07", $decorated);
        self::assertStringNotContainsString("\r", $decorated);

        $plain = (new TextRenderer(true, false))->render($plan);
        self::assertStringContainsString('<fg=green>PASS</> everything fine', $plain, 'undecorated output is written raw, so the tags are inert and kept verbatim');
        self::assertStringNotContainsString("\x1B", $plain);
    }
}
