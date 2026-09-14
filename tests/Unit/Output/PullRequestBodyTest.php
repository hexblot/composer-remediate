<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Output;

use PHPUnit\Framework\TestCase;
use Remediate\Output\PullRequestBody;

/**
 * The description a reviewer of a batched pull request reads. It has to say what closed, what did not,
 * and be honest when a run changed the lock without fixing anything.
 */
final class PullRequestBodyTest extends TestCase
{
    /**
     * @param list<array{package: string, version: string, advisories: list<array<string, mixed>>, remediation?: array<string, mixed>}> $findings
     * @param list<string>                                                                                                              $warnings
     *
     * @return array<string, mixed>
     */
    private static function report(array $findings, int $exit = 1, array $warnings = []): array
    {
        return [
            'exit_code' => $exit,
            'warnings' => $warnings,
            'summary' => ['packages' => count($findings), 'advisories' => array_sum(array_map(static fn (array $f): int => count($f['advisories']), $findings))],
            'findings' => array_map(static fn (array $f): array => $f + ['remediation' => ['status' => 'none', 'outcome' => 'none']], $findings),
        ];
    }

    /** @return array<string, mixed> */
    private static function advisory(string $id, ?string $cve = null, string $severity = 'high', ?string $link = null, string $title = 'Something'): array
    {
        return ['id' => $id, 'cve' => $cve, 'severity' => $severity, 'link' => $link, 'title' => $title];
    }

    public function testItSaysWhatClosedAndWhatRan(): void
    {
        $before = self::report([
            ['package' => 'acme/lib', 'version' => '1.0.0', 'advisories' => [self::advisory('PKSA-1', 'CVE-2026-1', 'high', 'https://example.test/1')]],
            ['package' => 'acme/other', 'version' => '2.0.0', 'advisories' => [self::advisory('PKSA-2', null, 'low')]],
        ]);
        $after = self::report([
            ['package' => 'acme/other', 'version' => '2.0.0', 'advisories' => [self::advisory('PKSA-2', null, 'low')]],
        ], 2);

        $body = PullRequestBody::render($before, $after, ['composer update acme/lib -W -m --no-install --no-interaction']);

        self::assertStringContainsString('1 of 2 advisories closed, on 1 of 2 packages.', $body);
        self::assertStringContainsString('composer update acme/lib -W -m --no-install --no-interaction', $body);
        self::assertStringContainsString('[CVE-2026-1](https://example.test/1)', $body, 'the identifier a reader searches for, linked');
        self::assertStringContainsString('`acme/lib`', $body);
        self::assertStringContainsString('## Still open', $body);
        self::assertStringContainsString('PKSA-2', $body);
        self::assertStringContainsString('Exit code 1 before, 2 after.', $body);
    }

    public function testARunThatFixedNothingSaysSoPlainly(): void
    {
        $finding = ['package' => 'acme/lib', 'version' => '1.0.0', 'advisories' => [self::advisory('PKSA-1')]];

        $body = PullRequestBody::render(self::report([$finding]), self::report([$finding]), ['composer update acme/lib']);

        self::assertStringContainsString('0 of 1 advisories closed', $body);
        self::assertStringContainsString('every advisory that was', $body);
        self::assertStringContainsString('Read this pull request carefully.', $body);
    }

    public function testACleanResultHasNoStillOpenSection(): void
    {
        $before = self::report([['package' => 'acme/lib', 'version' => '1.0.0', 'advisories' => [self::advisory('PKSA-1')]]]);

        $body = PullRequestBody::render($before, self::report([], 0), ['composer update acme/lib']);

        self::assertStringContainsString('1 of 1 advisories closed, on 1 of 1 packages.', $body);
        self::assertStringNotContainsString('## Still open', $body);
        self::assertStringContainsString('Exit code 1 before, 0 after.', $body);
    }

    public function testTheWarningsOfTheApplyingRunAreCarried(): void
    {
        $before = self::report([['package' => 'acme/lib', 'version' => '1.0.0', 'advisories' => [self::advisory('PKSA-1')]]]);
        $after = self::report([], 0, ['Applied: composer update acme/lib. The composer.json and composer.lock from before the run are in /tmp/x.']);

        $body = PullRequestBody::render($before, $after);

        self::assertStringContainsString('## Warnings from the run that applied it', $body);
        self::assertStringContainsString('from before the run are in /tmp/x.', $body);
    }

    public function testAnAdvisoryLinkCannotBreakOutOfTheMarkdownItSitsIn(): void
    {
        // The destination of a Markdown link ends at a parenthesis and the table cell ends at a pipe.
        // A parenthesis without whitespace is encoded, so the destination cannot end early.
        $parens = self::report([['package' => 'acme/lib', 'version' => '1.0.0', 'advisories' => [self::advisory('PKSA-1', 'CVE-2026-1', 'high', 'https://x.test/a)b|c')]]]);
        $body = PullRequestBody::render($parens, self::report([], 0));
        self::assertStringContainsString('[CVE-2026-1](https://x.test/a%29b%7Cc)', $body);

        // A link carrying whitespace is not a link at all, so nothing after it can be smuggled in.
        $hostile = self::report([['package' => 'acme/lib', 'version' => '1.0.0', 'advisories' => [self::advisory('PKSA-9', 'CVE-2026-9', 'high', 'https://x.test) **injected** [and](https://evil.test')]]]);
        $body = PullRequestBody::render($hostile, self::report([], 0));
        self::assertStringNotContainsString('**injected**', $body);
        self::assertStringNotContainsString('](https://evil.test', $body);
        self::assertStringContainsString('CVE-2026-9', $body, 'the identifier still shows');

        // A link with whitespace is not a link at all; the identifier still shows.
        $spaced = self::report([['package' => 'acme/lib', 'version' => '1.0.0', 'advisories' => [self::advisory('PKSA-2', 'CVE-2026-2', 'high', 'https://x.test trailing')]]]);
        $body = PullRequestBody::render($spaced, self::report([], 0));
        self::assertStringNotContainsString('trailing', $body);
        self::assertStringContainsString('CVE-2026-2', $body);

        // An ordinary link is left alone.
        $plain = self::report([['package' => 'acme/lib', 'version' => '1.0.0', 'advisories' => [self::advisory('PKSA-3', 'CVE-2026-3', 'high', 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc')]]]);
        self::assertStringContainsString('[CVE-2026-3](https://github.com/advisories/GHSA-aaaa-bbbb-cccc)', PullRequestBody::render($plain, self::report([], 0)));
    }

    public function testUpstreamTextCannotBreakOutOfTheTableOrTheMarkdown(): void
    {
        // Advisory data is upstream input and ends up in a rendered pull request description.
        $before = self::report([[
            'package' => "acme/lib | evil",
            'version' => '1.0.0',
            'advisories' => [self::advisory("PKSA-1 | <img src=x onerror=alert(1)> [click](javascript:alert(1))", null, "high\u{0007}")],
        ]]);

        $body = PullRequestBody::render($before, self::report([], 0));

        self::assertStringNotContainsString('<img', $body);
        self::assertStringNotContainsString("\u{0007}", $body);
        self::assertStringContainsString('&lt;img', $body);
        self::assertStringContainsString('\|', $body, 'a pipe cannot end a table cell');
        self::assertStringContainsString('\[click\]', $body, 'nor can a link be smuggled in');
    }
}
