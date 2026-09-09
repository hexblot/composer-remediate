<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Output;

use PHPUnit\Framework\TestCase;
use Remediate\Engine\Matching\Finding;
use Remediate\Engine\Plan\FindingPlan;
use Remediate\Engine\Plan\Plan;
use Remediate\Output\HtmlRenderer;

final class HtmlRendererTest extends TestCase
{
    public function testOnlyHttpLinksBecomeAnchors(): void
    {
        self::assertSame('https://example.test/a', HtmlRenderer::safeUrl('https://example.test/a'));
        self::assertSame('HTTP://example.test/a', HtmlRenderer::safeUrl('HTTP://example.test/a'));
        self::assertNull(HtmlRenderer::safeUrl('javascript:alert(1)'));
        self::assertNull(HtmlRenderer::safeUrl('data:text/html,hi'));
        self::assertNull(HtmlRenderer::safeUrl(' javascript:alert(1)'));
        self::assertNull(HtmlRenderer::safeUrl(null));
    }

    public function testJavascriptAdvisoryLinkIsRenderedAsText(): void
    {
        $advisory = new \Remediate\Engine\Advisory\Advisory('PKSA-1', 'acme/lib', (new \Composer\Semver\VersionParser())->parseConstraints('<1.1.0'), 'x', null, 'javascript:alert(1)');
        $plan = new Plan([new FindingPlan(new Finding($advisory, 'acme/lib', '1.0.0.0', '1.0.0', false, true), [], [])], [], [], null, null, []);
        $html = (new HtmlRenderer())->render($plan);
        self::assertStringNotContainsString('javascript:', $html, 'an unsafe advisory link is dropped entirely');
        self::assertStringContainsString('<strong>PKSA-1</strong>', $html, 'the advisory id is shown without a link');
        self::assertStringContainsString('No verified remediation found (none)', $html);
    }
}
