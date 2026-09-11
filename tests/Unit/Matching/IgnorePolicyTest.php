<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Matching;

use Composer\Config;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Matching\IgnorePolicy;

final class IgnorePolicyTest extends TestCase
{
    /** @param array<string, mixed> $config */
    private function policy(array $config): IgnorePolicy
    {
        $composerConfig = new Config(false);
        $composerConfig->merge(['config' => $config]);

        return IgnorePolicy::fromComposerConfig($composerConfig);
    }

    public function testLegacyAuditIgnoreListAndMap(): void
    {
        $policy = $this->policy(['audit' => ['ignore' => ['CVE-2026-1', 'GHSA-abcd' => 'reason']]]);
        self::assertNotNull($policy->matchedEntry('PKSA-x', 'CVE-2026-1', 'acme/lib', '1.0.0.0'));
        self::assertNotNull($policy->matchedEntry('GHSA-abcd', null, 'acme/lib', '1.0.0.0'));
        self::assertNull($policy->matchedEntry('PKSA-y', 'CVE-2026-2', 'acme/lib', '1.0.0.0'));
    }

    public function testBlockOnlyExceptionsDoNotSuppressAuditFindings(): void
    {
        $policy = $this->policy(['audit' => ['ignore' => [
            'CVE-2026-1' => ['apply' => 'block', 'reason' => 'install anyway'],
            'CVE-2026-2' => ['apply' => 'audit'],
            'CVE-2026-3' => ['apply' => 'all'],
        ]]]);
        self::assertNull($policy->matchedEntry('PKSA-1', 'CVE-2026-1', 'acme/lib', '1.0.0.0'), 'apply: block keeps the finding visible to audit-time tools');
        self::assertNotNull($policy->matchedEntry('PKSA-2', 'CVE-2026-2', 'acme/lib', '1.0.0.0'));
        self::assertNotNull($policy->matchedEntry('PKSA-3', 'CVE-2026-3', 'acme/lib', '1.0.0.0'));
    }

    public function testPolicyIgnoreIdHonoursOnAudit(): void
    {
        $policy = $this->policy(['policy' => ['advisories' => ['ignore-id' => [
            'CVE-2026-1' => ['on-audit' => false, 'on-block' => true],
            'CVE-2026-2' => ['on-audit' => true],
            'CVE-2026-3',
        ]]]]);
        self::assertNull($policy->matchedEntry('PKSA-1', 'CVE-2026-1', 'acme/lib', '1.0.0.0'));
        self::assertNotNull($policy->matchedEntry('PKSA-2', 'CVE-2026-2', 'acme/lib', '1.0.0.0'));
        self::assertNotNull($policy->matchedEntry('PKSA-3', 'CVE-2026-3', 'acme/lib', '1.0.0.0'));
    }

    public function testPackageRulesAreScopedToPackageAndConstraint(): void
    {
        $policy = $this->policy(['policy' => ['advisories' => ['ignore' => [
            'acme/lib' => ['constraint' => '<1.5', 'on-audit' => true],
            'acme/other' => ['on-audit' => false],
            'acme/any' => 'reason',
        ]]]]);
        self::assertSame('acme/lib', $policy->matchedEntry('PKSA-1', null, 'acme/lib', '1.4.0.0'));
        self::assertNull($policy->matchedEntry('PKSA-1', null, 'acme/lib', '1.6.0.0'), 'outside the constraint the advisory counts');
        self::assertNull($policy->matchedEntry('PKSA-1', null, 'acme/other', '1.0.0.0'));
        self::assertNotNull($policy->matchedEntry('PKSA-1', null, 'acme/any', '1.0.0.0'));
        self::assertNull($policy->matchedEntry('acme/lib', null, 'acme/unrelated', '1.0.0.0'), 'a package rule is never treated as an advisory id');
    }

    public function testCliIdsMergeAndAreCaseInsensitive(): void
    {
        $policy = IgnorePolicy::none()->withIds(['cve-2026-9', ' ']);
        self::assertSame('cve-2026-9', $policy->matchedEntry('PKSA-9', 'CVE-2026-9', 'acme/lib', '1.0.0.0'));
        self::assertSame(['cve-2026-9'], $policy->entries());
    }

    public function testEntriesTheAnalysedProjectSuppliedAreRemembered(): void
    {
        $config = new \Composer\Config(false);
        $config->merge(['config' => ['audit' => ['ignore' => ['CVE-2026-1']], 'policy' => ['advisories' => ['ignore-id' => ['PKSA-2'], 'ignore' => ['acme/lib']]]]], 'project/composer.json');

        $operatorSet = IgnorePolicy::fromComposerConfig($config);
        self::assertSame([], $operatorSet->projectEntries(), 'nothing is attributed to the project unless the caller says so');

        $projectSet = IgnorePolicy::fromComposerConfig($config, ['audit', 'policy']);
        self::assertSame(['cve-2026-1', 'pksa-2', 'acme/lib'], $projectSet->projectEntries());
        self::assertSame(['cve-2026-1', 'pksa-2', 'acme/lib'], $projectSet->withIds(['CVE-OPERATOR'])->projectEntries(), 'the operator\'s own --ignore is not the project\'s');

        $auditOnly = IgnorePolicy::fromComposerConfig($config, ['audit']);
        self::assertSame(['cve-2026-1'], $auditOnly->projectEntries(), 'only the keys the project set');
    }
}