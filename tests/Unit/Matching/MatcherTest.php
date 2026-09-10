<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Matching;

use Composer\Package\Link;
use Composer\Package\Package;
use Composer\Semver\Constraint\Constraint;
use Composer\Semver\VersionParser;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\Advisory;
use Remediate\Engine\Advisory\AdvisoryProvider;
use Remediate\Engine\Lock\LockSnapshot;
use Remediate\Engine\Matching\Matcher;

final class MatcherTest extends TestCase
{
    private function provider(): AdvisoryProvider
    {
        $parser = new VersionParser();
        $advisories = [
            'acme/lib' => [new Advisory('PKSA-1', 'acme/lib', $parser->parseConstraints('<1.5.0'), 'one', 'CVE-2026-1')],
            'acme/component' => [new Advisory('PKSA-2', 'acme/component', $parser->parseConstraints('<3.0.0'), 'two', 'CVE-2026-2')],
        ];

        return new class($advisories) implements AdvisoryProvider {
            /** @param array<string, list<Advisory>> $advisories */
            public function __construct(private readonly array $advisories)
            {
            }

            public function advisoriesFor(array $packageNames): array
            {
                return array_intersect_key($this->advisories, array_flip(array_map('strtolower', $packageNames)));
            }

            public function describe(): string
            {
                return 'test';
            }

            public function isComplete(): bool
            {
                return true;
            }
        };
    }

    public function testMatchesDirectReplacedAndIgnored(): void
    {
        $lib = new Package('acme/lib', '1.4.0.0', '1.4.0');
        $mono = new Package('acme/monorepo', '2.1.0.0', '2.1.0');
        $mono->setReplaces(['acme/component' => new Link('acme/monorepo', 'acme/component', new Constraint('==', '2.1.0.0'), Link::TYPE_REPLACE, '2.1.0')]);
        $lock = LockSnapshot::fromPackages([$lib], [$mono]);

        $matcher = new Matcher($this->provider());
        $findings = $matcher->match($lock, static fn (string $n): bool => $n === 'acme/lib');
        self::assertCount(2, $findings);
        self::assertSame('acme/lib', $findings[0]->packageName);
        self::assertTrue($findings[0]->isRootRequirement);
        self::assertFalse($findings[0]->isDev);
        self::assertSame('acme/monorepo', $findings[1]->packageName);
        self::assertSame('acme/component', $findings[1]->viaReplacedName);
        self::assertTrue($findings[1]->isDev);

        $ignoring = $matcher->withIgnored(['cve-2026-2']);
        $findings = $ignoring->match($lock, static fn (string $n): bool => false);
        self::assertCount(1, $findings);
        self::assertSame(1, $ignoring->ignoredCount());
        self::assertSame(['PKSA-1@acme/lib' => true], $ignoring->findingKeys($lock));
    }

    public function testTheSameAdvisoryIdOnTwoReplacedTargetsYieldsTwoFindings(): void
    {
        // A database keyed by CVE gives both components the same advisory id; the monorepo package
        // replaces both. Before, the second finding collapsed into the first.
        $parser = new VersionParser();
        $provider = new class([
            'acme/http' => [new Advisory('CVE-2026-77', 'acme/http', $parser->parseConstraints('<5.0.0'), 'shared', 'CVE-2026-77')],
            'acme/kernel' => [new Advisory('CVE-2026-77', 'acme/kernel', $parser->parseConstraints('<5.0.0'), 'shared', 'CVE-2026-77')],
        ]) implements AdvisoryProvider {
            /** @param array<string, list<Advisory>> $advisories */
            public function __construct(private readonly array $advisories)
            {
            }

            public function advisoriesFor(array $packageNames): array
            {
                return array_intersect_key($this->advisories, array_flip(array_map('strtolower', $packageNames)));
            }

            public function describe(): string
            {
                return 'test';
            }

            public function isComplete(): bool
            {
                return true;
            }
        };
        $suite = new Package('acme/suite', '4.4.0.0', '4.4.0');
        $suite->setReplaces([
            'acme/http' => new Link('acme/suite', 'acme/http', new Constraint('==', '4.4.0.0'), Link::TYPE_REPLACE, 'self.version'),
            'acme/kernel' => new Link('acme/suite', 'acme/kernel', new Constraint('==', '4.4.0.0'), Link::TYPE_REPLACE, 'self.version'),
        ]);
        $findings = (new Matcher($provider))->match(LockSnapshot::fromPackages([$suite], []), static fn (): bool => true);
        self::assertCount(2, $findings);
        self::assertSame(['CVE-2026-77@acme/suite/acme/http', 'CVE-2026-77@acme/suite/acme/kernel'], array_map(static fn ($f): string => $f->key(), $findings));
        self::assertSame(['acme/http', 'acme/kernel'], array_map(static fn ($f): ?string => $f->viaReplacedName, $findings));
    }
}
