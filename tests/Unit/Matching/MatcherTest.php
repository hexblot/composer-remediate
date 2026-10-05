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
use Remediate\Engine\Matching\Finding;
use Remediate\Engine\Matching\IgnorePolicy;
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

    /**
     * The ninth review's second finding: an ignore written against the package the advisory is about
     * (acme/component) did nothing when that package was present only through another's `replace`,
     * because the matcher asked the policy about the replacing package. Worse, the hygiene warning then
     * told the operator the rule matched nothing and could be removed.
     */
    public function testAnIgnoreOnTheReplacedPackageSuppressesTheFindingReachedThroughIt(): void
    {
        $mono = new Package('acme/monorepo', '2.1.0.0', '2.1.0');
        $mono->setReplaces(['acme/component' => new Link('acme/monorepo', 'acme/component', new Constraint('==', '2.1.0.0'), Link::TYPE_REPLACE, 'self.version')]);
        $lock = LockSnapshot::fromPackages([$mono], []);

        $byReplacedName = (new Matcher($this->provider()))->withIgnorePolicy(new IgnorePolicy([], ['acme/component' => [null]]));
        self::assertSame([], $byReplacedName->match($lock, static fn (): bool => true));
        self::assertSame(1, $byReplacedName->ignoredCount());
        self::assertSame([], $byReplacedName->unusedIgnores(), 'the rule that suppressed the finding is not reported as unused');

        $byReplacingName = (new Matcher($this->provider()))->withIgnorePolicy(new IgnorePolicy([], ['acme/monorepo' => [null]]));
        self::assertSame([], $byReplacingName->match($lock, static fn (): bool => true), 'the replacing package is the one in the lock; a rule on it applies too');
        self::assertSame([], $byReplacingName->unusedIgnores());

        $both = (new Matcher($this->provider()))->withIgnorePolicy(new IgnorePolicy([], ['acme/component' => [null], 'acme/monorepo' => [null]]));
        self::assertSame([], $both->match($lock, static fn (): bool => true));
        self::assertSame(1, $both->ignoredCount(), 'one finding ignored, however many rules agree');
        self::assertSame([], $both->unusedIgnores(), 'every rule that matched counts as used');
    }

    public function testAVersionedIgnoreOnTheReplacedPackageIsMatchedAgainstTheReplaceLink(): void
    {
        $parser = new VersionParser();
        $mono = new Package('acme/monorepo', '2.1.0.0', '2.1.0');
        $mono->setReplaces(['acme/component' => new Link('acme/monorepo', 'acme/component', new Constraint('==', '2.1.0.0'), Link::TYPE_REPLACE, 'self.version')]);
        $lock = LockSnapshot::fromPackages([$mono], []);

        $covering = (new Matcher($this->provider()))->withIgnorePolicy(new IgnorePolicy([], ['acme/component' => [$parser->parseConstraints('<3.0')]]));
        self::assertSame([], $covering->match($lock, static fn (): bool => true));

        $elsewhere = (new Matcher($this->provider()))->withIgnorePolicy(new IgnorePolicy([], ['acme/component' => [$parser->parseConstraints('<2.0')]]));
        self::assertCount(1, $elsewhere->match($lock, static fn (): bool => true), 'a rule for versions the replace does not cover leaves the finding');
        self::assertSame(['acme/component'], $elsewhere->unusedIgnores());
    }

    public function testTheKeyNamesTheLockedPackageAndCanBeReadBack(): void
    {
        $parser = new VersionParser();
        $advisory = new Advisory('CVE-2026-77', 'acme/component', $parser->parseConstraints('<3.0.0'));
        $direct = new Finding($advisory, 'acme/component', '2.1.0.0', '2.1.0', false, false);
        $viaReplace = new Finding($advisory, 'acme/monorepo', '2.1.0.0', '2.1.0', false, false, 'acme/component');

        self::assertSame('acme/component', Finding::packageOfKey($direct->key()));
        self::assertSame('acme/monorepo', Finding::packageOfKey($viaReplace->key()), 'the replacing package is what a command moves');
        self::assertSame('acme/monorepo', Finding::packageOfKey('symfony/symfony/CVE-2026-1.yaml@acme/monorepo/acme/component'), 'an id that is itself a path does not confuse it');
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
