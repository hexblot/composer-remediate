<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Advisory;

use Composer\Advisory\PartialSecurityAdvisory;
use Composer\Advisory\SecurityAdvisory;
use Composer\Config;
use Composer\Downloader\TransportException;
use Composer\IO\NullIO;
use Composer\Repository\ArrayRepository;
use Composer\Repository\RepositoryManager;
use Composer\Semver\Constraint\Constraint;
use Composer\Semver\VersionParser;
use Composer\Util\HttpDownloader;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\AdvisoryLookupFailed;
use Remediate\Engine\Advisory\ComposerRepositoryAdvisoryProvider;
use Remediate\Tests\Support\FakeAdvisoryRepository;

/**
 * The default adapter around Composer's @internal advisory API: what it asks the repositories, how
 * it converts their answers, and how it fails when no repository can answer.
 */
final class ComposerRepositoryAdvisoryProviderTest extends TestCase
{
    private static function constraint(string $expression): \Composer\Semver\Constraint\ConstraintInterface
    {
        return (new VersionParser())->parseConstraints($expression);
    }

    private static function full(string $package, string $id, string $range, ?string $cve = null, ?string $severity = 'high'): SecurityAdvisory
    {
        return new SecurityAdvisory($package, $id, self::constraint($range), 'Title of ' . $id, [['name' => 'GitHub', 'remoteId' => 'GHSA-' . $id]], new \DateTimeImmutable('2026-01-15 10:00:00', new \DateTimeZone('UTC')), $cve, 'https://example.invalid/' . $id, $severity);
    }

    public function testConvertsAdvisoriesAndOnlyAsksForPackagesItHasNotSeen(): void
    {
        $repository = new FakeAdvisoryRepository('packagist.org', [
            'Acme/Lib' => [
                self::full('Acme/Lib', 'PKSA-1', '<1.2', 'CVE-2026-40001'),
                new PartialSecurityAdvisory('Acme/Lib', 'PKSA-2', self::constraint('>=2.0,<2.0.3')),
            ],
        ]);
        $provider = new ComposerRepositoryAdvisoryProvider([$repository]);

        $result = $provider->advisoriesFor(['acme/lib', 'Acme/None']);
        self::assertSame(['acme/lib'], array_keys($result), 'packages without advisories are absent, keys are lower-case');
        self::assertCount(2, $result['acme/lib']);

        $full = $result['acme/lib'][0];
        self::assertSame('PKSA-1', $full->id);
        self::assertSame('acme/lib', $full->packageName);
        self::assertSame('CVE-2026-40001', $full->cve);
        self::assertSame('Title of PKSA-1', $full->title);
        self::assertSame('https://example.invalid/PKSA-1', $full->link);
        self::assertSame(property_exists(SecurityAdvisory::class, 'severity') ? 'high' : null, $full->severity, 'Composer 2.4 has no severity field; the adapter reads it only when it exists');
        self::assertSame('2026-01-15T10:00:00+00:00', $full->reportedAt?->format(DATE_ATOM));
        self::assertSame([['name' => 'GitHub', 'remoteId' => 'GHSA-PKSA-1']], $full->sources);
        self::assertTrue($full->affectsVersion('1.1.0.0'));
        self::assertFalse($full->affectsVersion('1.2.0.0'));

        $partial = $result['acme/lib'][1];
        self::assertSame('PKSA-2', $partial->id);
        self::assertSame('acme/lib', $partial->packageName);
        self::assertNull($partial->title);
        self::assertNull($partial->cve);
        self::assertNull($partial->severity);
        self::assertSame([], $partial->sources);
        self::assertTrue($partial->affectsVersion('2.0.1.0'));

        self::assertSame([['acme/lib', 'acme/none']], $repository->queries(), 'one query naming every requested package, lower-cased');

        self::assertSame($result, $provider->advisoriesFor(['acme/lib']));
        self::assertCount(1, $repository->queries(), 'answers are cached; nothing is asked again');

        $provider->advisoriesFor(['acme/lib', 'acme/new']);
        self::assertSame([['acme/lib', 'acme/none'], ['acme/new']], $repository->queries(), 'only the package not yet asked about is fetched');

        self::assertTrue($provider->isComplete(), 'the repository answers for every version, not only the locked one');
        self::assertSame('advisories from packagist.org', $provider->describe());
    }

    public function testMergesRepositoriesAndDropsDuplicateAdvisoryIds(): void
    {
        $first = new FakeAdvisoryRepository('mirror-a', ['acme/lib' => [self::full('acme/lib', 'PKSA-1', '<1.2')]]);
        $second = new FakeAdvisoryRepository('mirror-b', ['acme/lib' => [self::full('acme/lib', 'PKSA-1', '<1.3'), self::full('acme/lib', 'PKSA-3', '<0.9')]]);
        $provider = new ComposerRepositoryAdvisoryProvider([$first, new ArrayRepository(), $second]);

        $result = $provider->advisoriesFor(['acme/lib']);
        self::assertSame(['PKSA-1', 'PKSA-3'], array_map(static fn ($a): string => $a->id, $result['acme/lib']));
        self::assertFalse($result['acme/lib'][0]->affectsVersion('1.2.5.0'), 'the first repository\'s copy of PKSA-1 is kept');
        self::assertSame([['acme/lib']], $first->queries());
        self::assertSame([['acme/lib']], $second->queries());
        self::assertSame('advisories from mirror-a, mirror-b', $provider->describe());
    }

    public function testWithoutAnyAdvisoryProvidingRepositoryTheLookupFailsInsteadOfLookingClean(): void
    {
        $provider = new ComposerRepositoryAdvisoryProvider([new ArrayRepository(), new FakeAdvisoryRepository('private', providesAdvisories: false)]);
        self::assertSame('no repository provides advisories', $provider->describe());
        try {
            $provider->advisoriesFor(['acme/lib']);
            self::fail('expected the lookup to fail');
        } catch (AdvisoryLookupFailed $e) {
            self::assertStringContainsString('None of the configured repositories provides security advisories', $e->getMessage());
            self::assertStringContainsString('--database-location or --advisories-file', $e->getMessage());
        }
    }

    public function testATransportFailureBecomesAnAdvisoryLookupFailure(): void
    {
        $repository = new FakeAdvisoryRepository('packagist.org', failure: new TransportException('connection reset', 0));
        $provider = new ComposerRepositoryAdvisoryProvider([$repository]);
        try {
            $provider->advisoriesFor(['acme/lib']);
            self::fail('expected the lookup to fail');
        } catch (AdvisoryLookupFailed $e) {
            self::assertSame('Could not fetch advisories from packagist.org: connection reset', $e->getMessage());
            self::assertInstanceOf(TransportException::class, $e->getPrevious());
        }
    }

    public function testFromRepositoryManagerUsesTheConfiguredRepositories(): void
    {
        $io = new NullIO();
        $config = new Config(false);
        $manager = new RepositoryManager($io, $config, new HttpDownloader($io, $config));
        $manager->addRepository(new FakeAdvisoryRepository('packagist.org', ['acme/lib' => [self::full('acme/lib', 'PKSA-1', '<1.2')]]));
        $manager->addRepository(new ArrayRepository());

        $provider = ComposerRepositoryAdvisoryProvider::fromRepositoryManager($manager);
        self::assertSame('advisories from packagist.org', $provider->describe());
        self::assertSame(['acme/lib'], array_keys($provider->advisoriesFor(['acme/lib'])));
        self::assertTrue($provider->advisoriesFor(['acme/lib'])['acme/lib'][0]->affectsConstraint(new Constraint('<', '1.0.0.0')));
    }
}
