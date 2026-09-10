<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Advisory;

use Composer\Semver\Constraint\MatchAllConstraint;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\Advisory;
use Remediate\Engine\Advisory\AdvisoryLookupFailed;
use Remediate\Engine\Advisory\AdvisoryProvider;
use Remediate\Engine\Advisory\FallbackAdvisoryProvider;

/**
 * When Composer's in-process advisory API breaks (a PHP error from a changed @internal signature),
 * the run switches to `composer audit` and says so; when the lookup itself fails, it fails.
 */
final class FallbackAdvisoryProviderTest extends TestCase
{
    /**
     * @param array<string, list<Advisory>>|\Throwable $answer
     * @param list<list<string>>                       $calls   receives the package names of every call
     * @param-out list<list<string>> $calls
     */
    private static function provider(array|\Throwable $answer, string $description, bool $complete, ?array &$calls = null): AdvisoryProvider
    {
        $calls = [];

        return new class($answer, $description, $complete, $calls) implements AdvisoryProvider {
            /**
             * @param array<string, list<Advisory>>|\Throwable $answer
             * @param list<list<string>>                       $calls
             */
            public function __construct(private readonly array|\Throwable $answer, private readonly string $description, private readonly bool $complete, private array &$calls) // @phpstan-ignore property.onlyWritten (read through the reference by the test)
            {
            }

            public function advisoriesFor(array $packageNames): array
            {
                $this->calls[] = $packageNames;
                if ($this->answer instanceof \Throwable) {
                    throw $this->answer;
                }

                return $this->answer;
            }

            public function describe(): string
            {
                return $this->description;
            }

            public function isComplete(): bool
            {
                return $this->complete;
            }
        };
    }

    public function testStaysOnThePrimaryWhileItWorks(): void
    {
        $advisory = new Advisory('PKSA-1', 'acme/lib', new MatchAllConstraint());
        $primary = self::provider(['acme/lib' => [$advisory]], 'advisories from packagist.org', true, $primaryCalls);
        $fallback = self::provider([], '`composer audit --locked`', false, $fallbackCalls);
        $provider = new FallbackAdvisoryProvider($primary, $fallback);

        self::assertSame(['acme/lib' => [$advisory]], $provider->advisoriesFor(['acme/lib']));
        self::assertSame('advisories from packagist.org', $provider->describe());
        self::assertTrue($provider->isComplete());
        self::assertFalse($provider->usedFallback());
        self::assertSame([], $provider->warnings());
        self::assertSame([['acme/lib']], $primaryCalls);
        self::assertSame([], $fallbackCalls);
    }

    public function testAPhpErrorInThePrimarySwitchesTheRunToTheFallbackAndWarns(): void
    {
        $advisory = new Advisory('PKSA-2', 'acme/lib', new MatchAllConstraint());
        $primary = self::provider(new \ArgumentCountError("Too few arguments to function Composer\\Repository\\ComposerRepository::getSecurityAdvisories(), 2 passed\nand more"), 'advisories from packagist.org', true, $primaryCalls);
        $fallback = self::provider(['acme/lib' => [$advisory]], '`composer audit --locked` (current-lock advisories only)', false, $fallbackCalls);
        $provider = new FallbackAdvisoryProvider($primary, $fallback);

        self::assertSame(['acme/lib' => [$advisory]], $provider->advisoriesFor(['acme/lib']));
        self::assertTrue($provider->usedFallback());
        self::assertSame('`composer audit --locked` (current-lock advisories only)', $provider->describe());
        self::assertFalse($provider->isComplete());
        self::assertCount(1, $provider->warnings());
        self::assertSame(
            'Composer\'s in-process advisory API could not be used (ArgumentCountError: Too few arguments to function Composer\\Repository\\ComposerRepository::getSecurityAdvisories(), 2 passed); advisories were read with `composer audit --locked` (current-lock advisories only) instead, which only knows advisories for the current lock, so candidate locks cannot be checked for other advisories.',
            $provider->warnings()[0],
        );

        $provider->advisoriesFor(['acme/other']);
        self::assertSame([['acme/lib']], $primaryCalls, 'the primary is not tried again in this run');
        self::assertSame([['acme/lib'], ['acme/other']], $fallbackCalls);
        self::assertCount(1, $provider->warnings(), 'the switch is reported once');
    }

    public function testALookupFailureIsNotRetriedThroughTheFallback(): void
    {
        $primary = self::provider(new AdvisoryLookupFailed('Could not fetch advisories from packagist.org: timeout'), 'advisories from packagist.org', true);
        $fallback = self::provider([], '`composer audit --locked`', false, $fallbackCalls);
        $provider = new FallbackAdvisoryProvider($primary, $fallback);

        try {
            $provider->advisoriesFor(['acme/lib']);
            self::fail('expected the lookup failure to propagate');
        } catch (AdvisoryLookupFailed $e) {
            self::assertSame('Could not fetch advisories from packagist.org: timeout', $e->getMessage());
        }
        self::assertSame([], $fallbackCalls, 'composer audit would hit the same wall; the caller must report advisories unavailable');
        self::assertFalse($provider->usedFallback());
        self::assertSame([], $provider->warnings());
    }

    public function testAnOrdinaryExceptionIsNotSwallowed(): void
    {
        $primary = self::provider(new \RuntimeException('unexpected'), 'primary', true);
        $provider = new FallbackAdvisoryProvider($primary, self::provider([], 'fallback', false, $fallbackCalls));
        $this->expectException(\RuntimeException::class);
        try {
            $provider->advisoriesFor(['acme/lib']);
        } finally {
            self::assertSame([], $fallbackCalls);
        }
    }
}
