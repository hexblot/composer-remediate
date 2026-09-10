<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory;

/**
 * Uses Composer's in-process advisory API while it works and switches to the `composer audit`
 * subprocess the moment that API proves incompatible: a method that no longer exists, a changed
 * signature, a type error inside Composer's @internal classes. Those surface as PHP errors, not as
 * lookup failures. A lookup failure (network down, no repository provides advisories) is not
 * retried through the fallback, because `composer audit` would hit the same wall and the caller
 * must report "advisory data unavailable" rather than a clean lock.
 *
 * Once switched, the run stays on the fallback so every lookup of the run comes from one source,
 * and the switch is recorded as a warning for the report.
 */
final class FallbackAdvisoryProvider implements AdvisoryProvider
{
    private bool $usingFallback = false;

    /** @var list<string> */
    private array $warnings = [];

    public function __construct(private readonly AdvisoryProvider $primary, private readonly AdvisoryProvider $fallback)
    {
    }

    public function advisoriesFor(array $packageNames): array
    {
        if ($this->usingFallback) {
            return $this->fallback->advisoriesFor($packageNames);
        }
        try {
            return $this->primary->advisoriesFor($packageNames);
        } catch (AdvisoryLookupFailed $e) {
            throw $e;
        } catch (\Error $e) { // @phpstan-ignore catch.neverThrown (a changed Composer @internal signature surfaces as a PHP error, which no @throws declares)
            $this->usingFallback = true;
            $this->warnings[] = sprintf(
                'Composer\'s in-process advisory API could not be used (%s: %s); advisories were read with %s instead, which only knows advisories for the current lock, so candidate locks cannot be checked for other advisories.',
                (new \ReflectionClass($e))->getShortName(),
                trim(explode("\n", $e->getMessage())[0]),
                $this->fallback->describe(),
            );

            return $this->fallback->advisoriesFor($packageNames);
        }
    }

    public function describe(): string
    {
        return $this->active()->describe();
    }

    public function isComplete(): bool
    {
        return $this->active()->isComplete();
    }

    /** Whether the fallback took over during this run. */
    public function usedFallback(): bool
    {
        return $this->usingFallback;
    }

    /** @return list<string> */
    public function warnings(): array
    {
        return $this->warnings;
    }

    private function active(): AdvisoryProvider
    {
        return $this->usingFallback ? $this->fallback : $this->primary;
    }
}
