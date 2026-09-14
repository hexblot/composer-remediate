<?php

declare(strict_types=1);

namespace Remediate\Engine\Apply;

/** The outcome of `--apply`, with what ran and where the manifest and lock from before it were kept. */
final class ApplyResult
{
    /**
     * @param list<string> $commands the commands run, as they would be typed
     * @param string|null  $backup   directory holding the composer.json and composer.lock from before the run
     * @param string|null  $reason   why nothing ran, or how Composer failed
     */
    public function __construct(
        public readonly ApplyOutcome $outcome,
        public readonly array $commands = [],
        public readonly ?string $backup = null,
        public readonly ?string $reason = null,
    ) {
    }

    public static function refused(string $reason): self
    {
        return new self(ApplyOutcome::Refused, [], null, $reason);
    }
}
