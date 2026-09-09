<?php

declare(strict_types=1);

namespace Remediate\Engine\Candidate;

use Composer\DependencyResolver\Request;

/**
 * One concrete `composer update` invocation. Validation runs exactly this; the recommendation
 * prints exactly this.
 */
final class Candidate
{
    /**
     * @param list<string>                        $allowList            packages named on the command line
     * @param int                                 $transitiveMode       one of Request::UPDATE_*
     * @param array<string, string>               $temporaryConstraints package => constraint, rendered as --with
     * @param array<string, RootConstraintChange> $rootConstraintChanges
     * @param array<string, string>               $pins                 package => exact version, rendered as `name:version` in the allow list
     * @param list<string>                        $extraArguments       further `composer update` arguments the solve was run with and the
     *                                                                  user must repeat (e.g. --ignore-platform-req=php), so the printed
     *                                                                  command is the same request that was verified
     */
    public function __construct(
        public readonly Strategy $strategy,
        public readonly array $allowList,
        public readonly int $transitiveMode,
        public readonly array $temporaryConstraints,
        public readonly bool $minimalChanges,
        public readonly array $rootConstraintChanges,
        public readonly string $description,
        public readonly array $pins = [],
        public readonly array $extraArguments = [],
    ) {
    }

    /** @param list<string> $arguments */
    public function withExtraArguments(array $arguments): self
    {
        return new self($this->strategy, $this->allowList, $this->transitiveMode, $this->temporaryConstraints, $this->minimalChanges, $this->rootConstraintChanges, $this->description, $this->pins, array_values(array_unique([...$this->extraArguments, ...$arguments])));
    }

    /**
     * Temporary constraints as the solver must apply them: explicit --with constraints plus pins.
     *
     * @return array<string, string>
     */
    public function effectiveTemporaryConstraints(): array
    {
        return $this->temporaryConstraints + $this->pins;
    }

    /** @param array<string, string> $constraints */
    public function withTemporaryConstraints(array $constraints, string $description): self
    {
        return new self($this->strategy, $this->allowList, $this->transitiveMode, $constraints + $this->temporaryConstraints, $this->minimalChanges, $this->rootConstraintChanges, $description, $this->pins, $this->extraArguments);
    }

    /** @param list<string> $allowList */
    public function withAllowList(array $allowList, string $description): self
    {
        return new self($this->strategy, $allowList, $this->transitiveMode, $this->temporaryConstraints, $this->minimalChanges, $this->rootConstraintChanges, $description, $this->pins, $this->extraArguments);
    }

    public function withPin(string $packageName, string $version, string $description): self
    {
        $temporary = $this->temporaryConstraints;
        unset($temporary[$packageName]);

        return new self($this->strategy, $this->allowList, $this->transitiveMode, $temporary, $this->minimalChanges, $this->rootConstraintChanges, $description, $this->pins + [$packageName => $version], $this->extraArguments);
    }

    /** The same request with --with and/or -m removed; used when probing for a simpler spelling. */
    public function simplified(bool $dropTemporaryConstraints, bool $dropMinimalChanges): self
    {
        return new self($this->strategy, $this->allowList, $this->transitiveMode, $dropTemporaryConstraints ? [] : $this->temporaryConstraints, $dropMinimalChanges ? false : $this->minimalChanges, $this->rootConstraintChanges, $this->description, $this->pins, $this->extraArguments);
    }

    /** Identity of the solver request: allow-list order does not matter. */
    public function signature(): string
    {
        $allow = $this->allowList;
        sort($allow);
        $temp = $this->temporaryConstraints;
        ksort($temp);
        $pins = $this->pins;
        ksort($pins);
        $roots = array_map(static fn (RootConstraintChange $c): string => $c->packageName . '=' . $c->toConstraint . ($c->isDev ? '@dev' : ''), $this->rootConstraintChanges);
        sort($roots);

        return json_encode([$allow, $this->transitiveMode, $temp, $this->minimalChanges, $roots, $pins, $this->extraArguments], JSON_THROW_ON_ERROR);
    }

    public function changesRootConstraints(): bool
    {
        return $this->rootConstraintChanges !== [];
    }

    /**
     * The shell command a developer runs to reproduce this candidate.
     */
    public function commandLine(bool $minimalChangesSupported = true): string
    {
        $parts = [];
        if ($this->rootConstraintChanges !== []) {
            $prod = [];
            $dev = [];
            foreach ($this->rootConstraintChanges as $change) {
                $arg = self::quote($change->packageName . ':' . $change->toConstraint);
                if ($change->isDev) {
                    $dev[] = $arg;
                } else {
                    $prod[] = $arg;
                }
            }
            if ($prod !== []) {
                $parts[] = 'composer require --no-update ' . implode(' ', $prod);
            }
            if ($dev !== []) {
                $parts[] = 'composer require --no-update --dev ' . implode(' ', $dev);
            }
        }

        $update = ['composer update'];
        foreach ($this->allowList as $name) {
            $update[] = isset($this->pins[$name]) ? self::quote($name . ':' . $this->pins[$name]) : $name;
        }
        foreach ($this->pins as $name => $version) {
            if (!in_array($name, $this->allowList, true)) {
                $update[] = '--with ' . self::quote($name . ':' . $version);
            }
        }
        if ($this->transitiveMode === Request::UPDATE_LISTED_WITH_TRANSITIVE_DEPS) {
            $update[] = '-W';
        } elseif ($this->transitiveMode === Request::UPDATE_LISTED_WITH_TRANSITIVE_DEPS_NO_ROOT_REQUIRE) {
            $update[] = '-w';
        }
        if ($this->minimalChanges && $minimalChangesSupported) {
            $update[] = '-m';
        }
        foreach ($this->temporaryConstraints as $package => $constraint) {
            $update[] = '--with ' . self::quote($package . ':' . $constraint);
        }
        foreach ($this->extraArguments as $argument) {
            $update[] = self::quote($argument);
        }
        $parts[] = implode(' ', $update);

        return implode(' && ', $parts);
    }

    private static function quote(string $value): string
    {
        return preg_match('{^[A-Za-z0-9_./:@^~+=,-]+$}', $value) === 1 ? $value : "'" . str_replace("'", "'\\''", $value) . "'";
    }
}
