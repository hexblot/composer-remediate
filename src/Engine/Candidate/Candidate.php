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
     * The shell command a developer runs to reproduce this candidate, as a reader would type it. Built from the same argument
     * lists the applier runs, so what the report prints and what `--apply` executes cannot drift apart.
     */
    public function commandLine(bool $minimalChangesSupported = true): string
    {
        $parts = [];
        foreach ([...$this->requireArgumentLists(), $this->updateArguments($minimalChangesSupported)] as $arguments) {
            $parts[] = self::render($arguments);
        }

        return implode(' && ', $parts);
    }

    /**
     * One argument list as a command someone can paste into a shell and get these arguments back.
     *
     * Every place that shows a command has to come through here. A constraint like
     * `--with acme/lib:>=1.2` pasted unquoted is a redirection: the shell writes a file called `=1.2`
     * and Composer never sees the constraint, so a report that renders arguments by joining them with
     * spaces is not describing the command that ran.
     *
     * @param list<string> $arguments
     */
    public static function render(array $arguments): string
    {
        return 'composer ' . implode(' ', array_map(self::quote(...), $arguments));
    }

    /**
     * The `composer require --no-update` steps a recommendation needs before its update, one argument
     * list each: none for most candidates, one or two when the fix widens a root constraint
     * (production and development requirements cannot be written in a single command).
     *
     * @return list<list<string>>
     */
    public function requireArgumentLists(): array
    {
        $prod = [];
        $dev = [];
        foreach ($this->rootConstraintChanges as $change) {
            $argument = $change->packageName . ':' . $change->toConstraint;
            if ($change->isDev) {
                $dev[] = $argument;
            } else {
                $prod[] = $argument;
            }
        }
        $lists = [];
        if ($prod !== []) {
            $lists[] = ['require', '--no-update', ...$prod];
        }
        if ($dev !== []) {
            $lists[] = ['require', '--no-update', '--dev', ...$dev];
        }

        return $lists;
    }

    /**
     * The `composer update` arguments, without the `composer` itself: the packages to update (a pinned
     * one as `name:version`), the transitive flag, `-m` where it exists, the `--with` constraints and
     * the platform arguments the analysis ran with.
     *
     * @return list<string>
     */
    public function updateArguments(bool $minimalChangesSupported = true): array
    {
        $arguments = ['update'];
        foreach ($this->allowList as $name) {
            $arguments[] = isset($this->pins[$name]) ? $name . ':' . $this->pins[$name] : $name;
        }
        foreach ($this->pins as $name => $version) {
            if (!in_array($name, $this->allowList, true)) {
                $arguments[] = '--with';
                $arguments[] = $name . ':' . $version;
            }
        }
        if ($this->transitiveMode === Request::UPDATE_LISTED_WITH_TRANSITIVE_DEPS) {
            $arguments[] = '-W';
        } elseif ($this->transitiveMode === Request::UPDATE_LISTED_WITH_TRANSITIVE_DEPS_NO_ROOT_REQUIRE) {
            $arguments[] = '-w';
        }
        if ($this->minimalChanges && $minimalChangesSupported) {
            $arguments[] = '-m';
        }
        foreach ($this->temporaryConstraints as $package => $constraint) {
            $arguments[] = '--with';
            $arguments[] = $package . ':' . $constraint;
        }
        array_push($arguments, ...$this->extraArguments);

        return $arguments;
    }

    private static function quote(string $value): string
    {
        return preg_match('{^[A-Za-z0-9_./:@^~+=,-]+$}', $value) === 1 ? $value : "'" . str_replace("'", "'\\''", $value) . "'";
    }
}
