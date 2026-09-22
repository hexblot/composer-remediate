<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Engine;

use PHPUnit\Framework\TestCase;
use Remediate\Engine\Graph\DependencyGraph;
use Remediate\Tests\Support\ScriptedProject;

/**
 * Dependency paths, and what the limits on them are limits on.
 */
final class DependencyGraphTest extends TestCase
{
    /** @var list<ScriptedProject> */
    private array $projects = [];

    protected function tearDown(): void
    {
        foreach ($this->projects as $project) {
            $project->destroy();
        }
        $this->projects = [];
    }

    /**
     * A diamond lattice: each layer requires both packages of the layer below, so the number of
     * distinct paths from the leaf to the root doubles per layer.
     */
    private function lattice(int $layers): DependencyGraph
    {
        $packages = [['acme/leaf', '1.0.0']];
        $requires = [];
        $previous = ['acme/leaf' => '^1'];
        for ($i = 0; $i < $layers; ++$i) {
            $next = [];
            foreach (['a', 'b'] as $side) {
                $name = 'acme/l' . $i . $side;
                $packages[] = [$name, '1.0.0'];
                $requires[$name] = $previous;
                $next[$name] = '^1';
            }
            $previous = $next;
        }
        $project = new ScriptedProject($previous, $packages, requires: $requires);
        $this->projects[] = $project;
        $context = $project->context();

        return new DependencyGraph($context->rootPackage(), $context->lockedRepository());
    }

    public function testPathsAreCappedAtTheLimit(): void
    {
        self::assertCount(DependencyGraph::MAX_PATHS, $this->lattice(8)->pathsToRoot('acme/leaf'));
    }

    public function testAPackageNothingDependsOnHasNoPath(): void
    {
        $graph = $this->lattice(2);
        self::assertSame([], $graph->pathsToRoot('acme/absent'));
    }
}
