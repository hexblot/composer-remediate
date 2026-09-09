<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Candidate;

use Composer\DependencyResolver\Request;
use Composer\Semver\VersionParser;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Candidate\Candidate;
use Remediate\Engine\Candidate\CandidateGenerator;
use Remediate\Engine\Candidate\RootConstraintChange;
use Remediate\Engine\Candidate\Strategy;

final class CandidateTest extends TestCase
{
    public function testCommandLineForParentUpdate(): void
    {
        $candidate = new Candidate(Strategy::ParentUpdate, ['drupal/core-recommended'], Request::UPDATE_LISTED_WITH_TRANSITIVE_DEPS, ['symfony/http-foundation' => '>=6.4.24'], true, [], '');
        self::assertSame("composer update drupal/core-recommended -W -m --with 'symfony/http-foundation:>=6.4.24'", $candidate->commandLine(true));
        self::assertSame("composer update drupal/core-recommended -W --with 'symfony/http-foundation:>=6.4.24'", $candidate->commandLine(false));
    }

    public function testCommandLineQuotesConstraintsWithSpacesOrPipes(): void
    {
        $candidate = new Candidate(Strategy::WithDependencies, ['a/b'], Request::UPDATE_LISTED_WITH_TRANSITIVE_DEPS_NO_ROOT_REQUIRE, ['a/b' => '>=1.2,<2.0 || >=2.1'], false, [], '');
        self::assertSame("composer update a/b -w --with 'a/b:>=1.2,<2.0 || >=2.1'", $candidate->commandLine());
    }

    public function testCommandLineWithRootConstraintChange(): void
    {
        $candidate = new Candidate(Strategy::RootConstraintWiden, ['acme/fw'], Request::UPDATE_LISTED_WITH_TRANSITIVE_DEPS, ['acme/lib' => '>=2.0'], true, ['acme/fw' => new RootConstraintChange('acme/fw', '^1.0', '^2.0', false)], '');
        self::assertSame("composer require --no-update acme/fw:^2.0 && composer update acme/fw -W -m --with 'acme/lib:>=2.0'", $candidate->commandLine());
    }

    public function testNextMajorConstraint(): void
    {
        $parser = new VersionParser();
        self::assertSame('^12.0', CandidateGenerator::nextMajorConstraint($parser->parseConstraints('^11.4')));
        self::assertSame('^2.4', CandidateGenerator::nextMajorConstraint($parser->parseConstraints('~2.3.0')));
        self::assertSame('^3.0', CandidateGenerator::nextMajorConstraint($parser->parseConstraints('~2.3')));
        self::assertSame('^0.6', CandidateGenerator::nextMajorConstraint($parser->parseConstraints('^0.5')));
        self::assertNull(CandidateGenerator::nextMajorConstraint($parser->parseConstraints('>=1.0')));
        self::assertNull(CandidateGenerator::nextMajorConstraint($parser->parseConstraints('*')));
    }
}
