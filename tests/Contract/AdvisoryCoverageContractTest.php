<?php

declare(strict_types=1);

namespace Remediate\Tests\Contract;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\Db\DatabaseWriter;
use Remediate\Engine\Advisory\Db\Source\FriendsOfPhpSource;
use Remediate\Engine\Advisory\Db\Source\OsvDumpSource;
use Remediate\Tests\Support\CommandRunner;
use Remediate\Tests\Support\ScriptedDownloader;
use Remediate\Tests\Support\ScriptedProject;
use Remediate\Tests\Support\Zips;

/**
 * Invariant: advisory input this tool cannot fully read never produces a clean result.
 *
 * A clean result is a claim about a lock file, and the claim is only as good as the data behind it.
 * Anything the build could not interpret has to reach the report as a coverage gap, whatever else in
 * the same document it could interpret. The failure this guards against is silence: a record that
 * survives with the portion that parsed, and no trace of the portion that did not.
 *
 * Stated over a range of malformed shapes rather than the one that first slipped through, because the
 * property is about partial reads in general, not about any particular kind of rubbish.
 */
final class AdvisoryCoverageContractTest extends TestCase
{
    /** @return iterable<string, array{array<string, mixed>}> */
    public static function partiallyUnreadableDocuments(): iterable
    {
        $package = ['ecosystem' => 'Packagist', 'name' => 'acme/lib'];
        $goodRange = ['type' => 'ECOSYSTEM', 'events' => [['introduced' => '0'], ['fixed' => '0.5.0']]];

        yield 'a range whose events are not a list' => [[
            'id' => 'OSV-EVENTS', 'affected' => [['package' => $package, 'ranges' => [$goodRange, ['type' => 'ECOSYSTEM', 'events' => 'unreadable']]]],
        ]];
        yield 'a range of a type this cannot reason about' => [[
            'id' => 'OSV-TYPE', 'affected' => [['package' => $package, 'ranges' => [$goodRange, ['type' => 'FUTURE-SCHEME', 'events' => [['introduced' => '0']]]]]],
        ]];
        yield 'a range with no type at all' => [[
            'id' => 'OSV-NOTYPE', 'affected' => [['package' => $package, 'ranges' => [$goodRange, ['events' => [['introduced' => '0']]]]]],
        ]];
        yield 'an affected list that is not a list' => [[
            'id' => 'OSV-CONTAINER', 'affected' => 'unreadable container',
        ]];
        yield 'an affected entry that is not an entry' => [[
            'id' => 'OSV-ENTRY', 'affected' => [['package' => $package, 'ranges' => [$goodRange]], 'not an entry'],
        ]];
        yield 'an affected entry whose package is not a package' => [[
            'id' => 'OSV-PACKAGE', 'affected' => [['package' => $package, 'ranges' => [$goodRange]], ['package' => 'acme/lib']],
        ]];
        yield 'a range that is not a range, beside one that is' => [[
            'id' => 'OSV-SCALAR-RANGE', 'affected' => [['package' => $package, 'ranges' => [$goodRange, 'unreadable']]],
        ]];
        yield 'an event that is not an event, beside ones that are' => [[
            'id' => 'OSV-SCALAR-EVENT', 'affected' => [['package' => $package, 'ranges' => [['type' => 'ECOSYSTEM', 'events' => [['introduced' => '0'], ['fixed' => '0.5.0'], 'unreadable']]]]],
        ]];
        yield 'a version list holding something that is not a version' => [[
            'id' => 'OSV-SCALAR-VERSION', 'affected' => [['package' => $package, 'ranges' => [$goodRange], 'versions' => ['1.0.0', ['nested']]]],
        ]];
        yield 'every affected entry unreadable' => [[
            'id' => 'OSV-ALL-BAD', 'affected' => ['unreadable', 'also unreadable'],
        ]];
        yield 'an event boundary that is not a version string' => [[
            'id' => 'OSV-INT-BOUND', 'affected' => [['package' => $package, 'ranges' => [$goodRange, ['type' => 'ECOSYSTEM', 'events' => [['introduced' => 1]]]]]],
        ]];
        yield 'an event naming a boundary this does not know' => [[
            'id' => 'OSV-FUTURE-BOUND', 'affected' => [['package' => $package, 'ranges' => [$goodRange, ['type' => 'ECOSYSTEM', 'events' => [['future_boundary' => '0.8.0']]]]]],
        ]];
        yield 'a versions container that is not a container' => [[
            'id' => 'OSV-VERSIONS-SCALAR', 'affected' => [['package' => $package, 'ranges' => [$goodRange], 'versions' => 'unreadable']],
        ]];
        yield 'a ranges container that is not a container' => [[
            'id' => 'OSV-RANGES-SCALAR', 'affected' => [['package' => $package, 'ranges' => 'unreadable', 'versions' => ['0.1.0']]],
        ]];
        yield 'an explicit version that cannot be placed' => [[
            'id' => 'OSV-BAD-EXPLICIT', 'affected' => [['package' => $package, 'ranges' => [$goodRange], 'versions' => ['not a version']]],
        ]];
        yield 'a version the ecosystem cannot express' => [[
            'id' => 'OSV-VERSION', 'affected' => [['package' => $package, 'ranges' => [['type' => 'ECOSYSTEM', 'events' => [['introduced' => 'not a version']]]]]],
        ]];
    }

    /**
     * @param array<string, mixed> $document
     */
    #[DataProvider('partiallyUnreadableDocuments')]
    public function testSomethingUnreadableAlwaysReachesTheReport(array $document): void
    {
        $project = new ScriptedProject(['acme/lib' => '^1'], [['acme/lib', '1.0.0']]);
        try {
            $source = new OsvDumpSource(
                new ScriptedDownloader([OsvDumpSource::URL => Zips::build(['doc.json' => json_encode($document, JSON_THROW_ON_ERROR)])]),
                $project->directory . '/zip',
            );
            $records = $source->fetch(static function (): void {});
            $gaps = $source->gaps();

            // The build itself must have noticed. Either nothing survived, or something did and the
            // part that did not is recorded beside it; what must not happen is records and no gaps.
            // This holds whether or not anything in the document survived: a document discarded after
            // something in it could not be read must not be filed as simply belonging to another
            // ecosystem, which is the one classification that records nothing.
            self::assertNotSame([], $gaps, 'the build read this document only partly and said nothing about the rest');

            $path = $project->directory . '/partial.sqlite';
            (new DatabaseWriter())->write($records, [], $path, [], $gaps);
            $run = (new CommandRunner())->run(['command' => 'remediate', '--format' => 'json', '--database-location' => $path], $project->directory);
            $report = $run->json();

            // And the run must not read as clean. Either the package is reported affected, or the run
            // refuses to call the lock clean because of what it could not read.
            $clean = $run->exitCode === 0;
            self::assertFalse(
                $clean && $report['summary']['coverage_gaps'] === 0,
                sprintf("a lock was called clean on advisory data that could not be fully read\n%s", $run->describe()),
            );
        } finally {
            $project->destroy();
        }
    }

    public function testAnUnattributableGapSurvivesBesideAGapThatNamesAPackage(): void
    {
        // A record can fail to be read in two ways at once: a part that says which package it was
        // about, and a part that does not. Reporting only the named one loses the uncertainty that
        // could have been about any package, so a scan of some third package reads clean.
        $project = new ScriptedProject(['acme/lib' => '^1'], [['acme/lib', '1.0.0']]);
        try {
            $document = [
                'id' => 'OSV-TWO-WAYS',
                'affected' => [
                    'unreadable, and it does not say what it was about',
                    ['package' => ['ecosystem' => 'Packagist', 'name' => 'other/lib'], 'ranges' => 'unreadable'],
                ],
            ];
            $source = new OsvDumpSource(
                new ScriptedDownloader([OsvDumpSource::URL => Zips::build(['doc.json' => json_encode($document, JSON_THROW_ON_ERROR)])]),
                $project->directory . '/zip',
            );
            $records = $source->fetch(static function (): void {});
            $gaps = $source->gaps();

            $packages = array_map(static fn ($gap) => $gap->package, $gaps);
            self::assertContains(null, $packages, 'the part that named no package has to stay its own gap');

            $path = $project->directory . '/two-ways.sqlite';
            (new DatabaseWriter())->write($records, [], $path, [], $gaps);
            $run = (new CommandRunner())->run(['command' => 'remediate', '--format' => 'json', '--database-location' => $path], $project->directory);
            self::assertNotSame(0, $run->exitCode, 'a package nothing named is not thereby unaffected' . "\n" . $run->describe());
        } finally {
            $project->destroy();
        }
    }

    /** @return iterable<string, array{string}> */
    public static function partiallyUnreadableAdvisoryFiles(): iterable
    {
        $good = "        1.x:\n            versions: ['>=1.0.0', '<1.0.5']\n";

        yield 'a branch that is not a branch' => ["title: t\nreference: composer://acme/lib\nbranches:\n" . $good . "        2.x: 'unreadable'\n"];
        yield 'a branch with no versions list' => ["title: t\nreference: composer://acme/lib\nbranches:\n" . $good . "        2.x:\n            time: 2026-01-01 00:00:00\n"];
        yield 'a versions list holding something that is not a constraint' => ["title: t\nreference: composer://acme/lib\nbranches:\n" . $good . "        2.x:\n            versions: ['>=2.0.0', {nested: thing}]\n"];
    }

    /**
     * The same rule, in the other source. A guarantee that holds in one reader and not the other is
     * not a guarantee: the database is built from both, and a scan cannot tell which one was thin.
     */
    #[DataProvider('partiallyUnreadableAdvisoryFiles')]
    public function testTheOtherSourceAlsoKeepsWhatItCouldNotRead(string $yaml): void
    {
        $project = new ScriptedProject(['acme/lib' => '^1'], [['acme/lib', '1.0.0']]);
        try {
            $source = new FriendsOfPhpSource(
                new ScriptedDownloader([FriendsOfPhpSource::URL => Zips::build(['security-advisories-master/acme/lib/CVE-2026-1.yaml' => $yaml])]),
                $project->directory . '/zip',
            );
            $records = $source->fetch(static function (): void {});
            $gaps = $source->gaps();

            self::assertNotSame([], $gaps, 'the branch this could not read was dropped without a word');

            $path = $project->directory . '/fop.sqlite';
            (new DatabaseWriter())->write($records, [], $path, [], $gaps);
            $run = (new CommandRunner())->run(['command' => 'remediate', '--format' => 'json', '--database-location' => $path], $project->directory);
            $report = $run->json();
            self::assertFalse(
                $run->exitCode === 0 && $report['summary']['coverage_gaps'] === 0,
                "a lock was called clean on an advisory read only in part\n" . $run->describe(),
            );
        } finally {
            $project->destroy();
        }
    }

    public function testDataThatIsFullyReadableStillProducesNoGaps(): void
    {
        // The other half of the contract. A guard that turned everything into a gap would satisfy the
        // test above and be useless: gaps gate clean results, so crying wolf has a cost. A document
        // this can read completely, including a GIT range it has no use for, produces none.
        $project = new ScriptedProject(['acme/lib' => '^1'], [['acme/lib', '1.0.0']]);
        try {
            $document = [
                'id' => 'OSV-COMPLETE',
                'affected' => [[
                    'package' => ['ecosystem' => 'Packagist', 'name' => 'acme/lib'],
                    'ranges' => [
                        ['type' => 'ECOSYSTEM', 'events' => [['introduced' => '0'], ['fixed' => '2.0.0']]],
                        ['type' => 'GIT', 'events' => [['introduced' => 'aaaaaaaa'], ['fixed' => 'bbbbbbbb']]],
                    ],
                ]],
            ];
            $source = new OsvDumpSource(
                new ScriptedDownloader([OsvDumpSource::URL => Zips::build(['doc.json' => json_encode($document, JSON_THROW_ON_ERROR)])]),
                $project->directory . '/zip',
            );
            $records = $source->fetch(static function (): void {});

            self::assertCount(1, $records);
            self::assertSame([], $source->gaps(), 'a commit range is not something missing; every record that has one also has the version range');
        } finally {
            $project->destroy();
        }
    }
}
