<?php

declare(strict_types=1);

namespace Remediate\Tests\Contract;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\Db\DatabaseWriter;
use Remediate\Engine\Advisory\Db\Source\FriendsOfPhpSource;
use Remediate\Engine\Advisory\Db\Source\OsvDumpSource;
use Remediate\Engine\Advisory\Db\Source\PackagistShapeMapper;
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

        // An identity that cannot be read is not an identity belonging to another ecosystem. Each of
        // these entries might be about a locked package; only a reader that says so positively may
        // treat the entry as out of scope.
        $good = ['package' => $package, 'ranges' => [$goodRange]];
        yield 'a Packagist package whose name is not a name' => [[
            'id' => 'OSV-NAME-SHAPE', 'affected' => [$good, ['package' => ['ecosystem' => 'Packagist', 'name' => ['acme/lib']], 'versions' => ['1.0.0']]],
        ]];
        yield 'a Packagist package with no name at all' => [[
            'id' => 'OSV-NO-NAME', 'affected' => [$good, ['package' => ['ecosystem' => 'Packagist'], 'versions' => ['1.0.0']]],
        ]];
        yield 'an affected entry whose package is null' => [[
            'id' => 'OSV-NULL-PACKAGE', 'affected' => [$good, ['package' => null, 'versions' => ['1.0.0']]],
        ]];
        yield 'a package that does not say which ecosystem it is from' => [[
            'id' => 'OSV-NO-ECOSYSTEM', 'affected' => [$good, ['package' => ['name' => 'acme/lib'], 'versions' => ['1.0.0']]],
        ]];
        yield 'an affected entry with no package at all' => [[
            'id' => 'OSV-NO-PACKAGE', 'affected' => [$good, ['versions' => ['1.0.0']]],
        ]];
        // A name no package could be called is not an identity either. Kept, it would file a range
        // under something no lock can ever match, which is the quietest loss of all.
        yield 'a name no package could be called' => [[
            'id' => 'OSV-BAD-NAME', 'affected' => [$good, ['package' => ['ecosystem' => 'Packagist', 'name' => 'acme lib'], 'versions' => ['1.0.0']]],
        ]];

        // A container present as null is not an absent one, and a part that states nothing is not a
        // part stating that nothing is affected.
        yield 'a ranges container present as null' => [[
            'id' => 'OSV-NULL-RANGES', 'affected' => [['package' => $package, 'ranges' => null, 'versions' => ['0.1.0']]],
        ]];
        yield 'a versions container present as null' => [[
            'id' => 'OSV-NULL-VERSIONS', 'affected' => [['package' => $package, 'ranges' => [$goodRange], 'versions' => null]],
        ]];
        yield 'a range with an empty event list, beside a readable range' => [[
            'id' => 'OSV-NO-EVENTS', 'affected' => [['package' => $package, 'ranges' => [$goodRange, ['type' => 'ECOSYSTEM', 'events' => []]]]],
        ]];
        yield 'a range whose events close without opening' => [[
            'id' => 'OSV-NO-INTRODUCED', 'affected' => [['package' => $package, 'ranges' => [$goodRange, ['type' => 'ECOSYSTEM', 'events' => [['fixed' => '0.8.0']]]]]],
        ]];

        // A readable boundary in the same event as an unreadable one: whichever is looked at first,
        // the other still has to be read.
        yield 'an event whose second boundary is not a version string' => [[
            'id' => 'OSV-SECOND-BOUND', 'affected' => [['package' => $package, 'ranges' => [['type' => 'ECOSYSTEM', 'events' => [['introduced' => '0', 'fixed' => ['unreadable']], ['fixed' => '0.5.0']]]]]],
        ]];
        yield 'an event naming an unknown boundary beside a known one' => [[
            'id' => 'OSV-SECOND-UNKNOWN', 'affected' => [['package' => $package, 'ranges' => [['type' => 'ECOSYSTEM', 'events' => [['introduced' => '0', 'future_boundary' => '2.0.0'], ['fixed' => '0.5.0']]]]]],
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
        yield 'a branch listing no versions at all' => ["title: t\nreference: composer://acme/lib\nbranches:\n" . $good . "        2.x:\n            versions: []\n"];
        // The file sits under acme/lib/ in a repository of Composer advisories, so a reference that
        // cannot be read is not an advisory about some other packaging ecosystem.
        yield 'a reference that is not text' => ["title: t\nreference: {unreadable: value}\nbranches:\n" . $good];
        yield 'a file with no reference at all' => ["title: t\nbranches:\n" . $good];
        yield 'a reference naming no package' => ["title: t\nreference: 'composer://'\nbranches:\n" . $good];
        yield 'a reference that is neither a scheme nor a package' => ["title: t\nreference: 'not a reference'\nbranches:\n" . $good];
        yield 'a reference naming something no package could be called' => ["title: t\nreference: 'composer://acme lib'\nbranches:\n" . $good];
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

    /** @return iterable<string, array{array<mixed>}> */
    public static function partiallyUnreadablePackagistDocuments(): iterable
    {
        $good = ['advisoryId' => 'PKSA-1111-2222-3333-4444', 'affectedVersions' => '>=1.0.0,<1.0.5'];

        yield 'a key that is not a package name' => [['advisories' => ['other/lib' => [$good], 'acme lib' => [$good]]]];
        yield 'a key that is not a string' => [['advisories' => ['other/lib' => [$good], 7 => [$good]]]];
        yield 'a package whose advisories are not a list' => [['advisories' => ['other/lib' => [$good], 'acme/lib' => 'unreadable']]];
        yield 'an entry that is not an entry' => [['advisories' => ['acme/lib' => [$good, 'unreadable']]]];
        yield 'an entry with no version range' => [['advisories' => ['acme/lib' => [$good, ['advisoryId' => 'PKSA-no-range']]]]];
        yield 'an entry whose range cannot be parsed' => [['advisories' => ['acme/lib' => [$good, ['advisoryId' => 'PKSA-bad', 'affectedVersions' => 'unreadable']]]]];
    }

    /**
     * And in the third reader, which serves Packagist's API, `--include` files and `--advisories-file`.
     * The same invariant again, because a database built from three readers is only as complete as the
     * least careful of them.
     *
     * @param array<mixed> $document
     */
    #[DataProvider('partiallyUnreadablePackagistDocuments')]
    public function testTheThirdReaderAlsoKeepsWhatItCouldNotRead(array $document): void
    {
        $project = new ScriptedProject(['acme/lib' => '^1'], [['acme/lib', '1.0.0']]);
        try {
            $result = (new PackagistShapeMapper())->mapDocument($document, 'Test');

            self::assertNotSame([], $result['gaps'], 'something in this document was dropped without a word');

            $path = $project->directory . '/packagist.sqlite';
            (new DatabaseWriter())->write($result['records'], [], $path, [], $result['gaps']);
            $run = (new CommandRunner())->run(['command' => 'remediate', '--format' => 'json', '--database-location' => $path], $project->directory);
            self::assertFalse(
                $run->exitCode === 0 && $run->json()['summary']['coverage_gaps'] === 0,
                "a lock was called clean on advisory data that could not be fully read\n" . $run->describe(),
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

    public function testAnEcosystemThisCanReadIsStillNotAGap(): void
    {
        // The boundary the rule above turns on. Unreadable identity becomes a gap, so the reader has
        // to keep saying "this is npm's, not mine" about the identities it can read: the Packagist
        // dump carries plenty, and a gap for each would gate every scan on nothing.
        $project = new ScriptedProject(['acme/lib' => '^1'], [['acme/lib', '1.0.0']]);
        try {
            $document = [
                'id' => 'OSV-OTHER-ECOSYSTEM',
                'affected' => [
                    ['package' => ['ecosystem' => 'Packagist', 'name' => 'acme/lib'], 'ranges' => [['type' => 'ECOSYSTEM', 'events' => [['introduced' => '0'], ['fixed' => '0.5.0']]]]],
                    ['package' => ['ecosystem' => 'npm', 'name' => 'left-pad'], 'ranges' => [['type' => 'SEMVER', 'events' => [['introduced' => '0'], ['fixed' => '1.0.0']]]]],
                ],
            ];
            $osv = new OsvDumpSource(
                new ScriptedDownloader([OsvDumpSource::URL => Zips::build(['doc.json' => json_encode($document, JSON_THROW_ON_ERROR)])]),
                $project->directory . '/zip',
            );
            self::assertCount(1, $osv->fetch(static function (): void {}));
            self::assertSame([], $osv->gaps(), 'an npm entry is read, and read as somebody else\'s');

            $fop = new FriendsOfPhpSource(
                new ScriptedDownloader([FriendsOfPhpSource::URL => Zips::build([
                    'security-advisories-master/drupal/core/SA-CORE-2026-1.yaml' => "title: t\nreference: drupal://core\nbranches:\n    1.x:\n        versions: ['>=1.0.0']\n",
                    'security-advisories-master/acme/lib/CVE-2026-1.yaml' => "title: t\nreference: composer://acme/lib\nbranches:\n    1.x:\n        versions: ['>=1.0.0', '<1.0.5']\n",
                ])]),
                $project->directory . '/fop-zip',
            );
            self::assertCount(1, $fop->fetch(static function (): void {}));
            self::assertSame([], $fop->gaps(), 'a Drupal advisory says which ecosystem it is about');
        } finally {
            $project->destroy();
        }
    }
}
