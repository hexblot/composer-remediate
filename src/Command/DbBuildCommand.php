<?php

declare(strict_types=1);

namespace Remediate\Command;

use Composer\Command\BaseCommand;
use Composer\Factory;
use Remediate\Engine\Advisory\AdvisoryLookupFailed;
use Remediate\Engine\Advisory\Db\DatabaseBuildFactory;
use Remediate\Engine\Advisory\Db\DatabaseBuilder;
use Remediate\Engine\Advisory\Db\DatabaseLocator;
use Remediate\Engine\Advisory\Db\OperatorConfiguration;
use Remediate\Engine\Advisory\Db\Merger;
use Remediate\Engine\Advisory\Db\DatabaseWriter;
use Remediate\Engine\Plan\Plan;
use Remediate\Engine\Planner;
use Remediate\Output\ConsoleText;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

final class DbBuildCommand extends BaseCommand
{
    public const SOURCES = DatabaseBuildFactory::SOURCES;
    public const ENRICHMENTS = DatabaseBuildFactory::ENRICHMENTS;

    protected function configure(): void
    {
        $this
            ->setName('remediate:db-build')
            ->setAliases(['remediate-db-build'])
            ->setDescription('Build a local advisory database (SQLite) from live sources: Packagist, OSV and FriendsOfPHP')
            ->setDefinition([
                new InputOption('output', 'o', InputOption::VALUE_REQUIRED, 'Where to write the database (default: the configured path, see --database-path of remediate; COMPOSER_CACHE_DIR/remediate/advisories.sqlite unless configured)'),
                new InputOption('if-stale', null, InputOption::VALUE_NONE, 'Build only when the database at the output path is missing or not current against the published one (REMEDIATE_DATABASE or extra.remediate.database, default: this project\'s release); otherwise report it as current and exit 0'),
                new InputOption('source', 's', InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Source to include: packagist, osv, friendsofphp (repeatable; default all)'),
                new InputOption('friendsofphp-path', null, InputOption::VALUE_REQUIRED, 'Local checkout of FriendsOfPHP/security-advisories to read instead of downloading'),
                new InputOption('include', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Additional JSON file in the Packagist API shape with private or organisational advisories (repeatable)'),
                new InputOption('enrich', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Exploit data to attach to the CVEs: epss (FIRST exploit probability), kev (CISA Known Exploited Vulnerabilities), or none (repeatable; default both)'),
                new InputOption('epss-file', null, InputOption::VALUE_REQUIRED, 'Local copy of the EPSS scores CSV (plain or .gz) to read instead of downloading'),
                new InputOption('kev-file', null, InputOption::VALUE_REQUIRED, 'Local copy of the CISA KEV catalogue JSON to read instead of downloading'),
            ])
            ->setHelp(<<<'HELP'
Pulls every advisory for the Packagist ecosystem from the selected sources (plus any --include files
with private advisories), normalises the version
ranges to Composer constraints, merges records that share an identifier (CVE, GHSA, PKSA, FriendsOfPHP
file), keeps every source's range and flags disagreements, and writes a single SQLite file.

Every CVE in the database is enriched with its EPSS exploit probability and its CISA KEV listing when
present (<info>--enrich</info>); reports order findings by that urgency. A feed that cannot be fetched
is recorded in the database's metadata and the build continues without it.

Written to the path <info>composer remediate</info> reads by default, so the next run uses it; a build
with no options reproduces the database this project publishes. <info>--if-stale</info> first checks the
existing file against the published database (same sha256 or dataset hash, or a newer local build) and
skips the build when it is current, which suits a CI cache. The file is portable: publish it on a web
server or as a release asset with a <info>.sha256</info> sidecar (or a latest.json) and point other
machines at the URL with <info>--database-location</info>.
HELP);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = $this->getIO();
        $project = $this->tryComposer();
        $composer = $project ?? Factory::createGlobal($io, true, true);
        if ($composer === null) {
            $io->writeError('<error>Could not initialise Composer.</error>');

            return Plan::EXIT_ERROR;
        }
        $downloader = (new OperatorConfiguration())->httpDownloader($io);
        $locator = new DatabaseLocator($composer, $downloader);
        $target = $input->getOption('output');
        $settings = $locator->settings(null, is_string($target) && $target !== '' ? $target : null, null, false, $project === null ? null : dirname((string) realpath(Factory::getComposerFile())));
        $path = $settings->path;
        $tempDir = $locator->cacheDirectory() . '/tmp';
        $str = static fn (string $name): ?string => is_string($v = $input->getOption($name)) && $v !== '' ? $v : null;
        $list = static fn (string $name): array => array_values(array_filter(array_map('strval', (array) $input->getOption($name)), static fn (string $v): bool => $v !== ''));

        try {
            $sources = DatabaseBuildFactory::sources($downloader, $tempDir, $list('source'), $str('friendsofphp-path'), $list('include'));
            $enrichments = DatabaseBuildFactory::enrichments($downloader, $tempDir, $list('enrich'), $str('epss-file'), $str('kev-file'));
        } catch (\InvalidArgumentException $e) {
            $io->writeError('<error>' . ConsoleText::safe($e->getMessage()) . '</error>');

            return Plan::EXIT_ERROR;
        }

        $log = static function (string $message) use ($io): void {
            $io->writeError('<comment>' . ConsoleText::safe($message) . '</comment>');
        };
        $build = static fn (string $path): array => (new DatabaseBuilder($sources, new Merger(), new DatabaseWriter(), $enrichments))->build($path, $log, ['engine_version' => Planner::engineVersion()]);
        try {
            if ((bool) $input->getOption('if-stale')) {
                if (!$settings->usesDatabase()) {
                    $io->writeError('<error>--if-stale needs a published database to compare with, and the source is set to composer.</error>');

                    return Plan::EXIT_ERROR;
                }
                $result = null;
                $located = $locator->locate($settings, static function (string $path) use ($build, &$result): void {
                    $result = $build($path);
                }, true);
                foreach ($locator->warnings() as $warning) {
                    $io->writeError('<warning>' . ConsoleText::safe($warning) . '</warning>');
                }
                if ($located === null) {
                    $io->writeError('<error>No advisory database could be established at ' . ConsoleText::safe($path) . '.</error>');

                    return Plan::EXIT_ADVISORIES_UNAVAILABLE;
                }
                if ($result === null) {
                    $output->writeln(sprintf('<info>Advisory database kept:</info> %s (%s)', $located->path, ConsoleText::safe($located->provenance)));

                    return 0;
                }
            } else {
                $result = $build($path);
            }
        } catch (AdvisoryLookupFailed $e) {
            $io->writeError('<error>' . ConsoleText::safe($e->getMessage()) . '</error>');

            return Plan::EXIT_ADVISORIES_UNAVAILABLE;
        } catch (\RuntimeException $e) {
            $io->writeError('<error>Build failed: ' . ConsoleText::safe($e->getMessage()) . '</error>');

            return Plan::EXIT_ADVISORIES_UNAVAILABLE;
        }

        $output->writeln(sprintf('<info>Advisory database written:</info> %s', $result['path']));
        $output->writeln(sprintf('  %d advisories from %d source records, %d with conflicting ranges, %d coverage gap%s, %.1f MB', $result['advisories'], $result['records'], $result['conflicts'], $result['gaps'], $result['gaps'] === 1 ? '' : 's', $result['bytes'] / 1048576));
        if ($result['gaps'] > 0) {
            $output->writeln('  Coverage gaps are upstream records the build could not interpret; they are stored in the database and reported by composer remediate for packages in the lock. List them with remediate:db-status.');
        }
        if ($enrichments !== []) {
            $output->writeln(ConsoleText::safe(sprintf('  exploit data (EPSS / CISA KEV) for %d CVE%s%s', $result['exploits'], $result['exploits'] === 1 ? '' : 's', $result['enrichment_errors'] !== [] ? '; unavailable: ' . implode('; ', $result['enrichment_errors']) : '')));
        }
        $output->writeln(sprintf('  dataset hash %s', $result['hash']));
        if (is_string($target) && $target !== '') {
            $output->writeln(sprintf('Use it with: <comment>composer remediate --database-path=%s</comment>', $result['path']));
        } else {
            $output->writeln('composer remediate reads it from this path by default.');
        }

        return 0;
    }
}
