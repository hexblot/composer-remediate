<?php

declare(strict_types=1);

namespace Remediate\Command;

use Composer\Command\BaseCommand;
use Composer\Factory;
use Remediate\Engine\Advisory\Db\DatabaseBuilder;
use Remediate\Engine\Advisory\Db\DatabaseLocator;
use Remediate\Engine\Advisory\Db\Enrichment\EnrichmentSourceInterface;
use Remediate\Engine\Advisory\Db\Enrichment\EpssSource;
use Remediate\Engine\Advisory\Db\Enrichment\KevSource;
use Remediate\Engine\Advisory\Db\Merger;
use Remediate\Engine\Advisory\Db\DatabaseWriter;
use Remediate\Engine\Advisory\Db\Source\AdvisorySourceInterface;
use Remediate\Engine\Advisory\Db\Source\FriendsOfPhpSource;
use Remediate\Engine\Advisory\Db\Source\JsonFileSource;
use Remediate\Engine\Advisory\Db\Source\OsvDumpSource;
use Remediate\Engine\Advisory\Db\Source\PackagistApiSource;
use Remediate\Engine\Plan\Plan;
use Remediate\Engine\Planner;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

final class DbBuildCommand extends BaseCommand
{
    public const SOURCES = ['packagist', 'osv', 'friendsofphp'];
    public const ENRICHMENTS = ['epss', 'kev'];

    protected function configure(): void
    {
        $this
            ->setName('remediate:db-build')
            ->setAliases(['remediate-db-build'])
            ->setDescription('Build a local advisory database (SQLite) from live sources: Packagist, OSV and FriendsOfPHP')
            ->setDefinition([
                new InputOption('output', 'o', InputOption::VALUE_REQUIRED, 'Where to write the database (default: COMPOSER_CACHE_DIR/remediate/advisories.sqlite)'),
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

Use the file with <info>composer remediate --database-location=PATH</info>, the REMEDIATE_DATABASE
environment variable, or <info>extra.remediate.database</info> in composer.json. The file is portable:
publish it on a web server or as a release asset and point other machines at the URL.
HELP);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = $this->getIO();
        $composer = $this->tryComposer() ?? Factory::createGlobal($io, true, true);
        if ($composer === null) {
            $io->writeError('<error>Could not initialise Composer.</error>');

            return Plan::EXIT_ERROR;
        }
        $downloader = Factory::createHttpDownloader($io, $composer->getConfig());
        $locator = new DatabaseLocator($composer, $downloader);
        $target = $input->getOption('output');
        $path = is_string($target) && $target !== '' ? $target : $locator->defaultBuildPath();
        $tempDir = $locator->cacheDirectory() . '/tmp';

        $selected = array_map('strtolower', array_map('strval', (array) $input->getOption('source')));
        if ($selected === []) {
            $selected = self::SOURCES;
        }
        $unknown = array_diff($selected, self::SOURCES);
        if ($unknown !== []) {
            $io->writeError(sprintf('<error>Unknown source(s) %s; choose from %s.</error>', implode(', ', $unknown), implode(', ', self::SOURCES)));

            return Plan::EXIT_ERROR;
        }
        $fop = $input->getOption('friendsofphp-path');
        /** @var list<AdvisorySourceInterface> $sources */
        $sources = [];
        foreach (self::SOURCES as $name) {
            if (!in_array($name, $selected, true)) {
                continue;
            }
            $sources[] = match ($name) {
                'packagist' => new PackagistApiSource($downloader),
                'osv' => new OsvDumpSource($downloader, $tempDir),
                'friendsofphp' => new FriendsOfPhpSource($downloader, $tempDir, is_string($fop) && $fop !== '' ? $fop : null),
            };
        }

        foreach ((array) $input->getOption('include') as $file) {
            if (is_string($file) && $file !== '') {
                $sources[] = new JsonFileSource($file);
            }
        }

        $enrich = array_map('strtolower', array_map('strval', (array) $input->getOption('enrich')));
        if ($enrich === []) {
            $enrich = self::ENRICHMENTS;
        }
        $unknownEnrich = array_diff($enrich, [...self::ENRICHMENTS, 'none']);
        if ($unknownEnrich !== []) {
            $io->writeError(sprintf('<error>Unknown enrichment(s) %s; choose from %s or none.</error>', implode(', ', $unknownEnrich), implode(', ', self::ENRICHMENTS)));

            return Plan::EXIT_ERROR;
        }
        $epssFile = $input->getOption('epss-file');
        $kevFile = $input->getOption('kev-file');
        /** @var list<EnrichmentSourceInterface> $enrichments */
        $enrichments = [];
        if (!in_array('none', $enrich, true)) {
            if (in_array('epss', $enrich, true)) {
                $enrichments[] = new EpssSource($downloader, $tempDir, is_string($epssFile) && $epssFile !== '' ? $epssFile : null);
            }
            if (in_array('kev', $enrich, true)) {
                $enrichments[] = new KevSource($downloader, is_string($kevFile) && $kevFile !== '' ? $kevFile : null);
            }
        }

        $log = static function (string $message) use ($io): void {
            $io->writeError('<comment>' . $message . '</comment>');
        };
        try {
            $result = (new DatabaseBuilder($sources, new Merger(), new DatabaseWriter(), $enrichments))->build($path, $log, ['engine_version' => Planner::engineVersion()]);
        } catch (\RuntimeException $e) {
            $io->writeError('<error>Build failed: ' . $e->getMessage() . '</error>');

            return Plan::EXIT_ADVISORIES_UNAVAILABLE;
        }

        $output->writeln(sprintf('<info>Advisory database written:</info> %s', $result['path']));
        $output->writeln(sprintf('  %d advisories from %d source records, %d with conflicting ranges, %d coverage gap%s, %.1f MB', $result['advisories'], $result['records'], $result['conflicts'], $result['gaps'], $result['gaps'] === 1 ? '' : 's', $result['bytes'] / 1048576));
        if ($result['gaps'] > 0) {
            $output->writeln('  Coverage gaps are upstream records the build could not interpret; they are stored in the database and reported by composer remediate for packages in the lock. List them with remediate:db-status.');
        }
        if ($enrichments !== []) {
            $output->writeln(sprintf('  exploit data (EPSS / CISA KEV) for %d CVE%s%s', $result['exploits'], $result['exploits'] === 1 ? '' : 's', $result['enrichment_errors'] !== [] ? '; unavailable: ' . implode('; ', $result['enrichment_errors']) : ''));
        }
        $output->writeln(sprintf('  dataset hash %s', $result['hash']));
        $output->writeln(sprintf('Use it with: <comment>composer remediate --database-location=%s</comment>', $result['path']));

        return 0;
    }
}
