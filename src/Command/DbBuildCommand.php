<?php

declare(strict_types=1);

namespace Remediate\Command;

use Composer\Command\BaseCommand;
use Composer\Factory;
use Remediate\Engine\Advisory\Db\DatabaseBuilder;
use Remediate\Engine\Advisory\Db\DatabaseLocator;
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
            ])
            ->setHelp(<<<'HELP'
Pulls every advisory for the Packagist ecosystem from the selected sources (plus any --include files
with private advisories), normalises the version
ranges to Composer constraints, merges records that share an identifier (CVE, GHSA, PKSA, FriendsOfPHP
file), keeps every source's range and flags disagreements, and writes a single SQLite file.

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

        $log = static function (string $message) use ($io): void {
            $io->writeError('<comment>' . $message . '</comment>');
        };
        try {
            $result = (new DatabaseBuilder($sources))->build($path, $log, ['engine_version' => Planner::engineVersion()]);
        } catch (\RuntimeException $e) {
            $io->writeError('<error>Build failed: ' . $e->getMessage() . '</error>');

            return Plan::EXIT_ADVISORIES_UNAVAILABLE;
        }

        $output->writeln(sprintf('<info>Advisory database written:</info> %s', $result['path']));
        $output->writeln(sprintf('  %d advisories from %d source records, %d with conflicting ranges, %d coverage gap%s, %.1f MB', $result['advisories'], $result['records'], $result['conflicts'], $result['gaps'], $result['gaps'] === 1 ? '' : 's', $result['bytes'] / 1048576));
        if ($result['gaps'] > 0) {
            $output->writeln('  Coverage gaps are upstream records the build could not interpret; they are stored in the database and reported by composer remediate for packages in the lock. List them with remediate:db-status.');
        }
        $output->writeln(sprintf('  dataset hash %s', $result['hash']));
        $output->writeln(sprintf('Use it with: <comment>composer remediate --database-location=%s</comment>', $result['path']));

        return 0;
    }
}
