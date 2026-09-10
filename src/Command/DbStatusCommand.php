<?php

declare(strict_types=1);

namespace Remediate\Command;

use Composer\Command\BaseCommand;
use Composer\Factory;
use Remediate\Engine\Advisory\AdvisoryLookupFailed;
use Remediate\Engine\Advisory\Db\Database;
use Remediate\Engine\Advisory\Db\DatabaseLocator;
use Remediate\Engine\Plan\Plan;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

final class DbStatusCommand extends BaseCommand
{
    protected function configure(): void
    {
        $this
            ->setName('remediate:db-status')
            ->setAliases(['remediate-db-status'])
            ->setDescription('Show where the advisory database comes from and what it contains')
            ->setDefinition([
                new InputOption('database-location', null, InputOption::VALUE_REQUIRED, 'Path or URL of the database (default: REMEDIATE_DATABASE, then extra.remediate.database, then the default build path)'),
            ]);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = $this->getIO();
        $composer = $this->tryComposer() ?? Factory::createGlobal($io, true, true);
        if ($composer === null) {
            $io->writeError('<error>Could not initialise Composer.</error>');

            return Plan::EXIT_ERROR;
        }
        $locator = new DatabaseLocator($composer, Factory::createHttpDownloader($io, $composer->getConfig()));
        $option = $input->getOption('database-location');
        $location = $locator->configured(is_string($option) ? $option : null) ?? $locator->defaultBuildPath();
        $output->writeln(sprintf('Location: %s', $location));
        try {
            $path = $locator->resolve($location);
            $db = Database::open($path);
        } catch (AdvisoryLookupFailed $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');
            $output->writeln('Build one with <comment>composer remediate:db-build</comment>.');

            return Plan::EXIT_ADVISORIES_UNAVAILABLE;
        }
        $output->writeln(sprintf('File: %s (%.1f MB)', $path, (int) filesize($path) / 1048576));
        if (!$db->tracksGaps()) {
            $output->writeln('<warning>Built before coverage gaps were recorded; rebuild to learn which upstream records were left out.</warning>');
        }
        if (!$db->tracksExploits()) {
            $output->writeln('<warning>Built before exploit data (EPSS, CISA KEV) was recorded; findings are ordered by severity alone. Rebuild to enable it.</warning>');
        } else {
            $meta = $db->meta();
            $output->writeln(sprintf(
                'Exploit data: %d CVEs%s%s%s',
                $db->exploitCount(),
                isset($meta['epss_score_date']) ? ', EPSS scored ' . $meta['epss_score_date'] : '',
                isset($meta['kev_date_released']) ? ', KEV catalogue ' . $meta['kev_date_released'] . ' (' . ($meta['kev_count_matched'] ?? '0') . ' listed here)' : '',
                isset($meta['enrichment_errors']) ? ', unavailable at build: ' . $meta['enrichment_errors'] : '',
            ));
        }
        foreach ($db->meta() as $key => $value) {
            if ($key === 'sources') {
                $decoded = json_decode($value, true);
                if (is_array($decoded)) {
                    foreach ($decoded as $source) {
                        if (is_array($source)) {
                            $output->writeln(sprintf('  source: %s, %s records, fetched %s', $source['name'] ?? '?', $source['records'] ?? '?', $source['fetched_at'] ?? '?'));
                        }
                    }
                }
                continue;
            }
            $output->writeln(sprintf('  %s: %s', $key, $value));
        }

        $gaps = $db->gapsFor(null, 50);
        if ($gaps !== []) {
            $output->writeln(sprintf('Coverage gaps (%d, showing up to 50): upstream records the build could not interpret; the packages they name are treated as unaffected by them.', $db->gapCount()));
            foreach ($gaps as $gap) {
                $output->writeln('  ' . $gap->describe());
            }
        }

        return 0;
    }
}
