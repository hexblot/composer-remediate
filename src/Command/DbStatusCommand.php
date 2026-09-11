<?php

declare(strict_types=1);

namespace Remediate\Command;

use Composer\Command\BaseCommand;
use Composer\Factory;
use Remediate\Engine\Advisory\AdvisoryLookupFailed;
use Remediate\Engine\Advisory\Db\Database;
use Remediate\Engine\Advisory\Db\DatabaseLocator;
use Remediate\Engine\Advisory\Db\OperatorConfiguration;
use Remediate\Engine\Plan\Plan;
use Remediate\Output\ConsoleText;
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
                new InputOption('database-location', null, InputOption::VALUE_REQUIRED, 'Where the database comes from: https URL(s) tried in order (default: the database this project publishes), `composer` for none, or a local file; also REMEDIATE_DATABASE or extra.remediate.database'),
                new InputOption('database-path', null, InputOption::VALUE_REQUIRED, 'The file the database is kept in (default: COMPOSER_CACHE_DIR/remediate/advisories.sqlite); also REMEDIATE_DATABASE_PATH or extra.remediate.database_path'),
                new InputOption('database-max-age', null, InputOption::VALUE_REQUIRED, 'Fail when the copy cannot be confirmed current and is older than this many hours (or 2d, 36h); also REMEDIATE_DATABASE_MAX_AGE'),
                new InputOption('offline', null, InputOption::VALUE_NONE, 'Do not contact the source; report on the copy at the path as it is'),
                new InputOption('database-sha256', null, InputOption::VALUE_REQUIRED, 'Expected sha256 of the database (hex); a downloaded or cached copy that differs is refused'),
                new InputOption('allow-unverified-database', null, InputOption::VALUE_NONE, 'Accept a database URL without a published <url>.sha256 sidecar and without --database-sha256'),
            ]);
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
        $expectedSha = $input->getOption('database-sha256');
        if (is_string($expectedSha) && $expectedSha !== '' && preg_match('{^[0-9a-f]{64}$}i', $expectedSha) !== 1) {
            $io->writeError('<error>--database-sha256 must be a 64-character hexadecimal sha256 digest.</error>');

            return Plan::EXIT_ERROR;
        }
        $locator = new DatabaseLocator($composer, (new OperatorConfiguration())->httpDownloader($io), (bool) $input->getOption('offline'), !(bool) $input->getOption('allow-unverified-database'), is_string($expectedSha) && $expectedSha !== '' ? strtolower($expectedSha) : null);
        $option = static fn (string $name): ?string => is_string($v = $input->getOption($name)) && $v !== '' ? $v : null;
        try {
            $settings = $locator->settings($option('database-location'), $option('database-path'), $option('database-max-age'), false, $project === null ? null : dirname((string) realpath(Factory::getComposerFile())));
        } catch (\InvalidArgumentException $e) {
            $io->writeError('<error>' . ConsoleText::safe($e->getMessage()) . '</error>');

            return Plan::EXIT_ERROR;
        }
        if (!$settings->usesDatabase()) {
            $output->writeln('No advisory database is configured (' . ConsoleText::safe($settings->sourcesConfigured ? 'source set to composer' : 'default') . '); composer remediate asks the configured repositories, as composer audit does.');

            return 0;
        }
        $output->writeln(sprintf('Path: %s%s', ConsoleText::safe($settings->localSource() ?? $settings->path), $settings->pathConfigured || $settings->localSource() !== null ? '' : ' (default)'));
        if ($settings->localSource() === null) {
            $output->writeln(sprintf('Source: %s%s', ConsoleText::safe(DatabaseLocator::redact(implode(', ', $settings->sources))), $settings->sourcesConfigured ? '' : ' (default)'));
        }
        try {
            $located = $locator->locate($settings);
            if ($located === null) {
                foreach ($locator->warnings() as $warning) {
                    $output->writeln('<error>' . ConsoleText::safe($warning) . '</error>');
                }
                $output->writeln('Build one with <comment>composer remediate:db-build</comment>, or check the source; composer remediate falls back to the configured repositories meanwhile.');

                return Plan::EXIT_ADVISORIES_UNAVAILABLE;
            }
            $path = $located->path;
            $db = Database::open($path);
        } catch (AdvisoryLookupFailed $e) {
            $output->writeln('<error>' . ConsoleText::safe($e->getMessage()) . '</error>');
            $output->writeln('Build one with <comment>composer remediate:db-build</comment>.');

            return Plan::EXIT_ADVISORIES_UNAVAILABLE;
        }
        $output->writeln(sprintf('Status: %s', ConsoleText::safe($located->provenance)));
        foreach ($locator->warnings() as $warning) {
            $output->writeln('<warning>' . ConsoleText::safe($warning) . '</warning>');
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
                            $output->writeln(ConsoleText::safe(sprintf('  source: %s, %s records, fetched %s', is_scalar($source['name'] ?? null) ? (string) $source['name'] : '?', is_scalar($source['records'] ?? null) ? (string) $source['records'] : '?', is_scalar($source['fetched_at'] ?? null) ? (string) $source['fetched_at'] : '?')));
                        }
                    }
                }
                continue;
            }
            $output->writeln(ConsoleText::safe(sprintf('  %s: %s', $key, $value)));
        }

        $gaps = $db->gapsFor(null, 50);
        if ($gaps !== []) {
            $output->writeln(sprintf('Coverage gaps (%d, showing up to 50): upstream records the build could not interpret; the packages they name are treated as unaffected by them.', $db->gapCount()));
            foreach ($gaps as $gap) {
                $output->writeln('  ' . ConsoleText::safe($gap->describe()));
            }
        }

        return 0;
    }
}
