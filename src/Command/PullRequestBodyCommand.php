<?php

declare(strict_types=1);

namespace Remediate\Command;

use Composer\Command\BaseCommand;
use Remediate\Engine\Plan\Plan;
use Remediate\Output\ConsoleText;
use Remediate\Output\PullRequestBody;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Renders the description of a batched remediation pull request from two JSON reports: the run that
 * planned the fixes and the run that applied them. The shipped GitHub Action uses it, and it is a
 * command rather than a script so that it works however the plugin was installed.
 */
final class PullRequestBodyCommand extends BaseCommand
{
    protected function configure(): void
    {
        $this
            ->setName('remediate:pr-body')
            ->setAliases(['remediate-pr-body'])
            ->setDescription('Render a pull request description from the JSON reports of a planning run and an applying run')
            ->setDefinition([
                new InputArgument('before', InputArgument::REQUIRED, 'JSON report of the run that planned the fixes'),
                new InputArgument('after', InputArgument::REQUIRED, 'JSON report of the run that applied them'),
                new InputOption('commands', null, InputOption::VALUE_REQUIRED, 'File listing the commands that ran, one per line'),
            ])
            ->setHelp(<<<'HELP'
Reads two reports written with <info>--format=json</info> or <info>--output=x.json</info>: the state
before the fixes were applied and the state after. Writes Markdown on standard output saying which
advisories closed, which survived, what ran, and what the applying run warned about.

Advisory text is upstream data and reaches a rendered page, so it is escaped rather than trusted.
HELP);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $reports = [];
        foreach (['before', 'after'] as $which) {
            $path = (string) $input->getArgument($which);
            $raw = @file_get_contents($path);
            $decoded = $raw === false ? null : json_decode($raw, true);
            if (!is_array($decoded)) {
                $this->getIO()->writeError(sprintf('<error>%s is not a readable JSON report.</error>', ConsoleText::safe($path)));

                return Plan::EXIT_ERROR;
            }
            $reports[$which] = $decoded;
        }

        $commands = [];
        $commandsFile = $input->getOption('commands');
        if (is_string($commandsFile) && $commandsFile !== '' && is_file($commandsFile)) {
            $commands = array_values(array_filter(array_map('trim', explode("\n", (string) file_get_contents($commandsFile)))));
        }

        $output->write(PullRequestBody::render($reports['before'], $reports['after'], $commands), false, OutputInterface::OUTPUT_RAW);

        return 0;
    }
}
