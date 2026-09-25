#!/usr/bin/env php
<?php

/**
 * Runs the planner against one fixture and prints the text report, exactly as the test harness
 * does. Useful while writing or debugging a fixture's expected.json.
 *
 *   php bin/run-fixture.php <fixture-name> [--format=text|html|json] [--write-reports] [--allow-direct-require] [-v]
 *
 * --write-reports stores report.md (console output), report.json, report.html, report.sarif and report.cdx.json under the fixture's reports/ directory
 * with deterministic metadata (fixture name, fixed timestamp) so they can be committed as examples.
 * FixtureTest renders the same files through FixtureReports and fails when a stored copy differs.
 */

declare(strict_types=1);

use Remediate\Output\ReportFormat;
use Symfony\Component\Console\Output\ConsoleOutput;
use Symfony\Component\Console\Output\OutputInterface;
use Remediate\Tests\Support\FixtureReports;
use Remediate\Tests\Support\FixtureRunner;

require dirname(__DIR__) . '/vendor/autoload.php';

/** @var list<string> $args */
$args = array_slice(is_array($_SERVER['argv'] ?? null) ? $_SERVER['argv'] : [], 1);
$name = null;
$allowDirect = false;
$writeReports = false;
$parallelism = 1;
$format = ReportFormat::Text;
foreach ($args as $arg) {
    if ($arg === '--allow-direct-require') {
        $allowDirect = true;
    } elseif ($arg === '--write-reports') {
        $writeReports = true;
    } elseif (str_starts_with($arg, '--parallelize=')) {
        $parallelism = max(1, (int) substr($arg, 14));
    } elseif (str_starts_with($arg, '--format=')) {
        $format = ReportFormat::tryFrom(substr($arg, 9)) ?? throw new InvalidArgumentException('unknown format ' . substr($arg, 9));
    } elseif ($arg !== '-v' && $name === null) {
        $name = $arg;
    }
}
if ($name === null || preg_match('{^[a-z0-9][a-z0-9._-]*$}', $name) !== 1) {
    fwrite(STDERR, "usage: run-fixture.php <fixture-name> [--allow-direct-require]  (a fixture directory name: lower-case letters, digits, . _ -)\n");
    exit(2);
}
$dir = FixtureRunner::FIXTURE_ROOT . '/' . $name;
if (!is_dir($dir)) {
    fwrite(STDERR, "no such fixture: $dir\n");
    exit(2);
}
$home = sys_get_temp_dir() . '/composer-remediate-run-' . getmypid();
@mkdir($home, 0700, true);
putenv('COMPOSER_HOME=' . $home);
putenv('COMPOSER_CACHE_DIR=' . $home . '/cache');
putenv('COMPOSER_NO_INTERACTION=1');

// The same default FixtureTest uses, so written reports match what it renders.
$allowDirect = $allowDirect || (bool) (FixtureRunner::expected($dir)['allow_direct_require'] ?? false);
$runner = new FixtureRunner();
$start = microtime(true);
$plan = $runner->run($dir, $allowDirect, in_array('-v', $args, true) ? static function (string $m, bool $detail = true): void {
    fwrite(STDERR, $m . "\n");
} : null, $parallelism);
$runner->cleanup();
if ($writeReports) {
    FixtureReports::write($plan, $dir);
    fwrite(STDERR, "reports written to $dir/reports\n");
}
$decorated = $format === ReportFormat::Text && stream_isatty(STDOUT);
$stdout = new ConsoleOutput(OutputInterface::VERBOSITY_NORMAL, $decorated);
$stdout->write($format->render($plan, true, $decorated), false, $decorated ? OutputInterface::OUTPUT_NORMAL : OutputInterface::OUTPUT_RAW);
fwrite(STDERR, sprintf("(%.1fs, exit code %d)\n", microtime(true) - $start, $plan->exitCode()));
exit($plan->exitCode());
