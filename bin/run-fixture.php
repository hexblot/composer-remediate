#!/usr/bin/env php
<?php

/**
 * Runs the planner against one fixture and prints the text report, exactly as the test harness
 * does. Useful while writing or debugging a fixture's expected.json.
 *
 *   php bin/run-fixture.php <fixture-name> [--allow-direct-require] [-v]
 */

declare(strict_types=1);

use Remediate\Output\TextRenderer;
use Remediate\Tests\Support\FixtureRunner;

require dirname(__DIR__) . '/vendor/autoload.php';

/** @var list<string> $args */
$args = array_slice(is_array($_SERVER['argv'] ?? null) ? $_SERVER['argv'] : [], 1);
$name = null;
$allowDirect = false;
foreach ($args as $arg) {
    if ($arg === '--allow-direct-require') {
        $allowDirect = true;
    } elseif ($arg !== '-v' && $name === null) {
        $name = $arg;
    }
}
if ($name === null) {
    fwrite(STDERR, "usage: run-fixture.php <fixture-name> [--allow-direct-require]\n");
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

$runner = new FixtureRunner();
$start = microtime(true);
$plan = $runner->run($dir, $allowDirect, in_array('-v', $args, true) ? static function (string $m): void {
    fwrite(STDERR, $m . "\n");
} : null);
$runner->cleanup();
echo (new TextRenderer())->render($plan);
fwrite(STDERR, sprintf("(%.1fs, exit code %d)\n", microtime(true) - $start, $plan->exitCode()));
exit($plan->exitCode());
