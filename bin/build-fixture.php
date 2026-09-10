#!/usr/bin/env php
<?php

/**
 * Freezes a real Composer project into a reproducible fixture:
 *
 *   php bin/build-fixture.php --project=/path/to/project --name=drupal-11-http-foundation
 *
 * Steps: copy composer.json/.lock to a scratch directory with an empty Composer cache, run one full
 * dry-run update so Composer fetches every package metadata file the solver could need, turn the
 * cache into a static repository (versions below the locked one are dropped, metadata trimmed to
 * what the solver reads), fetch the advisories for every package name from Packagist, record the
 * platform of the build environment, and write an expected.json skeleton listing the findings for a
 * human to complete.
 *
 * Options:
 *   --project=<dir>        project containing composer.json and composer.lock (required)
 *   --name=<fixture>       directory name under tests/Fixture/third-party (required)
 *   --composer=<binary>    Composer executable (default: composer)
 *   --fixture-root=<dir>   default: tests/Fixture/third-party next to this script's parent
 *   --keep-dev-versions    keep dev-* versions in the static repository (default: dropped unless locked)
 *   --as-of=<YYYY-MM-DD>   historical snapshot: drop package versions released and advisories reported after this date
 *   --platform-php=<ver>   PHP version to record in expected.json (default: the project's config.platform.php, else the build PHP)
 *   --history-months=<n>   for packages not in the lock, keep only versions released within n months before as-of (default 30)
 */

declare(strict_types=1);

use Composer\IO\NullIO;
use Composer\MetadataMinifier\MetadataMinifier;
use Composer\Repository\PlatformRepository;
use Composer\Semver\Comparator;
use Composer\Semver\VersionParser;
use Remediate\Engine\Advisory\JsonFileAdvisoryProvider;
use Remediate\Engine\Matching\Matcher;
use Remediate\Engine\Project\ProjectContext;
use Remediate\Engine\Solver\ScratchWorkspace;
use Symfony\Component\Process\Process;

require dirname(__DIR__) . '/vendor/autoload.php';

$options = getopt('', ['project:', 'name:', 'composer::', 'fixture-root::', 'keep-dev-versions', 'as-of::', 'platform-php::', 'history-months::']);
$projectDir = is_string($options['project'] ?? null) ? realpath($options['project']) : false;
$name = is_string($options['name'] ?? null) ? $options['name'] : '';
$composerBinary = is_string($options['composer'] ?? null) ? $options['composer'] : 'composer';
$fixtureRoot = is_string($options['fixture-root'] ?? null) ? $options['fixture-root'] : dirname(__DIR__) . '/tests/Fixture/third-party';
$keepDev = array_key_exists('keep-dev-versions', $options);
$asOf = null;
if (is_string($options['as-of'] ?? null) && $options['as-of'] !== '') {
    $asOf = new DateTimeImmutable($options['as-of'] . ' 23:59:59', new DateTimeZone('UTC'));
}
$platformPhpOption = is_string($options['platform-php'] ?? null) ? $options['platform-php'] : null;
$historyMonths = is_string($options['history-months'] ?? null) ? max(1, (int) $options['history-months']) : 30;
$historyCutoff = ($asOf ?? new DateTimeImmutable('now', new DateTimeZone('UTC')))->modify(sprintf('-%d months', $historyMonths));

if ($projectDir === false || $name === '' || preg_match('{^[a-z0-9][a-z0-9._-]*$}', $name) !== 1) {
    fwrite(STDERR, "usage: build-fixture.php --project=<dir> --name=<fixture-name>\n");
    exit(2);
}
if (!is_file("$projectDir/composer.json") || !is_file("$projectDir/composer.lock")) {
    fwrite(STDERR, "$projectDir must contain composer.json and composer.lock\n");
    exit(2);
}
$fixtureDir = rtrim($fixtureRoot, '/') . '/' . $name;
if (is_dir($fixtureDir)) {
    fwrite(STDERR, "$fixtureDir already exists\n");
    exit(2);
}

$log = static function (string $message): void {
    fwrite(STDERR, $message . "\n");
};

$tmp = sys_get_temp_dir() . '/remediate-build-' . bin2hex(random_bytes(4));
mkdir("$tmp/project", 0700, true);
mkdir("$tmp/home", 0700, true);
$warmJson = json_decode((string) file_get_contents("$projectDir/composer.json"), true, 512, JSON_THROW_ON_ERROR);
if (!is_array($warmJson)) {
    throw new RuntimeException('composer.json is not an object');
}
// path/artifact/vcs repositories cannot be fetched here (and path globs abort Composer when empty);
// their locked packages are copied from the lock file into the static repository instead.
if (isset($warmJson['repositories']) && is_array($warmJson['repositories'])) {
    $kept = [];
    foreach ($warmJson['repositories'] as $key => $repo) {
        if (is_array($repo) && in_array($repo['type'] ?? null, ['path', 'artifact', 'vcs', 'git', 'github', 'gitlab', 'bitbucket', 'svn', 'hg', 'fossil', 'perforce'], true)) {
            continue;
        }
        $kept[$key] = $repo;
    }
    $warmJson['repositories'] = array_is_list($warmJson['repositories']) ? array_values($kept) : $kept;
}
file_put_contents("$tmp/project/composer.json", json_encode($warmJson, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
copy("$projectDir/composer.lock", "$tmp/project/composer.lock");
if (is_file("$projectDir/auth.json")) {
    copy("$projectDir/auth.json", "$tmp/project/auth.json");
}
$env = [
    'COMPOSER_HOME' => "$tmp/home",
    'COMPOSER_CACHE_DIR' => "$tmp/cache",
    'COMPOSER_NO_INTERACTION' => '1',
    'COMPOSER_NO_BLOCKING' => '1',
    'COMPOSER_NO_SECURITY_BLOCKING' => '1',
];

// 1. Warm the cache with a full dry-run update: this fetches metadata for every reachable package.
$log('Fetching package metadata with a full dry-run update…');
$warm = new Process([$composerBinary, 'update', '--dry-run', '--with-all-dependencies', '--no-plugins', '--no-scripts', '--no-audit', '--no-progress', '--no-interaction', '--ignore-platform-reqs'], "$tmp/project", $env, null, 1800.0);
$warm->run(static function (string $type, string $buffer) use ($log): void {
    foreach (explode("\n", trim($buffer)) as $line) {
        if ($line !== '' && preg_match('{^(Loading|Updating|Lock file|Nothing|Your requirements)}', $line) === 1) {
            $log('  ' . $line);
        }
    }
});
if ($warm->getExitCode() !== 0) {
    $log('  (dry-run did not resolve cleanly; metadata fetched so far is still used)');
}

// Second pass with every root constraint widened to "*": fetches metadata for the versions a
// root-constraint-widening candidate could reach (next majors and their new dependencies).
$log('Fetching metadata for widened root constraints…');
mkdir("$tmp/wide", 0700, true);
$wideJson = $warmJson;
foreach (['require', 'require-dev'] as $section) {
    if (isset($wideJson[$section]) && is_array($wideJson[$section])) {
        foreach ($wideJson[$section] as $pkg => $constraint) {
            if (is_string($pkg) && !preg_match('{^(php|hhvm|ext-|lib-|composer)}', $pkg)) {
                $wideJson[$section][$pkg] = '*';
            }
        }
    }
}
file_put_contents("$tmp/wide/composer.json", json_encode($wideJson, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
$wide = new Process([$composerBinary, 'update', '--dry-run', '--no-plugins', '--no-scripts', '--no-audit', '--no-progress', '--no-interaction', '--ignore-platform-reqs'], "$tmp/wide", $env, null, 1800.0);
$wide->run();
if ($wide->getExitCode() !== 0) {
    $log('  (wide dry-run did not resolve cleanly; metadata fetched so far is still used)');
}

// 2. Build the static repository from the cache.
$lockData = json_decode((string) file_get_contents("$tmp/project/composer.lock"), true, 512, JSON_THROW_ON_ERROR);
if (!is_array($lockData)) {
    throw new RuntimeException('composer.lock is not an object');
}
$locked = [];
foreach (['packages', 'packages-dev'] as $section) {
    foreach (is_array($lockData[$section] ?? null) ? $lockData[$section] : [] as $entry) {
        if (is_array($entry) && isset($entry['name'], $entry['version']) && is_string($entry['name']) && is_string($entry['version'])) {
            $locked[strtolower($entry['name'])] = $entry['version'];
        }
    }
}
$versionParser = new VersionParser();
$keepFields = ['name', 'version', 'version_normalized', 'type', 'require', 'replace', 'provide', 'conflict', 'dist', 'default-branch', 'bin'];

$static = [];
$files = glob("$tmp/cache/repo/*/provider-*.json") ?: [];
$log(sprintf('Building static repository from %d cached metadata files…', count($files)));
foreach ($files as $file) {
    $decoded = json_decode((string) file_get_contents($file), true);
    if (!is_array($decoded) || !isset($decoded['packages']) || !is_array($decoded['packages'])) {
        continue;
    }
    $minified = ($decoded['minified'] ?? null) === 'composer/2.0';
    foreach ($decoded['packages'] as $packageName => $versions) {
        if (!is_string($packageName) || !is_array($versions)) {
            continue;
        }
        $packageName = strtolower($packageName);
        if ($minified) {
            /** @var list<array<string, mixed>> $versions */
            $versions = MetadataMinifier::expand(array_values($versions));
        }
        $lockedVersion = $locked[$packageName] ?? null;
        $lockedNormalized = null;
        if ($lockedVersion !== null) {
            try {
                $lockedNormalized = $versionParser->normalize($lockedVersion);
            } catch (UnexpectedValueException) {
                $lockedNormalized = null;
            }
        }
        foreach ($versions as $entry) {
            if (!is_array($entry) || !isset($entry['version']) || !is_string($entry['version'])) {
                continue;
            }
            $version = $entry['version'];
            $normalized = is_string($entry['version_normalized'] ?? null) ? $entry['version_normalized'] : null;
            if ($normalized === null) {
                try {
                    $normalized = $versionParser->normalize($version);
                } catch (UnexpectedValueException) {
                    continue;
                }
            }
            $isDev = str_starts_with($normalized, 'dev-') || str_ends_with($normalized, '-dev') && str_starts_with($normalized, '9999999');
            $isLocked = $lockedNormalized !== null && $normalized === $lockedNormalized;
            if ($isDev && !$isLocked && !$keepDev) {
                continue;
            }
            if (!$isDev && $lockedNormalized !== null && !str_starts_with($lockedNormalized, 'dev-') && Comparator::lessThan($normalized, $lockedNormalized)) {
                continue;
            }
            if (!$isLocked && is_string($entry['time'] ?? null)) {
                try {
                    $released = new DateTimeImmutable($entry['time']);
                    if ($asOf !== null && $released > $asOf) {
                        continue;
                    }
                    if ($lockedNormalized === null && $released < $historyCutoff) {
                        continue; // not in the lock: only recent history is plausible for the solver
                    }
                } catch (Exception) {
                    // unparsable release time: keep the version
                }
            }
            $trimmed = array_intersect_key($entry, array_flip($keepFields));
            $trimmed['name'] = $packageName;
            $trimmed['version_normalized'] = $normalized;
            if (isset($trimmed['dist']) && is_array($trimmed['dist'])) {
                $trimmed['dist'] = array_intersect_key($trimmed['dist'], array_flip(['type', 'url', 'reference']));
            }
            $static[$packageName][$version] = $trimmed;
        }
    }
}
ksort($static);
$missing = array_diff_key($locked, $static);
if ($missing !== []) {
    $log('  locked packages without cached metadata, copied from the lock file as single versions: ' . implode(', ', array_keys($missing)));
    foreach (['packages', 'packages-dev'] as $section) {
        foreach (is_array($lockData[$section] ?? null) ? $lockData[$section] : [] as $entry) {
            if (!is_array($entry) || !isset($entry['name'], $entry['version']) || !is_string($entry['name']) || !is_string($entry['version'])) {
                continue;
            }
            $pname = strtolower($entry['name']);
            if (!isset($missing[$pname])) {
                continue;
            }
            $trimmed = array_intersect_key($entry, array_flip($keepFields));
            $trimmed['name'] = $pname;
            if (!isset($trimmed['version_normalized'])) {
                try {
                    $trimmed['version_normalized'] = $versionParser->normalize($entry['version']);
                } catch (UnexpectedValueException) {
                    continue;
                }
            }
            $static[$pname][$entry['version']] = $trimmed;
        }
    }
    ksort($static);
}

mkdir("$fixtureDir/repo", 0755, true);
$staticJson = json_encode(['packages' => $static], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
$gz = gzencode($staticJson, 9);
if ($gz === false) {
    throw new RuntimeException('gzencode failed');
}
file_put_contents("$fixtureDir/repo/packages.json.gz", $gz);
$versionCount = array_sum(array_map('count', $static));
$log(sprintf('  %d packages, %d versions, %.1f MB uncompressed, %.1f MB gzipped', count($static), $versionCount, strlen($staticJson) / 1048576, strlen($gz) / 1048576));

// 3. Advisories for every package name that can appear in a solve.
$log('Fetching advisories from Packagist…');
$names = array_values(array_unique([...array_keys($static), ...array_keys($locked)]));
$advisories = [];
foreach (array_chunk($names, 400) as $batch) {
    $context = stream_context_create(['http' => [
        'method' => 'POST',
        'header' => "Content-Type: application/x-www-form-urlencoded\r\nUser-Agent: composer-remediate/build-fixture\r\n",
        'content' => http_build_query(['packages' => $batch]),
        'timeout' => 60,
    ]]);
    $response = @file_get_contents('https://packagist.org/api/security-advisories/', false, $context);
    if ($response === false) {
        throw new RuntimeException('Packagist advisory API request failed');
    }
    $decoded = json_decode($response, true, 512, JSON_THROW_ON_ERROR);
    if (is_array($decoded) && isset($decoded['advisories']) && is_array($decoded['advisories'])) {
        foreach ($decoded['advisories'] as $packageName => $list) {
            if (!is_string($packageName) || !is_array($list)) {
                continue;
            }
            if ($asOf !== null) {
                $list = array_values(array_filter($list, static function ($record) use ($asOf): bool {
                    if (!is_array($record) || !is_string($record['reportedAt'] ?? null)) {
                        return true;
                    }
                    try {
                        return new DateTimeImmutable($record['reportedAt'], new DateTimeZone('UTC')) <= $asOf;
                    } catch (Exception) {
                        return true;
                    }
                }));
            }
            if ($list !== []) {
                $advisories[strtolower($packageName)] = array_values($list);
            }
        }
    }
}
ksort($advisories);
file_put_contents("$fixtureDir/advisories.json", json_encode(['advisories' => $advisories], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n");
$log(sprintf('  %d packages with advisories', count($advisories)));

// 4. Platform of the build environment, so fixtures resolve identically on any machine.
$platform = [];
foreach ((new PlatformRepository())->getPackages() as $package) {
    $pname = $package->getName();
    if ($pname === 'php' || str_starts_with($pname, 'ext-')) {
        $platform[$pname] = preg_replace('{^(\d+\.\d+\.\d+).*$}', '$1', $package->getPrettyVersion()) ?? $package->getPrettyVersion();
    }
}
$projectJson = json_decode((string) file_get_contents("$projectDir/composer.json"), true);
$projectPlatform = is_array($projectJson) && is_array($projectJson['config'] ?? null) && is_array($projectJson['config']['platform'] ?? null) ? $projectJson['config']['platform'] : [];
foreach ($projectPlatform as $pname => $pversion) {
    if (is_string($pname) && (is_string($pversion) || $pversion === false)) {
        $platform[strtolower($pname)] = $pversion;
    }
}
if ($platformPhpOption !== null) {
    $platform['php'] = $platformPhpOption;
}
ksort($platform);
$log(sprintf('Platform: php %s plus %d extensions', is_string($platform['php'] ?? null) ? $platform['php'] : '?', count($platform) - 1));

// 5. Copy project files and compute the findings the harness will see.
copy("$projectDir/composer.json", "$fixtureDir/composer.json");
copy("$projectDir/composer.lock", "$fixtureDir/composer.lock");

$workspace = ScratchWorkspace::fromFiles("$fixtureDir/composer.json", "$fixtureDir/composer.lock");
$repoDir = "$tmp/repo";
mkdir($repoDir, 0700, true);
file_put_contents("$repoDir/packages.json", $staticJson);
$workspace->overrideRepositories([['type' => 'composer', 'url' => 'file://' . $repoDir], ['packagist.org' => false]]);
$workspace->overridePlatform($platform);
$scratch = $workspace->materialize();
$context = ProjectContext::fromDirectory($scratch->directory(), new NullIO());
$matcher = new Matcher(new JsonFileAdvisoryProvider("$fixtureDir/advisories.json"));
$findings = $matcher->match($context->lockSnapshot(), static fn (string $n): bool => $context->isRootRequirement($n));
$scratch->destroy();

$expected = [
    'description' => 'TODO: describe the case and the remediation a competent human would choose.',
    'source' => ['project' => basename($projectDir), 'captured_at' => gmdate('c'), 'as_of' => $asOf?->format('Y-m-d'), 'url' => 'TODO', 'commit' => 'TODO'],
    'platform' => $platform,
    'findings' => array_map(static fn ($f): array => [
        'package' => $f->packageName,
        'advisory' => $f->advisory->cve ?? $f->advisory->id,
        'title' => $f->advisory->title,
        'affected' => $f->advisory->affectedVersions->getPrettyString(),
        'direct' => $f->isRootRequirement,
        'dev' => $f->isDev,
        'remediation' => true,
        'command' => 'TODO',
    ], $findings),
];
file_put_contents("$fixtureDir/expected.json", json_encode($expected, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n");
file_put_contents("$fixtureDir/README.md", "# $name\n\nTODO: provenance (source project, URL, commit, date), which advisories are present, and why this\ncase matters. Then fill in `expected.json`.\n\nBuilt with `bin/build-fixture.php` on " . gmdate('Y-m-d') . ".\n");

$log(sprintf('Wrote %s with %d finding(s):', $fixtureDir, count($findings)));
foreach ($findings as $finding) {
    $log(sprintf('  %s on %s %s%s', $finding->advisory->cve ?? $finding->advisory->id, $finding->packageName, $finding->prettyVersion, $finding->isRootRequirement ? ' (direct)' : ''));
}
$log('Now edit expected.json and README.md.');

// cleanup
$rm = static function (string $dir) use (&$rm): void {
    foreach (scandir($dir) ?: [] as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }
        $path = "$dir/$item";
        is_dir($path) && !is_link($path) ? $rm($path) : @unlink($path);
    }
    @rmdir($dir);
};
$rm($tmp);
