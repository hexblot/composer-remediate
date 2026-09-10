<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

// Isolate every test run from the developer's global Composer configuration and cache so that
// fixtures cannot pick up extra repositories, auth or previously cached metadata. Composer reads
// $_SERVER before getenv(), so a plain putenv() would lose against a COMPOSER_CACHE_DIR exported by
// the environment (DDEV does that); Platform::putEnv() sets both.
$home = sys_get_temp_dir() . '/composer-remediate-tests-' . getmypid();
@mkdir($home, 0700, true);
\Composer\Util\Platform::putEnv('COMPOSER_HOME', $home);
\Composer\Util\Platform::putEnv('COMPOSER_CACHE_DIR', $home . '/cache');
\Composer\Util\Platform::putEnv('COMPOSER_NO_INTERACTION', '1');
\Composer\Util\Platform::putEnv('COMPOSER_DISABLE_XDEBUG_WARN', '1');
// By default the plugin keeps a shared advisory database current from this project's GitHub release.
// Tests never reach the network for that: the source is the configured repositories unless a test says otherwise.
\Composer\Util\Platform::putEnv('REMEDIATE_DATABASE', 'composer');

register_shutdown_function(static function () use ($home): void {
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($home, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($it as $file) {
        $file->isDir() ? @rmdir($file->getPathname()) : @unlink($file->getPathname());
    }
    @rmdir($home);
});
