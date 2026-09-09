<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

// Isolate every test run from the developer's global Composer configuration and cache so that
// fixtures cannot pick up extra repositories, auth or previously cached metadata.
$home = sys_get_temp_dir() . '/composer-remediate-tests-' . getmypid();
@mkdir($home, 0700, true);
putenv('COMPOSER_HOME=' . $home);
putenv('COMPOSER_CACHE_DIR=' . $home . '/cache');
putenv('COMPOSER_NO_INTERACTION=1');
putenv('COMPOSER_DISABLE_XDEBUG_WARN=1');

register_shutdown_function(static function () use ($home): void {
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($home, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($it as $file) {
        $file->isDir() ? @rmdir($file->getPathname()) : @unlink($file->getPathname());
    }
    @rmdir($home);
});
