<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db;

use Composer\Config;
use Composer\Factory;
use Composer\IO\IOInterface;
use Composer\Util\HttpDownloader;

/**
 * Composer's configuration as the operator gave it: the environment, their global `config.json` and
 * `auth.json`, and Composer's defaults. The analysed project's `composer.json` is never merged into it.
 *
 * A plugin command runs inside the project's Composer instance, whose configuration is the operator's
 * and the project's combined, and a project can set any of it. Only this configuration may decide what
 * counts as the operator's: reading `home` from the merged configuration would let a project that sets
 * `config.home` alongside another setting declare its own files trustworthy.
 */
final class OperatorConfiguration
{
    private ?Config $config = null;

    /** Relative values resolve against a neutral directory, never the project being analysed. */
    public function config(): Config
    {
        return $this->config ??= Factory::createConfig(null, sys_get_temp_dir());
    }

    public function get(string $key): mixed
    {
        return $this->config()->get($key);
    }

    /**
     * A downloader for the files this tool fetches on the operator's behalf: the advisory database and
     * the feeds a build reads. It carries the operator's TLS configuration and credentials, never the
     * analysed project's, so a repository cannot decide which certificates authenticate a publisher the
     * operator chose. Package metadata for candidate solves keeps using the project's configuration,
     * where the project's repositories and their credentials are the point.
     */
    public function httpDownloader(IOInterface $io): HttpDownloader
    {
        return Factory::createHttpDownloader($io, $this->config());
    }

    /**
     * Whether a value in the merged configuration came from anywhere but the operator.
     *
     * Composer records the source of every value. The operator's are its defaults, values a command
     * set, the `COMPOSER_*` environment variables, and exactly two files: the `config.json` and
     * `auth.json` Composer reads from the home directory. Everything else is a file belonging to the
     * analysed project (its `composer.json`, or an `auth.json` beside it), and so is any source that
     * cannot be resolved.
     *
     * The two files are compared by their resolved paths, not by their directory: a checkout that sits
     * below the home directory, which happens when `COMPOSER_HOME` is inside the workspace, must not
     * make the project's own files look like the operator's.
     */
    public function setByProject(Config $merged, string $key): bool
    {
        $source = $merged->getSourceOfValue($key);
        if (in_array($source, [Config::SOURCE_DEFAULT, Config::SOURCE_COMMAND, Config::SOURCE_UNKNOWN], true) || str_starts_with($source, 'COMPOSER_')) {
            return false;
        }

        return !in_array(realpath($source), $this->globalFiles(), true);
    }

    /**
     * The only configuration files that are the operator's: Composer reads these two from the home
     * directory and nothing else into a pristine configuration.
     *
     * @return list<string>
     */
    private function globalFiles(): array
    {
        $home = $this->get('home');
        if (!is_string($home) || $home === '') {
            return [];
        }

        return array_values(array_filter([realpath($home . '/config.json'), realpath($home . '/auth.json')], static fn (string|false $path): bool => $path !== false));
    }

    /**
     * The keys among those given that the analysed project set.
     *
     * @param list<string> $keys
     *
     * @return list<string>
     */
    public function keysSetByProject(Config $merged, array $keys): array
    {
        return array_values(array_filter($keys, fn (string $key): bool => $this->setByProject($merged, $key)));
    }
}
