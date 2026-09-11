<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db;

use Composer\Config;
use Composer\Factory;

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
     * Whether a configuration value in the merged configuration was set by a composer.json or auth.json
     * outside the operator's home directory, which for a plugin command means the analysed project's own
     * files. Composer records the source of every value: `SOURCE_DEFAULT`, `SOURCE_UNKNOWN` and the
     * `COMPOSER_*` environment variables are the operator's; a file is theirs only when it sits in the
     * home directory the operator's own configuration names. A source that cannot be resolved counts as
     * the project's.
     */
    public function setByProject(Config $merged, string $key): bool
    {
        $source = $merged->getSourceOfValue($key);
        if ($source === Config::SOURCE_DEFAULT || $source === Config::SOURCE_UNKNOWN || str_starts_with($source, 'COMPOSER_')) {
            return false;
        }
        if (!str_ends_with($source, '.json') && !is_file($source)) {
            return false;
        }
        $home = $this->get('home');
        $home = is_string($home) ? realpath($home) : false;
        $directory = realpath(dirname($source));

        return $home === false || $directory === false || ($directory !== $home && !str_starts_with($directory, $home . '/'));
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
