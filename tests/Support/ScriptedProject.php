<?php

declare(strict_types=1);

namespace Remediate\Tests\Support;

use Composer\IO\NullIO;
use Composer\Package\Package;
use Remediate\Engine\Advisory\Advisory;
use Remediate\Engine\Advisory\AdvisoryProvider;
use Remediate\Engine\Lock\LockSnapshot;
use Remediate\Engine\Project\ProjectContext;
use Remediate\Engine\Solver\ScratchWorkspace;

/**
 * A throwaway project on disk (composer.json + composer.lock) for planner tests that use a
 * FakeSolver, plus helpers to build lock snapshots and advisory providers without Composer running.
 */
final class ScriptedProject
{
    public readonly string $directory;

    /**
     * @param array<string, string>                                      $require  root requirements
     * @param list<array{string, string, 2?: bool, 3?: string|null}>     $packages [name, version, dev?, releaseDate?]
     * @param array<string, string>                                      $requireDev
     */
    public function __construct(array $require, array $packages, array $requireDev = [])
    {
        $this->directory = sys_get_temp_dir() . '/composer-remediate-scripted-' . bin2hex(random_bytes(5));
        mkdir($this->directory, 0700, true);
        $json = ['name' => 'test/project', 'require' => $require, 'minimum-stability' => 'stable', 'config' => ['platform' => ['php' => '8.3.0']]];
        if ($requireDev !== []) {
            $json['require-dev'] = $requireDev;
        }
        file_put_contents($this->directory . '/composer.json', json_encode($json, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));
        $prod = [];
        $dev = [];
        foreach ($packages as $spec) {
            $entry = ['name' => $spec[0], 'version' => $spec[1], 'type' => 'library', 'require' => []];
            if ($spec[2] ?? false) {
                $dev[] = $entry;
            } else {
                $prod[] = $entry;
            }
        }
        $lock = [
            '_readme' => ['scripted'],
            'content-hash' => md5((string) file_get_contents($this->directory . '/composer.json')),
            'packages' => $prod,
            'packages-dev' => $dev,
            'aliases' => [],
            'minimum-stability' => 'stable',
            'stability-flags' => [],
            'prefer-stable' => false,
            'prefer-lowest' => false,
            'platform' => [],
            'platform-dev' => [],
            'plugin-api-version' => '2.6.0',
        ];
        file_put_contents($this->directory . '/composer.lock', json_encode($lock, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));
    }

    public function context(): ProjectContext
    {
        return ProjectContext::fromDirectory($this->directory, new NullIO());
    }

    public function workspace(): ScratchWorkspace
    {
        return ScratchWorkspace::fromFiles($this->directory . '/composer.json', $this->directory . '/composer.lock');
    }

    public function destroy(): void
    {
        @unlink($this->directory . '/composer.json');
        @unlink($this->directory . '/composer.lock');
        @rmdir($this->directory);
    }

    /**
     * @param list<array{string, string, 2?: bool, 3?: string|null}> $packages [name, prettyVersion, dev?, releaseDate?]
     */
    public static function lock(array $packages): LockSnapshot
    {
        $prod = [];
        $dev = [];
        foreach ($packages as $spec) {
            [$name, $pretty] = $spec;
            $package = new Package($name, self::normalize($pretty), $pretty);
            if (array_key_exists(3, $spec) && $spec[3] !== null) {
                $package->setReleaseDate(new \DateTime($spec[3], new \DateTimeZone('UTC')));
            }
            if ($spec[2] ?? false) {
                $dev[] = $package;
            } else {
                $prod[] = $package;
            }
        }

        return LockSnapshot::fromPackages($prod, $dev);
    }

    public static function normalize(string $pretty): string
    {
        return (new \Composer\Semver\VersionParser())->normalize($pretty);
    }

    /**
     * @param list<Advisory> $advisories
     */
    public static function advisories(array $advisories, bool $complete = true): AdvisoryProvider
    {
        $byPackage = [];
        foreach ($advisories as $advisory) {
            $byPackage[$advisory->packageName][] = $advisory;
        }

        return new class($byPackage, $complete) implements AdvisoryProvider {
            /** @param array<string, list<Advisory>> $advisories */
            public function __construct(private readonly array $advisories, private readonly bool $complete)
            {
            }

            public function advisoriesFor(array $packageNames): array
            {
                return array_intersect_key($this->advisories, array_flip(array_map('strtolower', $packageNames)));
            }

            public function describe(): string
            {
                return 'scripted advisories';
            }

            public function isComplete(): bool
            {
                return $this->complete;
            }
        };
    }

    public static function advisory(string $id, string $package, string $affected, ?string $severity = 'high', ?string $cve = null): Advisory
    {
        return new Advisory($id, $package, (new \Composer\Semver\VersionParser())->parseConstraints($affected), 'title ' . $id, $cve, 'https://example.test/' . $id, $severity);
    }
}
