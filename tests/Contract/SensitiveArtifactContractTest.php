<?php

declare(strict_types=1);

namespace Remediate\Tests\Contract;

use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\Db\DatabaseWriter;
use Remediate\Engine\Parallel\ForkPool;

/**
 * Invariant: a file this tool writes into a directory other people can reach is readable by its owner
 * and nobody else, from the moment it exists until it is gone.
 *
 * What these files hold is the shape of somebody's private project: package names, versions, the
 * advisories that affect them, and in a build with `--include` advisories the operator has not
 * published. The temporary directory is shared with every other account on the machine.
 *
 * "From the moment it exists" is the part that needs stating. Creating a file and then tightening it
 * leaves a window in which it is readable, and on a rename the permissions that survive are the ones
 * the new file was created with, not the ones the file it replaced had. So the check is applied at
 * every state a file passes through, not only the last one.
 */
final class SensitiveArtifactContractTest extends TestCase
{
    public function testAWorkerPayloadIsOwnerOnlyAtEveryStateItPassesThrough(): void
    {
        if (ForkPool::unavailableReason() !== null) {
            self::markTestSkipped((string) ForkPool::unavailableReason());
        }
        // A umask that would make anything created carelessly world-readable.
        $previous = umask(0022);
        try {
            $pool = new ForkPool(1);
            $start = new \ReflectionMethod($pool, 'start');
            /** @var array{int, string} $started */
            $started = $start->invoke($pool, static fn (): array => ['advisory' => 'a private project detail'], null);
            [$pid, $file] = $started;
            $status = 0;
            pcntl_waitpid($pid, $status);

            clearstatcache();
            self::assertFileExists($file);
            self::assertSame(0600, fileperms($file) & 0777, 'the payload the worker left is readable by other accounts on this machine');
            self::assertFileDoesNotExist($file . '.part', 'the file it was written as must not outlive the rename');

            $collect = new \ReflectionMethod($pool, 'collect');
            self::assertSame(['advisory' => 'a private project detail'], $collect->invoke($pool, $file, $status));
            self::assertFileDoesNotExist($file, 'a payload that has been read is not left lying about');
        } finally {
            umask($previous);
        }
    }

    public function testAWorkerPayloadIsNeverObservablePermissiveWhileItIsBeingWritten(): void
    {
        if (ForkPool::unavailableReason() !== null) {
            self::markTestSkipped((string) ForkPool::unavailableReason());
        }
        // Checking the file after the worker has finished says nothing about how it got there. A file
        // created readable and tightened afterwards ends up looking identical, and anyone on the
        // machine could have read it in between. So this watches while the write is happening.
        //
        // The payload is large enough that writing it is not instantaneous, and the parent samples the
        // file as fast as it can for as long as the worker runs. Every sample has to be owner-only.
        $previous = umask(0022);
        try {
            $pool = new ForkPool(1);
            $start = new \ReflectionMethod($pool, 'start');
            /** @var array{int, string} $started */
            $started = $start->invoke($pool, static fn (): string => str_repeat('a private project detail. ', 2_000_000), null);
            [$pid, $file] = $started;

            $samples = [];
            while (pcntl_waitpid($pid, $status, WNOHANG) === 0) {
                foreach ([$file . '.part', $file] as $candidate) {
                    clearstatcache(true, $candidate);
                    $mode = @fileperms($candidate);
                    if ($mode !== false) {
                        $samples[$candidate][] = $mode & 0777;
                    }
                }
            }

            self::assertNotSame([], $samples, 'nothing was sampled, so this proves nothing; the payload needs to take longer to write');
            foreach ($samples as $candidate => $modes) {
                foreach (array_unique($modes) as $mode) {
                    self::assertSame(
                        0600,
                        $mode,
                        sprintf('%s was %04o at some point while the worker was writing it, so another account could have read it then', basename($candidate), $mode),
                    );
                }
            }

            $collect = new \ReflectionMethod($pool, 'collect');
            self::assertIsString($collect->invoke($pool, $file, $status));
        } finally {
            umask($previous);
        }
    }

    public function testABuiltDatabaseIsOwnerOnlyIncludingWhileItIsBeingBuilt(): void
    {
        if (\Composer\Util\Platform::isWindows()) {
            self::markTestSkipped('file modes are a POSIX concept; Windows cannot make a file owner-only this way');
        }
        if (ForkPool::unavailableReason() !== null) {
            self::markTestSkipped('watching a build as it happens needs a second process: ' . ForkPool::unavailableReason());
        }
        $previous = umask(0022);
        $directory = sys_get_temp_dir() . '/remediate-contract-' . bin2hex(random_bytes(6));
        mkdir($directory, 0700, true);
        $path = $directory . '/advisories.sqlite';
        try {
            // A database is built beside its final path over many inserts, so there is a long moment
            // in which the file exists and is not finished. It is watched throughout rather than
            // inspected at the end, for the same reason as the worker payload: a file created
            // readable and tightened afterwards ends up indistinguishable from one that never was.
            $pid = pcntl_fork();
            self::assertNotSame(-1, $pid, 'could not start the process that does the building');
            if ($pid === 0) {
                (new DatabaseWriter())->write(self::manyAdvisories(400), [], $path);
                posix_kill(posix_getpid(), SIGKILL);
            }

            $samples = [];
            while (pcntl_waitpid($pid, $status, WNOHANG) === 0) {
                foreach (glob($directory . '/*') ?: [] as $candidate) {
                    clearstatcache(true, $candidate);
                    $mode = @fileperms($candidate);
                    if ($mode !== false) {
                        $samples[basename($candidate)][] = $mode & 0777;
                    }
                }
            }

            self::assertNotSame([], $samples, 'nothing was sampled, so this proves nothing');
            foreach ($samples as $name => $modes) {
                foreach (array_unique($modes) as $mode) {
                    self::assertSame(0600, $mode, sprintf('%s was %04o while the database was being built, so another account could have read it then', $name, $mode));
                }
            }

            clearstatcache();
            self::assertSame(0600, fileperms($path) & 0777, 'a database can carry advisories the operator has not published');
            self::assertSame([], glob($directory . '/*.tmp-*') ?: [], 'the file it was built as must not outlive the rename');
        } finally {
            umask($previous);
            foreach (glob($directory . '/*') ?: [] as $file) {
                @unlink($file);
            }
            @rmdir($directory);
        }
    }

    /** @return list<\Remediate\Engine\Advisory\Db\NormalizedAdvisory> */
    private static function manyAdvisories(int $count): array
    {
        $advisories = [];
        for ($i = 0; $i < $count; ++$i) {
            $id = sprintf('CVE-2026-%04d', $i);
            $advisories[] = new \Remediate\Engine\Advisory\Db\NormalizedAdvisory(
                $id,
                [$id],
                'Synthetic',
                null,
                'high',
                null,
                null,
                [new \Remediate\Engine\Advisory\Db\AffectedRange('acme/lib' . $i, '<2.0.0', 'contract')],
                [new \Remediate\Engine\Advisory\Db\SourceRecord('contract', $id)],
            );
        }

        return $advisories;
    }
}
