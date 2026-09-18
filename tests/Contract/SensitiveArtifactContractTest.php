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

    public function testABuiltDatabaseIsOwnerOnlyIncludingWhileItIsBeingBuilt(): void
    {
        if (\Composer\Util\Platform::isWindows()) {
            self::markTestSkipped('file modes are a POSIX concept; Windows cannot make a file owner-only this way');
        }
        $previous = umask(0022);
        $directory = sys_get_temp_dir() . '/remediate-contract-' . bin2hex(random_bytes(6));
        mkdir($directory, 0700, true);
        $path = $directory . '/advisories.sqlite';
        try {
            (new DatabaseWriter())->write([], [], $path);

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
}
