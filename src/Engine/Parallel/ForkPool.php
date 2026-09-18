<?php

declare(strict_types=1);

namespace Remediate\Engine\Parallel;

/**
 * Runs independent jobs in forked child processes, at most a given number at a time.
 *
 * PHP has no threads, so the only way to use more than one core is more than one process. Forking
 * rather than spawning a fresh interpreter is deliberate: the work being parallelised needs a lock
 * file, a dependency graph, an advisory source and a scratch workspace that the parent has already
 * built, and a fork inherits all of it at no cost and with no second construction path that could
 * drift from the first. Children write nothing but their own result file and never talk to each
 * other, so a job must be independent of every other job in the batch.
 *
 * A result travels back as a serialized value in a temporary file. Anything a job returns must
 * therefore survive `serialize()`: plain values and objects without closures or open resources.
 * Failures travel too, so a child that throws re-throws in the parent rather than vanishing.
 */
final class ForkPool
{
    /**
     * Why this machine cannot fork, or null when it can.
     *
     * Windows has no fork at all, and pcntl is a non-default extension that hosting providers
     * commonly disable, so this is a normal answer rather than an error.
     */
    public static function unavailableReason(): ?string
    {
        foreach (['pcntl_fork', 'pcntl_waitpid', 'pcntl_wifsignaled', 'pcntl_wtermsig', 'posix_kill', 'posix_getpid'] as $function) {
            // Functions disabled through disable_functions still exist; they cannot be called.
            if (!function_exists($function) || in_array($function, self::disabledFunctions(), true)) {
                return sprintf('PHP here cannot fork (%s is unavailable); the ext-pcntl and ext-posix extensions are required, and Windows has no equivalent', $function);
            }
        }

        return null;
    }

    /** @return list<string> */
    private static function disabledFunctions(): array
    {
        $disabled = ini_get('disable_functions');

        return $disabled === false || $disabled === ''
            ? []
            : array_map(static fn (string $name): string => strtolower(trim($name)), explode(',', $disabled));
    }

    /**
     * @param int $workers how many children may run at once; at least one
     */
    public function __construct(private readonly int $workers)
    {
    }

    /**
     * Runs every job, at most `workers` at a time, and returns their results under the original keys.
     *
     * Results come back in the order the jobs were given, whatever order the children finished in, so
     * a parallel run produces exactly what a sequential one would.
     *
     * @template T
     *
     * @param array<int, callable(): T> $jobs
     * @param callable(int, T): void|null $onResult called in the parent as each job's result arrives,
     *                                              in completion order, for progress reporting
     * @param callable(): void|null       $inChild  called in the child before the job, to re-establish
     *                                              anything that must not be shared across a fork
     *
     * @return array<int, T>
     *
     * @throws \RuntimeException when a child could not be started, died without a result, or threw
     */
    public function run(array $jobs, ?callable $onResult = null, ?callable $inChild = null): array
    {
        $results = [];
        $pending = array_keys($jobs);
        /** @var array<int, array{int, string}> $running pid => [job key, result file] */
        $running = [];

        try {
            while ($pending !== [] || $running !== []) {
                while (count($running) < max(1, $this->workers) && $pending !== []) {
                    $key = array_shift($pending);
                    [$pid, $file] = $this->start($jobs[$key], $inChild);
                    $running[$pid] = [$key, $file];
                }

                [$pid, $status] = self::awaitAny(array_keys($running));
                [$key, $file] = $running[$pid];
                unset($running[$pid]);
                $results[$key] = $this->collect($file, $status);
                if ($onResult !== null) {
                    $onResult($key, $results[$key]);
                }
            }
        } finally {
            // Siblings are waited for rather than killed. A worker signalled mid-solve dies without
            // running the solver's own cleanup, leaving its scratch directory behind; letting it
            // finish costs one more solve and leaves nothing. What must not happen is abandoning
            // them, which would leave Composer running long after the run reported a failure.
            foreach ($running as $pid => [, $file]) {
                $ignored = 0;
                pcntl_waitpid($pid, $ignored);
                @unlink($file);
                @unlink($file . '.part');
            }
        }

        // Back into the order the jobs were given, not the order they finished.
        $ordered = [];
        foreach (array_keys($jobs) as $key) {
            $ordered[$key] = $results[$key];
        }

        return $ordered;
    }

    /**
     * Waits until one of these workers has finished, and returns which, with its exit status.
     *
     * Each is waited for by pid rather than with `pcntl_waitpid(-1)`, which returns any child of this
     * process. The process this runs inside is somebody else's: Composer's, another plugin's, a
     * script's, and a child of theirs exiting during this window would be reaped here. That would
     * both look like a worker we do not recognise and take from its real owner the exit status it is
     * waiting for. Polling a handful of pids a few times a second costs nothing against solves that
     * take a third of a second each.
     *
     * @param list<int> $pids
     *
     * @return array{int, int} the pid that finished, and its raw exit status
     */
    private static function awaitAny(array $pids): array
    {
        while (true) {
            foreach ($pids as $pid) {
                $status = 0;
                $finished = pcntl_waitpid($pid, $status, WNOHANG);
                if ($finished === $pid) {
                    return [$pid, $status];
                }
                if ($finished === -1) {
                    // Gone, and its status already taken by someone else. Whether it did the work is
                    // a question for the file it was told to leave, which is where the answer is anyway.
                    return [$pid, 0];
                }
            }
            usleep(20_000);
        }
    }

    /**
     * @param callable(): mixed      $job
     * @param callable(): void|null  $inChild
     *
     * @return array{int, string} the child's pid and the file its result will be in
     */
    private function start(callable $job, ?callable $inChild): array
    {
        $file = tempnam(sys_get_temp_dir(), 'remediate-worker-');
        if ($file === false) {
            throw new \RuntimeException('Cannot create a temporary file for a planning worker.');
        }
        // Only this process needs to read it, and it may describe a project's dependencies.
        @chmod($file, 0600);

        $pid = pcntl_fork();
        if ($pid === -1) {
            @unlink($file);

            throw new \RuntimeException('Cannot fork a planning worker.');
        }
        if ($pid !== 0) {
            return [$pid, $file];
        }

        // In the child from here on. It must never return into the caller's loop: one child continuing
        // the parent's work would run the whole batch again.
        try {
            if ($inChild !== null) {
                $inChild();
            }
            $payload = serialize(['ok' => true, 'value' => $job()]);
        } catch (\Throwable $e) {
            $payload = serialize(['ok' => false, 'class' => get_class($e), 'message' => $e->getMessage()]);
        }
        // A partial file must not read as a result, so it is written beside the target and moved into
        // place, which is atomic on the same filesystem.
        //
        // The payload is a serialized plan: the package names, versions and advisory ids of a project
        // that is probably private. It is created owner-only rather than created and then chmodded,
        // because between those two steps anyone on the machine can read it, and because the rename
        // carries the new file's permissions over the protected one it replaces.
        $umask = umask(0077);
        $written = @file_put_contents($file . '.part', $payload);
        umask($umask);
        if ($written !== strlen($payload) || !@rename($file . '.part', $file)) {
            @unlink($file . '.part');
        }
        self::stop();
    }

    /**
     * Ends the child without running anything the parent registered for its own exit.
     *
     * A fork inherits every shutdown function and every destructor, and the process this runs inside
     * is somebody else's: Composer's, a test harness's, another plugin's. Left to exit normally a
     * child would run their cleanup as if the whole run were over, and cleanup means deleting things
     * the parent is still using. So the child's result is a file it has already written, and the
     * child itself is stopped outright. The parent reads the file and never looks at the exit status
     * of a child that left one.
     */
    private static function stop(): never
    {
        posix_kill(posix_getpid(), SIGKILL);
        // Not reached; SIGKILL cannot be caught, blocked or ignored.
        exit(0);
    }

    /**
     * Reads one child's result, or explains what happened to it instead.
     */
    private function collect(string $file, int $status): mixed
    {
        try {
            $raw = is_file($file) ? @file_get_contents($file) : false;
        } finally {
            @unlink($file);
            // The child writes beside the target and renames into place. One killed between the two
            // leaves the half-written file behind, and that is the documented failure mode: the
            // out-of-memory killer on a large lock file. Nothing else ever sweeps it up.
            @unlink($file . '.part');
        }

        // The result is the file, not the exit status: a worker stops itself with a signal on purpose,
        // so how it died says nothing about whether it finished the work.
        $decoded = $raw === false || $raw === '' ? null : @unserialize($raw);
        if (!is_array($decoded) || !isset($decoded['ok'])) {
            $signal = pcntl_wifsignaled($status) ? pcntl_wtermsig($status) : null;
            throw new \RuntimeException($signal !== null && $signal !== SIGKILL
                ? sprintf('A planning worker was killed by signal %d before it left a result. On a large lock file this is usually the out-of-memory killer; use fewer workers.', $signal)
                : 'A planning worker stopped without leaving a result. On a large lock file this is usually the out-of-memory killer; use fewer workers.');
        }
        if ($decoded['ok'] !== true) {
            throw new \RuntimeException(sprintf('A planning worker failed: %s: %s', is_string($decoded['class'] ?? null) ? $decoded['class'] : 'error', is_string($decoded['message'] ?? null) ? $decoded['message'] : ''));
        }

        return $decoded['value'];
    }
}
