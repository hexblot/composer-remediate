<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory;

/**
 * An advisory provider that can keep answering in a forked child process.
 *
 * Planning several findings at once forks the analysing process. A provider holding an operating
 * system resource that must not be carried across a fork (a SQLite connection, a curl handle, a
 * socket) cannot simply be inherited: the child and the parent would share one file offset and one
 * set of locks. Implementing this interface is the provider's statement that it knows what it holds
 * and can re-establish it, and `afterFork()` is where it does so. A provider that does not implement
 * it is never forked: the planner falls back to planning one finding at a time and says why.
 */
interface ForkSafe
{
    /**
     * Called in the child, before anything else, once per fork. Re-establish anything that must not
     * be shared with the parent. Data already read may be kept: it is identical in every child.
     */
    public function afterFork(): void;
}
