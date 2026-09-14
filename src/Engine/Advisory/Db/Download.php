<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db;

use Composer\Downloader\TransportException;
use Composer\Util\HttpDownloader;
use Composer\Util\Loop;

/**
 * Fetching a file to disk, with a failure that stays an exception.
 *
 * `HttpDownloader::copy()` discards the rejected promise before Composer 2.10, which added a handler
 * for exactly this; react/promise then reports the failure on stderr when that promise is collected.
 * Every download here has a failure this tool expects and explains, a publisher that cannot be reached,
 * a mirror without a `latest.json`, a feed that is down during a build, so on Composer 2.4 to 2.9 the
 * tool's own account of the event arrived next to an alarming line about an unhandled rejection.
 * `HttpDownloader::get()` has carried the handler for longer and needs none of this.
 *
 * The asynchronous form gives the rejection somewhere to go. It has to be allowed before the request is
 * queued and driven afterwards, which is what a loop around the downloader does; allowing it takes
 * nothing away from synchronous callers that share the downloader, since the flag only decides whether
 * a non-blocking request is refused.
 */
final class Download
{
    /** @throws TransportException */
    public static function toFile(HttpDownloader $downloader, string $url, string $to): void
    {
        $loop = new Loop($downloader);
        $failure = null;
        $promise = $downloader->addCopy($url, $to);
        $promise->then(null, static function (\Throwable $e) use (&$failure): void {
            $failure = $e;
        });
        $loop->wait([$promise]);
        if ($failure instanceof \Throwable) {
            throw $failure;
        }
    }
}
