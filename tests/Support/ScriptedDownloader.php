<?php

declare(strict_types=1);

namespace Remediate\Tests\Support;

use Composer\Config;
use Composer\Downloader\TransportException;
use Composer\IO\NullIO;
use Composer\Util\Http\Response;
use Composer\Util\HttpDownloader;

/**
 * An HTTP layer scripted by URL: each URL answers with a body, or fails with an HTTP status code.
 * Every request is recorded so a test can assert what was (and was not) asked for.
 */
final class ScriptedDownloader extends HttpDownloader
{
    /** @var list<string> */
    private array $requests = [];

    /**
     * @param array<string, string|int> $responses url => body, or an HTTP status code to fail with
     */
    public function __construct(private readonly array $responses)
    {
        parent::__construct(new NullIO(), new Config(false));
    }

    public function get(string $url, array $options = []): Response
    {
        if ($url === '') {
            throw new \InvalidArgumentException('$url must not be an empty string');
        }
        $this->requests[] = $url;

        return new Response(['url' => $url], 200, [], $this->body($url));
    }

    public function copy(string $url, string $to, array $options = []): Response
    {
        if ($url === '') {
            throw new \InvalidArgumentException('$url must not be an empty string');
        }
        $this->requests[] = $url;
        file_put_contents($to, $this->body($url));

        return new Response(['url' => $url], 200, [], null);
    }

    /** @return list<string> every URL requested, in order */
    public function requested(): array
    {
        return $this->requests;
    }

    private function body(string $url): string
    {
        $response = $this->responses[$url] ?? 404;
        if (is_int($response)) {
            throw new TransportException(sprintf('The "%s" file could not be downloaded (%d)', $url, $response), $response);
        }

        return $response;
    }
}
