<?php

/**
 * A minimal HTTPS file server for tests: serves one directory over TLS on an ephemeral loopback port,
 * GET and HEAD only, one request per connection. Prints "PORT <n>" on stdout once listening and
 * appends one line per request to <docroot>/.requests so a test can assert what was asked for.
 *
 * Usage: php tls-server.php <docroot> <certificate.pem> <key.pem>
 */

declare(strict_types=1);

$arguments = is_array($_SERVER['argv'] ?? null) ? $_SERVER['argv'] : [];
[, $docroot, $cert, $key] = $arguments + [null, null, null, null];
if (!is_string($docroot) || !is_dir($docroot) || !is_string($cert) || !is_string($key)) {
    fwrite(STDERR, "usage: tls-server.php <docroot> <cert.pem> <key.pem>\n");
    exit(2);
}
$context = stream_context_create(['ssl' => ['local_cert' => $cert, 'local_pk' => $key, 'allow_self_signed' => true, 'verify_peer' => false]]);
$server = stream_socket_server('tls://127.0.0.1:0', $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
if ($server === false) {
    fwrite(STDERR, "cannot listen: $errstr ($errno)\n");
    exit(1);
}
$name = stream_socket_get_name($server, false);
echo 'PORT ', substr((string) $name, strrpos((string) $name, ':') + 1), "\n";
flush();

$root = realpath($docroot);
while (true) {
    $client = @stream_socket_accept($server, 1.0);
    if ($client === false) {
        // Exit when the parent went away (stdin closed): no orphaned servers after a test run.
        if (feof(STDIN)) {
            exit(0);
        }
        continue;
    }
    stream_set_timeout($client, 5);
    $request = '';
    while (!str_contains($request, "\r\n\r\n")) {
        $chunk = fread($client, 8192);
        if ($chunk === false || $chunk === '') {
            break;
        }
        $request .= $chunk;
    }
    $line = strtok($request, "\r\n");
    $parts = $line === false ? [] : explode(' ', $line);
    $method = $parts[0] ?? '';
    $target = parse_url($parts[1] ?? '/', PHP_URL_PATH);
    $target = is_string($target) ? $target : '/';
    @file_put_contents($docroot . '/.requests', $method . ' ' . $target . "\n", FILE_APPEND);
    $file = realpath($docroot . $target);
    $respond = static function (string $status, string $body, bool $head) use ($client): void {
        fwrite($client, "HTTP/1.1 $status\r\nContent-Type: application/octet-stream\r\nContent-Length: " . strlen($body) . "\r\nConnection: close\r\n\r\n" . ($head ? '' : $body));
    };
    if (!in_array($method, ['GET', 'HEAD'], true)) {
        $respond('405 Method Not Allowed', 'method not allowed', false);
    } elseif ($file === false || $root === false || !str_starts_with($file, $root . '/') || !is_file($file) || basename($file) === '.requests') {
        $respond('404 Not Found', 'not found', $method === 'HEAD');
    } else {
        $respond('200 OK', (string) file_get_contents($file), $method === 'HEAD');
    }
    fclose($client);
}
