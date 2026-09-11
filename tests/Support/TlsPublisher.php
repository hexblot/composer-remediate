<?php

declare(strict_types=1);

namespace Remediate\Tests\Support;

/**
 * A publisher of advisory databases for end-to-end tests: a real HTTPS server (tests/Support/tls-server.php,
 * a PHP TLS stream server) with a certificate generated for 127.0.0.1 at start-up. Composer's curl layer
 * trusts it through the `cafile` setting, so the plugin's production code path (https-only sources,
 * latest.json and sidecar verification, downloads through HttpDownloader) is exercised unchanged.
 */
final class TlsPublisher
{
    private string $docroot;
    private string $certificate;
    private string $key;
    /** @var resource|null */
    private $process;
    private int $port = 0;

    public function __construct()
    {
        $this->docroot = sys_get_temp_dir() . '/composer-remediate-publisher-' . bin2hex(random_bytes(4));
        mkdir($this->docroot, 0700, true);
        $this->certificate = $this->docroot . '/../' . basename($this->docroot) . '.crt.pem';
        $this->key = $this->docroot . '/../' . basename($this->docroot) . '.key.pem';
        self::generateCertificate($this->certificate, $this->key);
        $this->start();
    }

    /** The certificate file to pass as Composer's `cafile`. */
    public function certificate(): string
    {
        return $this->certificate;
    }

    public function url(string $file): string
    {
        return sprintf('https://127.0.0.1:%d/%s', $this->port, ltrim($file, '/'));
    }

    public function docroot(): string
    {
        return $this->docroot;
    }

    /** Puts a file on the server. */
    public function publish(string $name, string $bytes): void
    {
        file_put_contents($this->docroot . '/' . $name, $bytes);
    }

    public function unpublish(string $name): void
    {
        @unlink($this->docroot . '/' . $name);
    }

    /**
     * Publishes an advisory database the way the project's release workflow does: the file, its
     * sha256sum sidecar and a latest.json with sha256, dataset_hash and published_at.
     *
     * @return string the database URL
     */
    public function publishDatabase(string $databaseFile, string $name = 'advisories.sqlite', bool $withLatestJson = true, bool $withSidecar = true): string
    {
        $bytes = (string) file_get_contents($databaseFile);
        $statement = (new \PDO('sqlite:' . $databaseFile))->query('SELECT key, value FROM meta');
        $meta = $statement === false ? [] : $statement->fetchAll(\PDO::FETCH_KEY_PAIR);
        $this->publish($name, $bytes);
        $this->unpublish($name . '.sha256');
        $this->unpublish('latest.json');
        if ($withSidecar) {
            $this->publish($name . '.sha256', hash('sha256', $bytes) . '  ' . $name . "\n");
        }
        if ($withLatestJson) {
            $this->publish('latest.json', json_encode(['sha256' => hash('sha256', $bytes), 'dataset_hash' => $meta['dataset_hash'] ?? '', 'published_at' => $meta['built_at'] ?? gmdate(DATE_ATOM), 'database' => $name], JSON_THROW_ON_ERROR));
        }

        return $this->url($name);
    }

    /** @return list<string> every request the server saw, as "METHOD /path", in order */
    public function requests(): array
    {
        $log = @file_get_contents($this->docroot . '/.requests');

        return $log === false || $log === '' ? [] : explode("\n", rtrim($log, "\n"));
    }

    public function clearRequests(): void
    {
        @unlink($this->docroot . '/.requests');
    }

    /** Stops the server; URLs then refuse connections, which is how a test simulates an outage. */
    public function stop(): void
    {
        if ($this->process !== null) {
            proc_terminate($this->process);
            proc_close($this->process);
            $this->process = null;
        }
    }

    public function destroy(): void
    {
        $this->stop();
        foreach (glob($this->docroot . '/{,.}*', GLOB_BRACE) ?: [] as $file) {
            if (is_file($file)) {
                @unlink($file);
            }
        }
        @rmdir($this->docroot);
        @unlink($this->certificate);
        @unlink($this->key);
    }

    private function start(): void
    {
        $descriptors = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $process = proc_open([PHP_BINARY, __DIR__ . '/tls-server.php', $this->docroot, $this->certificate, $this->key], $descriptors, $pipes);
        if ($process === false) {
            throw new \RuntimeException('cannot start the TLS test server');
        }
        $this->process = $process;
        $line = fgets($pipes[1]);
        if ($line === false || preg_match('{^PORT (\d+)}', $line, $m) !== 1) {
            $error = stream_get_contents($pipes[2]);
            throw new \RuntimeException('the TLS test server did not report a port: ' . $error);
        }
        $this->port = (int) $m[1];
        // stdin stays open (the server exits when it closes); stdout/stderr are not read further.
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
    }

    private static function generateCertificate(string $certificateFile, string $keyFile): void
    {
        $config = tempnam(sys_get_temp_dir(), 'remediate-openssl-');
        if ($config === false) {
            throw new \RuntimeException('cannot create the openssl config');
        }
        file_put_contents($config, "[req]\ndistinguished_name = dn\nx509_extensions = v3\n[dn]\n[v3]\nsubjectAltName = IP:127.0.0.1\nbasicConstraints = CA:TRUE\n");
        $args = ['config' => $config, 'digest_alg' => 'sha256', 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA, 'x509_extensions' => 'v3'];
        $key = openssl_pkey_new($args);
        if ($key === false) {
            throw new \RuntimeException('cannot generate a key: ' . (string) openssl_error_string());
        }
        $csr = openssl_csr_new(['CN' => '127.0.0.1', 'O' => 'composer-remediate tests'], $key, $args);
        if (!$csr instanceof \OpenSSLCertificateSigningRequest) {
            throw new \RuntimeException('cannot create a CSR: ' . (string) openssl_error_string());
        }
        $cert = openssl_csr_sign($csr, null, $key, 1, $args);
        if ($cert === false) {
            throw new \RuntimeException('cannot self-sign: ' . (string) openssl_error_string());
        }
        openssl_x509_export_to_file($cert, $certificateFile);
        openssl_pkey_export_to_file($key, $keyFile);
        @unlink($config);
    }
}
