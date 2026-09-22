<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db;

use Composer\Semver\Constraint\ConstraintInterface;
use Composer\Semver\Constraint\MultiConstraint;
use Remediate\Engine\Advisory\Advisory;
use Remediate\Engine\Advisory\AdvisoryLookupFailed;
use Remediate\Engine\Advisory\PackagistAdvisoryJsonParser;

/**
 * Read-only access to an advisory database file produced by DatabaseWriter.
 */
final class Database
{
    public const SCHEMA_VERSION = 1;

    /**
     * The digest of the bytes this connection was opened against. Recorded once, and required to still
     * hold every time the connection is reopened — see reconnect().
     *
     * It is a digest of the file and not anything the file says about itself. The first version of this
     * check compared schema_version, dataset_hash and built_at, which are rows inside the database:
     * a replacement that kept those three and dropped every advisory passed it, and the worker read a
     * lock as clean against a database with nothing in it. Whoever can replace the file can write the
     * fields it is judged by, so the only thing worth comparing is the content itself.
     */
    private ?string $digest = null;

    private function __construct(private \PDO $pdo, public readonly string $path)
    {
    }

    /** The digest of the file behind this connection, or null when it cannot be read. */
    private function digestOf(): ?string
    {
        clearstatcache(true, $this->path);
        $digest = @hash_file('sha256', $this->path);

        return $digest === false ? null : $digest;
    }

    /**
     * @param string|null $expectedDigest the sha256 the caller established for this file, when it
     *                                    established one. Given, it is required here and at every
     *                                    reopen; absent, whatever is read now is pinned for the rest
     *                                    of the run. Opening is the first read, so it is the first
     *                                    place the file can be something other than what was verified.
     */
    public static function open(string $path, ?string $expectedDigest = null): self
    {
        if (!is_file($path)) {
            throw new AdvisoryLookupFailed(sprintf('Advisory database %s does not exist.', $path));
        }
        $db = new self(self::connect($path), $path);
        $actual = $db->digestOf();
        if ($expectedDigest !== null && ($actual === null || !hash_equals($expectedDigest, $actual))) {
            throw new AdvisoryLookupFailed(sprintf(
                'The advisory database at %s is not the file that was verified for this run (sha256 %s, now %s).',
                $path,
                substr($expectedDigest, 0, 12),
                $actual === null ? 'unreadable' : substr($actual, 0, 12),
            ));
        }
        $db->digest = $expectedDigest ?? $actual;
        $schema = (int) ($db->meta()['schema_version'] ?? 0);
        if ($schema !== self::SCHEMA_VERSION) {
            throw new AdvisoryLookupFailed(sprintf('Advisory database %s has schema version %d; this version of the tool reads %d.', $path, $schema, self::SCHEMA_VERSION));
        }

        return $db;
    }

    /**
     * Opens a fresh read-only connection to the file.
     */
    private static function connect(string $path): \PDO
    {
        if (!extension_loaded('pdo_sqlite')) {
            throw new AdvisoryLookupFailed('The pdo_sqlite PHP extension is required to read an advisory database.');
        }
        try {
            // PHP 8.5 moved the SQLite driver constants to Pdo\Sqlite; older versions only have the PDO ones.
            $openFlags = class_exists(\Pdo\Sqlite::class) ? \Pdo\Sqlite::ATTR_OPEN_FLAGS : \PDO::SQLITE_ATTR_OPEN_FLAGS;
            $readOnly = class_exists(\Pdo\Sqlite::class) ? \Pdo\Sqlite::OPEN_READONLY : \PDO::SQLITE_OPEN_READONLY;

            return new \PDO('sqlite:' . $path, null, null, [
                \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
                $openFlags => $readOnly,
            ]);
        } catch (\PDOException $e) {
            throw new AdvisoryLookupFailed(sprintf('Cannot open advisory database %s: %s', $path, $e->getMessage()), 0, $e);
        }
    }

    /**
     * Drops the inherited connection and opens its own. A SQLite connection must not be carried
     * across a fork: parent and child would share one file offset and one set of POSIX locks, and
     * closing it in either releases it for both. Called in the child, before it reads anything.
     *
     * Eighth adversarial review, finding 4. Reopening named the path, and a path is not a file. A cache
     * refresh landing between the run's verification and this call — a concurrent process, or this
     * tool's own download — put a different database there, and the child read it as if it were the one
     * checked for this run. Because the answers already fetched survive the fork, one run could also
     * mix records from two databases. What was verified was a set of bytes, so reopening has to arrive
     * at the same ones: the file's own identity is required to be what it was, and a child that finds
     * anything else refuses rather than answering from a database nobody vouched for.
     */
    public function reconnect(): void
    {
        $this->pdo = self::connect($this->path);
        $now = $this->digestOf();
        if ($this->digest !== null && ($now === null || !hash_equals($this->digest, $now))) {
            throw new AdvisoryLookupFailed(sprintf(
                'The advisory database at %s is not the file this run verified (sha256 %s, now %s). Nothing was read from it; run again.',
                $this->path,
                substr($this->digest, 0, 12),
                $now === null ? 'unreadable' : substr($now, 0, 12),
            ));
        }
    }

    /** @return array<string, string> */
    public function meta(): array
    {
        try {
            $rows = $this->query('SELECT key, value FROM meta')->fetchAll(\PDO::FETCH_KEY_PAIR);
        } catch (\PDOException $e) {
            throw new AdvisoryLookupFailed(sprintf('%s is not an advisory database: %s', $this->path, $e->getMessage()), 0, $e);
        }
        $meta = [];
        foreach ($rows as $key => $value) {
            $meta[(string) $key] = is_scalar($value) ? (string) $value : '';
        }

        return $meta;
    }

    public function advisoryCount(): int
    {
        return (int) $this->query('SELECT COUNT(*) FROM advisory')->fetchColumn();
    }

    /** Databases built before coverage gaps were recorded have no gap table. */
    public function tracksGaps(): bool
    {
        return (int) $this->query("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'gap'")->fetchColumn() === 1;
    }

    public function gapCount(): int
    {
        return $this->tracksGaps() ? (int) $this->query('SELECT COUNT(*) FROM gap')->fetchColumn() : 0;
    }

    /** Databases built before EPSS / KEV enrichment have no exploit table. */
    public function tracksExploits(): bool
    {
        return (int) $this->query("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'exploit'")->fetchColumn() === 1;
    }

    public function exploitCount(): int
    {
        return $this->tracksExploits() ? (int) $this->query('SELECT COUNT(*) FROM exploit')->fetchColumn() : 0;
    }

    /**
     * Exploit data for the given CVEs (upper-cased keys); CVEs without a row are absent.
     *
     * @param list<string> $cves
     *
     * @return array<string, Enrichment\ExploitRecord>
     */
    public function exploitsFor(array $cves): array
    {
        $cves = array_values(array_unique(array_map('strtoupper', $cves)));
        if ($cves === [] || !$this->tracksExploits()) {
            return [];
        }
        $records = [];
        foreach (array_chunk($cves, 400) as $chunk) {
            $placeholders = implode(',', array_fill(0, count($chunk), '?'));
            $statement = $this->pdo->prepare("SELECT cve, epss, epss_percentile, kev_added, kev_ransomware FROM exploit WHERE cve IN ($placeholders)");
            $statement->execute($chunk);
            foreach ($statement->fetchAll(\PDO::FETCH_ASSOC) as $row) {
                /** @var array{cve: string, epss: mixed, epss_percentile: mixed, kev_added: ?string, kev_ransomware: mixed} $row */
                $records[$row['cve']] = new Enrichment\ExploitRecord(
                    $row['cve'],
                    is_numeric($row['epss']) ? (float) $row['epss'] : null,
                    is_numeric($row['epss_percentile']) ? (float) $row['epss_percentile'] : null,
                    is_string($row['kev_added']) && $row['kev_added'] !== '' ? new \DateTimeImmutable($row['kev_added'], new \DateTimeZone('UTC')) : null,
                    (int) $row['kev_ransomware'] === 1,
                );
            }
        }

        return $records;
    }

    /**
     * Upstream records about the given packages that the build could not interpret, plus every record it
     * could not attribute to a package at all.
     *
     * @param list<string>|null $packageNames null for every gap
     *
     * @return list<CoverageGap>
     */
    public function gapsFor(?array $packageNames, int $limit = 1000): array
    {
        if (!$this->tracksGaps()) {
            return [];
        }
        $gaps = [];
        if ($packageNames === null) {
            $statement = $this->pdo->prepare('SELECT source, remote_id, package, reason, raw FROM gap ORDER BY package, source, remote_id LIMIT ?');
            $statement->execute([$limit]);
            $this->collectGaps($statement, $gaps);

            return $gaps;
        }
        foreach (array_chunk(array_values(array_unique(array_map('strtolower', $packageNames))), 400) as $chunk) {
            $placeholders = implode(',', array_fill(0, count($chunk), '?'));
            $statement = $this->pdo->prepare("SELECT source, remote_id, package, reason, raw FROM gap WHERE package IN ($placeholders) ORDER BY package, source, remote_id");
            $statement->execute($chunk);
            $this->collectGaps($statement, $gaps);
        }
        // Records the build could not attribute to any package may concern any of them: they are part
        // of every answer, so uncertainty the build recorded is never filtered away by the question.
        $statement = $this->pdo->prepare('SELECT source, remote_id, package, reason, raw FROM gap WHERE package IS NULL ORDER BY source, remote_id LIMIT ?');
        $statement->execute([$limit]);
        $this->collectGaps($statement, $gaps);

        return $gaps;
    }

    /** @param list<CoverageGap> $gaps */
    private function collectGaps(\PDOStatement $statement, array &$gaps): void
    {
        foreach ($statement->fetchAll(\PDO::FETCH_ASSOC) as $row) {
            /** @var array{source: string, remote_id: string, package: ?string, reason: string, raw: ?string} $row */
            $gaps[] = new CoverageGap($row['source'], $row['remote_id'], $row['package'], $row['reason'], $row['raw']);
        }
    }

    private function query(string $sql): \PDOStatement
    {
        $statement = $this->pdo->query($sql);
        if ($statement === false) {
            throw new AdvisoryLookupFailed(sprintf('Query failed on %s', $this->path));
        }

        return $statement;
    }

    /**
     * @param list<string> $packageNames
     *
     * @return array<string, list<Advisory>>
     */
    public function advisoriesFor(array $packageNames): array
    {
        $names = array_values(array_unique(array_map('strtolower', $packageNames)));
        if ($names === []) {
            return [];
        }
        $parser = new PackagistAdvisoryJsonParser();
        $result = [];
        try {
            return $this->lookUp($names, $parser, $result);
        } catch (\PDOException $e) {
            // A database that cannot answer is advisory data unavailable, which the caller turns into
            // exit 4 and a report saying the run did not complete. Left to escape, it reached Symfony
            // as an uncaught exception and became exit 1 — "vulnerabilities, all with verified fixes".
            throw new AdvisoryLookupFailed(sprintf('Advisory database %s could not be queried: %s', $this->path, $e->getMessage()), 0, $e);
        }
    }

    /**
     * @param list<string>              $names
     * @param array<string, list<Advisory>> $result
     *
     * @return array<string, list<Advisory>>
     */
    private function lookUp(array $names, PackagistAdvisoryJsonParser $parser, array $result): array
    {
        foreach (array_chunk($names, 400) as $chunk) {
            $placeholders = implode(',', array_fill(0, count($chunk), '?'));
            $statement = $this->pdo->prepare(
                "SELECT a.id, a.canonical_id, a.title, a.link, a.severity, a.reported_at, af.package, af.constraint_expr
                 FROM affected af JOIN advisory a ON a.id = af.advisory_id
                 WHERE af.package IN ($placeholders) AND a.withdrawn_at IS NULL
                 ORDER BY af.package, a.canonical_id",
            );
            $statement->execute($chunk);
            /** @var array<string, array<int, array{canonical_id: string, title: ?string, link: ?string, severity: ?string, reported_at: ?string, expressions: array<string, true>}>> $grouped */
            $grouped = [];
            foreach ($statement->fetchAll(\PDO::FETCH_ASSOC) as $row) {
                if (!is_array($row)) {
                    continue;
                }
                $package = (string) ($row['package'] ?? '');
                $advisoryId = (int) ($row['id'] ?? 0);
                $grouped[$package][$advisoryId] ??= [
                    'canonical_id' => (string) ($row['canonical_id'] ?? ''),
                    'title' => is_string($row['title'] ?? null) ? $row['title'] : null,
                    'link' => is_string($row['link'] ?? null) ? $row['link'] : null,
                    'severity' => is_string($row['severity'] ?? null) ? $row['severity'] : null,
                    'reported_at' => is_string($row['reported_at'] ?? null) ? $row['reported_at'] : null,
                    'expressions' => [],
                ];
                $grouped[$package][$advisoryId]['expressions'][(string) ($row['constraint_expr'] ?? '')] = true;
            }
            $cves = [];
            foreach ($grouped as $package => $advisories) {
                foreach ($advisories as $advisoryId => $data) {
                    $cves[$package][$advisoryId] = $this->cve($advisoryId, $data['canonical_id']);
                }
            }
            $exploits = $this->exploitsFor(array_values(array_filter(array_merge(...array_values(array_map('array_values', $cves)) ?: [[]]))));
            foreach ($grouped as $package => $advisories) {
                foreach ($advisories as $advisoryId => $data) {
                    $cve = $cves[$package][$advisoryId];
                    $exploit = $cve !== null ? ($exploits[strtoupper($cve)] ?? null) : null;
                    $result[$package][] = new Advisory(
                        $data['canonical_id'],
                        $package,
                        self::union(array_keys($data['expressions']), $parser, $data['canonical_id']),
                        $data['title'],
                        $cve,
                        $data['link'],
                        $data['severity'],
                        $data['reported_at'] !== null ? new \DateTimeImmutable($data['reported_at'], new \DateTimeZone('UTC')) : null,
                        $this->sources($advisoryId),
                        $exploit?->epss,
                        $exploit?->epssPercentile,
                        $exploit?->kevAdded,
                    );
                }
            }
        }

        return $result;
    }

    /**
     * Sources disagreeing on a range are unioned: a version any source calls affected is affected.
     * Ranges were validated when the database was built; one that no longer parses means a corrupt
     * or hand-edited file, which is fatal rather than silently matching nothing.
     *
     * @param list<string> $expressions
     */
    private static function union(array $expressions, PackagistAdvisoryJsonParser $parser, string $advisoryId): ConstraintInterface
    {
        if (count($expressions) === 1) {
            return $parser->parseAffectedVersionsStrict($expressions[0], $advisoryId);
        }
        $constraints = array_map(static fn (string $e): ConstraintInterface => $parser->parseAffectedVersionsStrict($e, $advisoryId), $expressions);
        $union = MultiConstraint::create($constraints, false);
        $union->setPrettyString(implode('|', $expressions));

        return $union;
    }

    private function cve(int $advisoryId, string $canonicalId): ?string
    {
        if (preg_match('{^CVE-}i', $canonicalId) === 1) {
            return $canonicalId;
        }
        $statement = $this->pdo->prepare("SELECT alias FROM alias WHERE advisory_id = ? AND alias LIKE 'CVE-%' LIMIT 1");
        $statement->execute([$advisoryId]);
        $alias = $statement->fetchColumn();

        return is_string($alias) ? $alias : null;
    }

    /** @return list<array{name: string, remoteId: string}> */
    private function sources(int $advisoryId): array
    {
        $statement = $this->pdo->prepare('SELECT name, remote_id FROM source WHERE advisory_id = ? ORDER BY name, remote_id');
        $statement->execute([$advisoryId]);
        $sources = [];
        foreach ($statement->fetchAll(\PDO::FETCH_ASSOC) as $row) {
            /** @var array{name: string, remote_id: string} $row */
            $sources[] = ['name' => $row['name'], 'remoteId' => $row['remote_id']];
        }

        return $sources;
    }
}
