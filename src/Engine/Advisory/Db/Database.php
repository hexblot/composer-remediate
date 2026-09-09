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

    private function __construct(private readonly \PDO $pdo, public readonly string $path)
    {
    }

    public static function open(string $path): self
    {
        if (!is_file($path)) {
            throw new AdvisoryLookupFailed(sprintf('Advisory database %s does not exist.', $path));
        }
        if (!extension_loaded('pdo_sqlite')) {
            throw new AdvisoryLookupFailed('The pdo_sqlite PHP extension is required to read an advisory database.');
        }
        try {
            // PHP 8.5 moved the SQLite driver constants to Pdo\Sqlite; older versions only have the PDO ones.
            $openFlags = class_exists(\Pdo\Sqlite::class) ? \Pdo\Sqlite::ATTR_OPEN_FLAGS : \PDO::SQLITE_ATTR_OPEN_FLAGS;
            $readOnly = class_exists(\Pdo\Sqlite::class) ? \Pdo\Sqlite::OPEN_READONLY : \PDO::SQLITE_OPEN_READONLY;
            $pdo = new \PDO('sqlite:' . $path, null, null, [
                \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
                $openFlags => $readOnly,
            ]);
        } catch (\PDOException $e) {
            throw new AdvisoryLookupFailed(sprintf('Cannot open advisory database %s: %s', $path, $e->getMessage()), 0, $e);
        }
        $db = new self($pdo, $path);
        $schema = (int) ($db->meta()['schema_version'] ?? 0);
        if ($schema !== self::SCHEMA_VERSION) {
            throw new AdvisoryLookupFailed(sprintf('Advisory database %s has schema version %d; this version of the tool reads %d.', $path, $schema, self::SCHEMA_VERSION));
        }

        return $db;
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

    /**
     * Upstream records about the given packages that the build could not interpret.
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
            foreach ($grouped as $package => $advisories) {
                foreach ($advisories as $advisoryId => $data) {
                    $result[$package][] = new Advisory(
                        $data['canonical_id'],
                        $package,
                        self::union(array_keys($data['expressions']), $parser, $data['canonical_id']),
                        $data['title'],
                        $this->cve($advisoryId, $data['canonical_id']),
                        $data['link'],
                        $data['severity'],
                        $data['reported_at'] !== null ? new \DateTimeImmutable($data['reported_at'], new \DateTimeZone('UTC')) : null,
                        $this->sources($advisoryId),
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
