<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db;

/**
 * Writes merged advisories to a new SQLite file (atomically: temp file, then rename) and computes the
 * logical dataset hash that decides whether a shared copy needs republishing.
 */
final class DatabaseWriter
{
    /**
     * @param list<NormalizedAdvisory>                                              $advisories
     * @param list<array{name: string, fetched_at: string, records: int, gaps?: int}>  $sourceStats
     * @param array<string, string>                                                 $extraMeta
     * @param list<CoverageGap>                                                     $gaps       upstream records left out because they could not be read
     *
     * @return array{path: string, hash: string, advisories: int, conflicts: int, gaps: int, bytes: int}
     */
    public function write(array $advisories, array $sourceStats, string $path, array $extraMeta = [], array $gaps = []): array
    {
        if (!extension_loaded('pdo_sqlite')) {
            throw new \RuntimeException('The pdo_sqlite PHP extension is required to build an advisory database.');
        }
        $dir = dirname($path);
        if (!is_dir($dir) && !@mkdir($dir, 0755, true)) {
            throw new \RuntimeException("Cannot create $dir");
        }
        $tmp = $path . '.tmp-' . bin2hex(random_bytes(4));
        @unlink($tmp);
        $hash = self::datasetHash($advisories);

        $pdo = new \PDO('sqlite:' . $tmp, null, null, [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]);
        $pdo->exec('PRAGMA journal_mode = OFF');
        $pdo->exec('PRAGMA synchronous = OFF');
        $pdo->exec('CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)');
        $pdo->exec('CREATE TABLE advisory (id INTEGER PRIMARY KEY, canonical_id TEXT NOT NULL UNIQUE, title TEXT, link TEXT, severity TEXT, reported_at TEXT, withdrawn_at TEXT, has_conflict INTEGER NOT NULL DEFAULT 0)');
        $pdo->exec('CREATE TABLE alias (advisory_id INTEGER NOT NULL, alias TEXT NOT NULL, PRIMARY KEY (advisory_id, alias))');
        $pdo->exec('CREATE INDEX alias_lookup ON alias (alias)');
        $pdo->exec('CREATE TABLE affected (advisory_id INTEGER NOT NULL, package TEXT NOT NULL, constraint_expr TEXT NOT NULL, source TEXT NOT NULL)');
        $pdo->exec('CREATE INDEX affected_package ON affected (package)');
        $pdo->exec('CREATE TABLE source (advisory_id INTEGER NOT NULL, name TEXT NOT NULL, remote_id TEXT NOT NULL, url TEXT, modified_at TEXT)');
        $pdo->exec('CREATE TABLE gap (source TEXT NOT NULL, remote_id TEXT NOT NULL, package TEXT, reason TEXT NOT NULL, raw TEXT)');
        $pdo->exec('CREATE INDEX gap_package ON gap (package)');

        $pdo->beginTransaction();
        $insertAdvisory = $pdo->prepare('INSERT INTO advisory (canonical_id, title, link, severity, reported_at, withdrawn_at, has_conflict) VALUES (?, ?, ?, ?, ?, ?, ?)');
        $insertAlias = $pdo->prepare('INSERT OR IGNORE INTO alias (advisory_id, alias) VALUES (?, ?)');
        $insertAffected = $pdo->prepare('INSERT INTO affected (advisory_id, package, constraint_expr, source) VALUES (?, ?, ?, ?)');
        $insertSource = $pdo->prepare('INSERT INTO source (advisory_id, name, remote_id, url, modified_at) VALUES (?, ?, ?, ?, ?)');
        $conflicts = 0;
        foreach ($advisories as $advisory) {
            $insertAdvisory->execute([
                $advisory->canonicalId,
                $advisory->title,
                $advisory->link,
                $advisory->severity,
                $advisory->reportedAt?->format(DATE_ATOM),
                $advisory->withdrawnAt?->format(DATE_ATOM),
                $advisory->conflicts === [] ? 0 : 1,
            ]);
            $id = (int) $pdo->lastInsertId();
            if ($advisory->conflicts !== []) {
                ++$conflicts;
            }
            foreach ($advisory->aliases as $alias) {
                $insertAlias->execute([$id, $alias]);
            }
            foreach ($advisory->affected as $range) {
                $insertAffected->execute([$id, strtolower($range->package), $range->constraint, $range->source]);
            }
            foreach ($advisory->sources as $source) {
                $insertSource->execute([$id, $source->name, $source->remoteId, $source->url, $source->modifiedAt?->format(DATE_ATOM)]);
            }
        }
        $insertGap = $pdo->prepare('INSERT INTO gap (source, remote_id, package, reason, raw) VALUES (?, ?, ?, ?, ?)');
        foreach ($gaps as $gap) {
            $insertGap->execute([$gap->source, $gap->remoteId, $gap->package !== null ? strtolower($gap->package) : null, $gap->reason, $gap->raw !== null ? substr($gap->raw, 0, 500) : null]);
        }
        $meta = [
            'schema_version' => (string) Database::SCHEMA_VERSION,
            'built_at' => gmdate(DATE_ATOM),
            'dataset_hash' => $hash,
            'advisory_count' => (string) count($advisories),
            'conflict_count' => (string) $conflicts,
            'gap_count' => (string) count($gaps),
            'sources' => json_encode($sourceStats, JSON_THROW_ON_ERROR),
        ] + $extraMeta;
        $insertMeta = $pdo->prepare('INSERT INTO meta (key, value) VALUES (?, ?)');
        foreach ($meta as $key => $value) {
            $insertMeta->execute([$key, $value]);
        }
        $pdo->commit();
        $pdo->exec('VACUUM');
        $pdo = null;

        if (!@rename($tmp, $path)) {
            @unlink($tmp);
            throw new \RuntimeException("Cannot write $path");
        }

        return ['path' => $path, 'hash' => $hash, 'advisories' => count($advisories), 'conflicts' => $conflicts, 'gaps' => count($gaps), 'bytes' => (int) filesize($path)];
    }

    /**
     * Hash of the canonical security dataset: ids, aliases, ranges, withdrawal. Retrieval timestamps and
     * source metadata are excluded so an unchanged dataset hashes identically across builds.
     *
     * @param list<NormalizedAdvisory> $advisories
     */
    public static function datasetHash(array $advisories): string
    {
        $canonical = [];
        foreach ($advisories as $advisory) {
            $aliases = array_map('strtolower', $advisory->aliases);
            sort($aliases);
            $ranges = array_map(static fn (AffectedRange $r): string => strtolower($r->package) . ' ' . $r->constraint, $advisory->affected);
            sort($ranges);
            $canonical[$advisory->canonicalId] = [$aliases, $ranges, $advisory->withdrawnAt?->format(DATE_ATOM), $advisory->severity];
        }
        ksort($canonical);

        return hash('sha256', json_encode($canonical, JSON_THROW_ON_ERROR));
    }
}
