<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory;

/**
 * Reads a snapshot in the Packagist API shape from disk. Used by fixtures and by users who want a
 * fully offline run against a file they fetched themselves.
 */
final class JsonFileAdvisoryProvider implements AdvisoryProvider
{
    /** @var array<string, list<Advisory>>|null */
    private ?array $advisories = null;

    /**
     * @param bool|null $complete whether the file holds every advisory for its packages (a Packagist API
     *                            dump) rather than only those matching the current lock (a `composer audit`
     *                            output); incomplete snapshots cannot vouch for candidate locks. Null
     *                            detects `composer audit --format=json` output by its extra top-level keys.
     */
    public function __construct(
        private readonly string $path,
        private readonly PackagistAdvisoryJsonParser $parser = new PackagistAdvisoryJsonParser(),
        private ?bool $complete = null,
    ) {
    }

    public function advisoriesFor(array $packageNames): array
    {
        $all = $this->load();
        $wanted = [];
        foreach ($packageNames as $name) {
            $wanted[strtolower($name)] = true;
        }

        return array_intersect_key($all, $wanted);
    }

    public function describe(): string
    {
        return 'advisory snapshot ' . $this->path . ($this->isComplete() ? '' : ' (current-lock advisories only)');
    }

    public function isComplete(): bool
    {
        if ($this->complete === null) {
            $this->load();
        }

        return $this->complete ?? true;
    }

    /** @return array<string, list<Advisory>> */
    private function load(): array
    {
        if ($this->advisories !== null) {
            return $this->advisories;
        }
        $raw = @file_get_contents($this->path);
        if ($raw === false) {
            throw new AdvisoryLookupFailed(sprintf('Cannot read advisory file %s.', $this->path));
        }
        try {
            $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new AdvisoryLookupFailed(sprintf('Advisory file %s is not valid JSON: %s', $this->path, $e->getMessage()), 0, $e);
        }
        if (!is_array($decoded)) {
            throw new AdvisoryLookupFailed(sprintf('Advisory file %s must contain a JSON object.', $this->path));
        }
        /** @var array<string, mixed> $decoded */
        if ($this->complete === null) {
            // `composer audit --format=json` carries "abandoned" (and "filter" from 2.10) next to
            // "advisories" and lists only the advisories matching the audited lock.
            $this->complete = !array_key_exists('abandoned', $decoded) && !array_key_exists('filter', $decoded);
        }

        return $this->advisories = $this->parser->parseDocument($decoded);
    }
}
