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

    public function __construct(
        private readonly string $path,
        private readonly PackagistAdvisoryJsonParser $parser = new PackagistAdvisoryJsonParser(),
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
        return 'advisory snapshot ' . $this->path;
    }

    public function isComplete(): bool
    {
        return true;
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
        return $this->advisories = $this->parser->parseDocument($decoded);
    }
}
