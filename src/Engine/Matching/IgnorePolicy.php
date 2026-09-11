<?php

declare(strict_types=1);

namespace Remediate\Engine\Matching;

use Composer\Config;
use Composer\Semver\Constraint\ConstraintInterface;
use Composer\Semver\VersionParser;

/**
 * Which advisories to leave out, with Composer's own scoping honoured: an entry that applies only to
 * `block` (the install-time policy) must not suppress an audit-time finding here.
 *
 * Sources: `--ignore` ids, `config.audit.ignore` (legacy, with optional `apply: audit|block|all`) and
 * `config.policy.advisories.ignore-id` / `.ignore` (Composer 2.10+, with `on-audit` / `on-block`).
 * Package rules may carry a version constraint; a finding is ignored only when the rule's constraint
 * matches the locked version.
 */
final class IgnorePolicy
{
    /**
     * @param array<string, true>                          $ids           lower-cased advisory ids and CVEs
     * @param array<string, list<ConstraintInterface|null>> $packages     lower-cased package name => constraints
     * @param array<string, true>                          $fromProject   entries the analysed project's composer.json
     *                                                                    supplied, rather than the operator
     */
    public function __construct(public readonly array $ids = [], public readonly array $packages = [], private readonly array $fromProject = [])
    {
    }

    public static function none(): self
    {
        return new self();
    }

    /** @param list<string> $ids */
    public function withIds(array $ids): self
    {
        $merged = $this->ids;
        foreach ($ids as $id) {
            $id = strtolower(trim($id));
            if ($id !== '') {
                $merged[$id] = true;
            }
        }

        return new self($merged, $this->packages, $this->fromProject);
    }

    /**
     * Entries that came from the analysed project's own composer.json. A repository can suppress its own
     * advisories that way, which is the point of the setting for a project you own and a disclosure a
     * gate needs for one you do not.
     *
     * @return list<string>
     */
    public function projectEntries(): array
    {
        return array_keys($this->fromProject);
    }

    public function isEmpty(): bool
    {
        return $this->ids === [] && $this->packages === [];
    }

    /** @return list<string> every configured entry, for hygiene reporting */
    public function entries(): array
    {
        return [...array_keys($this->ids), ...array_keys($this->packages)];
    }

    /** Returns the matching entry (id, CVE or package name) or null when the finding is not ignored. */
    public function matchedEntry(string $advisoryId, ?string $cve, string $packageName, string $normalizedVersion): ?string
    {
        foreach ([$advisoryId, $cve] as $candidate) {
            if ($candidate !== null && isset($this->ids[strtolower($candidate)])) {
                return strtolower($candidate);
            }
        }
        $package = strtolower($packageName);
        foreach ($this->packages[$package] ?? [] as $constraint) {
            if ($constraint === null || $constraint->matches(new \Composer\Semver\Constraint\Constraint('==', $normalizedVersion))) {
                return $package;
            }
        }

        return null;
    }

    /**
     * Reads the audit-scoped ignores from a project's Composer configuration.
     *
     * @param list<string> $projectKeys which of `audit` and `policy` the analysed project set, so the
     *                                  entries taken from them can be disclosed in the report
     */
    public static function fromComposerConfig(Config $config, array $projectKeys = []): self
    {
        $ids = [];
        $packages = [];
        $auditEntries = [];
        $policyEntries = [];
        $parser = new VersionParser();

        // Legacy config.audit.ignore: ["CVE-..."] or {"CVE-...": "reason"} or {"CVE-...": {"apply": "audit|block|all", "reason": "..."}}.
        $audit = $config->get('audit');
        if (is_array($audit) && is_array($audit['ignore'] ?? null)) {
            foreach ($audit['ignore'] as $key => $value) {
                $entry = is_int($key) ? (is_string($value) ? $value : null) : (string) $key;
                if ($entry === null || $entry === '') {
                    continue;
                }
                $appliesToAudit = true;
                if (is_array($value)) {
                    $apply = $value['apply'] ?? 'all';
                    $appliesToAudit = in_array($apply, ['audit', 'all'], true);
                }
                if (!$appliesToAudit) {
                    continue;
                }
                $auditEntries[] = strtolower($entry);
                if (self::looksLikePackage($entry)) {
                    $packages[strtolower($entry)][] = null;
                } else {
                    $ids[strtolower($entry)] = true;
                }
            }
        }

        // Composer 2.10+ config.policy.advisories: ignore-id (ids) and ignore (packages, optional constraint).
        $policy = $config->has('policy') ? $config->get('policy') : null;
        if (is_array($policy) && is_array($policy['advisories'] ?? null)) {
            $advisories = $policy['advisories'];
            foreach (is_array($advisories['ignore-id'] ?? null) ? $advisories['ignore-id'] : [] as $key => $value) {
                $entry = is_int($key) ? (is_string($value) ? $value : null) : (string) $key;
                if ($entry === null || $entry === '' || !self::onAudit($value)) {
                    continue;
                }
                $ids[strtolower($entry)] = true;
                $policyEntries[] = strtolower($entry);
            }
            foreach (is_array($advisories['ignore'] ?? null) ? $advisories['ignore'] : [] as $key => $value) {
                $name = is_int($key) ? (is_string($value) ? $value : null) : (string) $key;
                if ($name === null || $name === '') {
                    continue;
                }
                $rules = is_array($value) && array_is_list($value) ? $value : [$value];
                foreach ($rules as $rule) {
                    if (!self::onAudit($rule)) {
                        continue;
                    }
                    $constraint = null;
                    if (is_array($rule) && is_string($rule['constraint'] ?? null)) {
                        try {
                            $constraint = $parser->parseConstraints($rule['constraint']);
                        } catch (\UnexpectedValueException) {
                            continue; // unparsable constraint: do not widen the ignore to every version
                        }
                    }
                    $packages[strtolower($name)][] = $constraint;
                    $policyEntries[] = strtolower($name);
                }
            }
        }

        $fromProject = [];
        foreach ($projectKeys as $key) {
            foreach ($key === 'audit' ? $auditEntries : $policyEntries as $entry) {
                $fromProject[$entry] = true;
            }
        }

        return new self($ids, $packages, $fromProject);
    }

    private static function onAudit(mixed $value): bool
    {
        if (is_array($value) && array_key_exists('on-audit', $value)) {
            return (bool) $value['on-audit'];
        }

        return true;
    }

    private static function looksLikePackage(string $entry): bool
    {
        return str_contains($entry, '/') && preg_match('{^(CVE|GHSA|PKSA)-}i', $entry) !== 1;
    }
}
