# Ninth Adversarial Review: Pre-1.0.0-beta1 Security & Contract Audit

**Target commit**: `b762d5a` (`main`, clean working tree)  
**Date**: 2026-10-05  
**Review focus**: Adversarial attack on engine invariants, CLI compatibility surface, ignore policies, advisory matching across virtual/replaced packages, solver warnings, and machine-readable report integrity prior to tagging `1.0.0-beta1`.  
**Baseline suite verification**: All checks passing (`phpstan` level 8 on 177 files with 0 errors, `deptrac` with 0 violations, `phpunit` with 507 tests and 3,937 assertions across unit, fixtures, and contract suites, and `action-test.sh`).

---

## Executive Summary

The engine's core invariants, fail-closed handling, subprocess boundary isolation, and advisory cache security remain solid. However, this 9th adversarial review uncovered **4 actionable defects** that compromise the documented CLI surface, cause security ignore rules to be bypassed on monorepos, suppress critical Composer 2.10+ blocking warnings, and generate broken 404 URLs in machine-readable reports. In addition, an architectural assessment is provided for the open **Finding 10** (unbounded work in dependency graph expansion).

All four defects can be remedied with surgical patches before cutting `1.0.0-beta1`.

### Summary of Findings

| ID | Title | Severity | Component | Category |
|---|---|---|---|---|
| **Finding 1** | Standalone Binary Omits `remediate:pr-body` | Medium | `bin/composer-remediate` | CLI Contract / Usability |
| **Finding 2** | Package-Level Ignore Bypassed for Replaced/Provided Packages | High | `Matcher.php` | Core Logic / False Positives / Hygiene |
| **Finding 3** | `Planner::blockingRisk()` Fails to Detect Blocking on Replaced Packages | Medium | `Planner.php` | Correctness / Warning Omission |
| **Finding 4** | Inaccurate Provenance & Broken 404 URLs in CycloneDX/GitLab Reports for Drupal Advisories | Low / Medium | `CycloneDxRenderer.php`, `GitLabRenderer.php` | Data Integrity / Spec Compliance |
| **Finding 5** | Unbounded Work vs. Output in `DependencyGraph` (Finding 10 Status) | Informational | `DependencyGraph.php` | Performance / Algorithm Complexity |

---

## Detailed Findings

---

### Finding 1: Standalone Binary Omits `remediate:pr-body` (Broken CLI Contract)

* **Severity**: Medium
* **Files**:
  * [`bin/composer-remediate`](../bin/composer-remediate#L124-L136)
  * [`src/Command/PullRequestBodyCommand.php`](../src/Command/PullRequestBodyCommand.php#L21-L41)
  * [`docs/compatibility.md`](../docs/compatibility.md#L24)
* **Root Cause**:
  `docs/compatibility.md` guarantees the CLI contract for helper commands:
  > *"The helper commands `remediate:db-build`, `remediate:db-status`, and `remediate:pr-body` are covered with their documented options."*

  While `PullRequestBodyCommand` is registered for Composer plugin mode via `Remediate\Command\CommandProvider`, it was omitted from the standalone CLI binary entry point in `bin/composer-remediate`:
  ```php
  // bin/composer-remediate lines 124-136
  $commandNames = ['remediate', 'remediate:db-build', 'remediate-db-build', 'remediate:db-status', 'remediate-db-status', 'list', 'help'];
  $first = $args[0] ?? null;
  if ($first === null || str_starts_with($first, '-') || !in_array($first, $commandNames, true)) {
      array_unshift($args, 'remediate');
  }
  ...
  $application = new Application();
  $application->setName('Composer Remediate');
  $application->add(new RemediateCommand());
  $application->add(new DbBuildCommand());
  $application->add(new DbStatusCommand());
  ```
  Neither `remediate:pr-body` nor its alias `remediate-pr-body` is included in `$commandNames`, and `PullRequestBodyCommand` is never added to `$application`.

* **Reproduction**:
  Run the command via the standalone binary:
  ```bash
  bin/composer-remediate remediate:pr-body before.json after.json
  ```
  Because `remediate:pr-body` is not in `$commandNames`, the binary assumes it is an argument to the default `remediate` command, executing `composer-remediate remediate remediate:pr-body before.json after.json`. Symfony Console throws:
  ```
  RuntimeEngineException: No arguments expected for "remediate" command, got "remediate:pr-body".
  ```
  Exit code is 1.

* **Impact**:
  Standalone CI environments, custom GitHub Action workflows, or containerized runners invoking `composer-remediate remediate:pr-body` crash immediately.

* **Remediation**:
  In `bin/composer-remediate`:
  1. Import `Remediate\Command\PullRequestBodyCommand`.
  2. Add `'remediate:pr-body'` and `'remediate-pr-body'` to `$commandNames`.
  3. Register `$application->add(new PullRequestBodyCommand());`.

---

### Finding 2: Package-Level Ignore Bypassed for Replaced/Provided Packages

* **Severity**: High
* **Files**:
  * [`src/Engine/Matching/Matcher.php`](../src/Engine/Matching/Matcher.php#L95-L105)
  * [`src/Engine/Matching/IgnorePolicy.php`](../src/Engine/Matching/IgnorePolicy.php#L96-L112)
* **Root Cause**:
  In `Matcher::match()`, replaced and provided packages are checked for vulnerabilities:
  ```php
  // Matcher.php lines 95-105
  foreach ($package->getReplaces() + $package->getProvides() as $target => $link) {
      $target = strtolower((string) $target);
      if ($lock->has($target)) {
          continue; // the replaced package is also installed on its own; it is matched directly
      }
      foreach ($advisories[$target] ?? [] as $advisory) {
          if ($advisory->affectsConstraint($link->getConstraint()) && !$this->isIgnored($advisory, $name, $package->getVersion())) {
              $findings[] = new Finding($advisory, $name, $package->getVersion(), $package->getPrettyVersion(), $lock->isDev($name), $isRootRequirement($name), $target);
          }
      }
  }
  ```
  Notice line 101: `!$this->isIgnored($advisory, $name, $package->getVersion())`.
  `$name` is the host package (e.g. `acme/monorepo` or `symfony/symfony`), while `$target` is the replaced package carrying the advisory (e.g. `acme/component` or `symfony/http-foundation`).
  If a project configures an ignore on the component (`config.audit.ignore = ["acme/component"]` or `config.policy.advisories.ignore = {"acme/component": "*"}`), `isIgnored` queries `$name` (`acme/monorepo`), which does not match.

* **Reproduction**:
  1. Configure a project where `acme/monorepo` replaces `acme/component`.
  2. Advisory `ADV-1` exists for `acme/component`.
  3. Set `config.audit.ignore = ["acme/component"]` in `composer.json`.
  4. Run `composer remediate`.
  5. The advisory is **not ignored** and appears as an active vulnerability in the report.
  6. Remediate concurrently emits a false hygiene warning:
     `"Ignore hygiene: 1 ignore entry matches nothing in this lock and can be removed: acme/component"`.

* **Impact**:
  Users cannot suppress vulnerabilities in replaced or provided packages using standard package-level ignore rules. Furthermore, the tool gives false-positive advice telling users their ignore rules are unused and can be deleted.

* **Remediation**:
  In `Matcher.php`, check both `$target` (the replaced component) and `$name` (the host package) against the ignore policy:
  ```php
  if ($advisory->affectsConstraint($link->getConstraint())
      && !$this->isIgnored($advisory, $target, $package->getVersion())
      && !$this->isIgnored($advisory, $name, $package->getVersion())
  ) {
  ```
  If either `$target` or `$name` matches an ignore rule, the finding is suppressed and the matched rule is recorded in `$this->usedIgnores`, preserving clean hygiene reporting.

---

### Finding 3: `Planner::blockingRisk()` Fails to Detect Composer 2.10+ Advisory Blocking on Replaced Packages

* **Severity**: Medium
* **Files**:
  * [`src/Engine/Planner.php`](../src/Engine/Planner.php#L966-L977)
  * [`src/Engine/Matching/Finding.php`](../src/Engine/Matching/Finding.php#L41-L44)
* **Root Cause**:
  `Planner::blockingRisk()` identifies packages whose upgrade moves them to a version that still carries an unignored advisory, which Composer 2.10+ blocks by default.
  ```php
  // Planner.php lines 966-977
  private static function blockingRisk(LockDiff $diff, array $afterKeys): array
  {
      $stillVulnerable = [];
      foreach (array_keys($afterKeys) as $key) {
          $stillVulnerable[explode('@', $key, 2)[1] ?? ''] = true;
      }
      $risk = [];
      foreach ($diff->changes as $change) {
          if ($change->kind !== \Remediate\Engine\Solver\PackageChange::REMOVED && isset($stillVulnerable[$change->packageName])) {
              $risk[] = $change->packageName;
          }
      }

      return $risk;
  }
  ```
  Per `Finding::key()`, finding keys for replaced packages append `/{viaReplacedName}`:
  `$advisory->id . '@' . $this->packageName . ($this->viaReplacedName !== null ? '/' . $this->viaReplacedName : '')`
  For example: `ADV-1@acme/monorepo/acme/component`.
  `explode('@', $key, 2)[1]` evaluates to `'acme/monorepo/acme/component'`.
  However, in `$diff->changes`, `$change->packageName` is `'acme/monorepo'`.
  `isset($stillVulnerable['acme/monorepo'])` evaluates to `false`.

* **Reproduction**:
  1. A candidate upgrades `acme/monorepo` from 1.0.0 to 1.1.0 to resolve advisory X.
  2. Version 1.1.0 still carries advisory Y on replaced component `acme/component`.
  3. `$afterKeys` contains `ADV-Y@acme/monorepo/acme/component`.
  4. `blockingRisk()` returns `[]` instead of `['acme/monorepo']`.

* **Impact**:
  Remediate fails to detect the blocking risk and omits the warning:
  `"...the recommended command moves acme/monorepo to a version that still carries another advisory; Composer 2.10+ advisory blocking may refuse it..."`.
  The operator runs the printed command and is unexpectedly blocked by Composer 2.10+.

* **Remediation**:
  In `Planner::blockingRisk()`, extract both the host package name and the replaced package name when populating `$stillVulnerable`:
  ```php
  private static function blockingRisk(LockDiff $diff, array $afterKeys): array
  {
      $stillVulnerable = [];
      foreach (array_keys($afterKeys) as $key) {
          $pkgPath = explode('@', $key, 2)[1] ?? '';
          $parts = explode('/', $pkgPath);
          if (count($parts) >= 2) {
              $stillVulnerable[$parts[0] . '/' . $parts[1]] = true;
          }
          if (count($parts) >= 4) {
              $stillVulnerable[$parts[2] . '/' . $parts[3]] = true;
          }
      }
      $risk = [];
      foreach ($diff->changes as $change) {
          if ($change->kind !== \Remediate\Engine\Solver\PackageChange::REMOVED && isset($stillVulnerable[$change->packageName])) {
              $risk[] = $change->packageName;
          }
      }

      return $risk;
  }
  ```

---

### Finding 4: Inaccurate Provenance & Broken 404 URLs in CycloneDX/GitLab Reports for Drupal Advisories

* **Severity**: Low / Medium
* **Files**:
  * [`src/Output/CycloneDxRenderer.php`](../src/Output/CycloneDxRenderer.php#L108-L111)
  * [`src/Output/GitLabRenderer.php`](../src/Output/GitLabRenderer.php#L83-L86)
* **Root Cause**:
  Both renderers assume any advisory not starting with `GHSA-` is a Packagist security advisory:
  - `CycloneDxRenderer.php#L108-L111`:
    ```php
    $source = ['name' => 'Packagist', 'url' => 'https://packagist.org/security-advisories/' . $advisory->id];
    if (preg_match('{^GHSA-}i', $advisory->id) === 1) {
        $source = ['name' => 'GitHub', 'url' => 'https://github.com/advisories/' . $advisory->id];
    }
    ```
  - `GitLabRenderer.php#L86`:
    ```php
    $identifiers[] = ['type' => 'packagist_advisory', 'name' => $advisory->id, 'value' => $advisory->id, 'url' => 'https://packagist.org/security-advisories/' . $advisory->id];
    ```
  Since release `v0.11.0`, Drupal.org advisories (`SA-CONTRIB-*`, `SA-CORE-*`) are ingested. Packagist does not host these advisories; requesting `https://packagist.org/security-advisories/SA-CONTRIB-...` yields a 404 Not Found.
  (In contrast, `SarifRenderer.php#L106` correctly checks `$advisory->link` before falling back).

* **Impact**:
  Machine-readable reports (CycloneDX SBOMs and GitLab SAST/dependency scanning JSON) publish broken 404 links and attribute Drupal security team advisories to Packagist.

* **Remediation**:
  1. Determine provenance using advisory ID prefix or `$advisory->link`:
     - If `$advisory->id` matches `^SA-(CORE|CONTRIB)-` or `$advisory->link` contains `drupal.org`:
       - CycloneDX source: `['name' => 'Drupal.org', 'url' => $advisory->link ?? 'https://www.drupal.org/security-advisories']`.
       - GitLab identifier: `['type' => 'drupal_advisory', 'name' => $advisory->id, 'value' => $advisory->id, 'url' => $advisory->link ?? 'https://www.drupal.org/security-advisories']`.
     - Otherwise, if matching `^GHSA-`, attribute to GitHub.
     - Only emit `Packagist` / `packagist_advisory` when matching `^PKSA-` or when originating from Packagist.

---

### Finding 5: Unbounded Work vs. Output in `DependencyGraph` (Finding 10 Status)

* **Severity**: Informational / Architecture Note
* **Files**:
  * [`src/Engine/Graph/DependencyGraph.php`](../src/Engine/Graph/DependencyGraph.php#L41-L51)
* **Context**:
  In Finding 10 of the 8th review, `DependencyGraph::pathsToRoot()` called `InstalledRepository::getDependents(..., recursive: true)`, which builds the complete recursive ancestor tree before `walk()` trims the result to `MAX_PATHS = 200`. In dense synthetic lattices (35 interconnected packages), this caused a 6-second, 144 MiB memory spike.
  Commit `f4ad87e` attempted a breadth-first level-by-level walk to bound the work, but had to be reverted because the breadth-first order altered the prioritization of root requirements on real-world fixtures (specifically dropping `drupal/core-recommended` on the Islandora fixture, causing the planner to recommend four packages instead of one).

* **Assessment for 1.0.0-beta1**:
  As documented in `docs/roadmap.md`, this is an asymptotic cost in pathological/adversarial graphs rather than a safety vulnerability or correctness flaw on realistic dependency trees. Preserving exact, minimal recommendations across the golden fixture corpus is paramount.
  **Recommendation**: Keep Finding 10 open as an accepted limitation for `1.0.0-beta1`. Address post-beta via a priority-queue / Dijkstra search that faithfully mirrors Composer's depth-first traversal and replacement resolution while bounding exploration work.

---

## Release Checklist for 1.0.0-beta1

- [ ] **Patch Finding 1**: Add `remediate:pr-body` and alias `remediate-pr-body` to `bin/composer-remediate`.
- [ ] **Patch Finding 2**: Update `Matcher::match()` to check ignores for both `$target` and `$name` on replaced/provided dependencies.
- [ ] **Patch Finding 3**: Update `Planner::blockingRisk()` to extract host and replaced package names from finding keys.
- [ ] **Patch Finding 4**: Update `CycloneDxRenderer` and `GitLabRenderer` to correctly attribute Drupal.org advisories and emit valid URLs.
- [ ] **Regression Tests**: Add test cases covering each finding in `tests/Unit/`.
- [ ] **Validation Run**: Execute `ddev composer check` (`phpstan`, `deptrac`, `phpunit`, `action-test.sh`).
