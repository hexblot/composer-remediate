# Composer Remediation Planner — Initial Technical Design

> **Revision note (2026-09-09).** This design was revised after verifying Composer's internals and
> building the Phase 0 prototype. The decisions and their reasons are recorded as architecture
> decision records in `docs/adr/`; the sections below were updated to match. Where the original
> text said "should be evaluated", the choice is now stated.

## 1. Purpose

This document defines the initial technical scope and architecture for a free, open-source Composer vulnerability remediation planner, delivered as a Composer plugin.

The project is intended to solve one specific problem:

> **Given a Composer dependency graph containing one or more known vulnerable packages, determine the smallest safe set of dependency changes that removes those vulnerabilities, validate the proposed graph with Composer's own solver, and explain the remediation clearly to the developer.**

The system is not intended to replace Composer, `composer audit`, static analysis, vulnerability feeds, or existing Software Composition Analysis products.

Instead, it occupies the layer between vulnerability detection and developer action.

---

## 2. Scope

### 2.1 In scope

Initial releases should support:

- Composer projects with `composer.json` and `composer.lock`;
- dependency graph construction;
- direct and transitive dependency tracing;
- multiple advisory sources;
- local normalized advisory storage;
- vulnerability aliasing and deduplication;
- affected and fixed version range interpretation;
- candidate remediation generation;
- Composer solver-backed validation;
- remediation ranking;
- human-readable explanations;
- machine-readable output for CI;
- fully local project analysis;
- reproducible database-backed analysis;
- signed/versioned advisory database artifacts.

### 2.2 Explicitly out of scope initially

The first versions should not attempt to provide:

- PHP source-code static analysis;
- taint analysis;
- DAST;
- malware scanning;
- secret scanning;
- dependency reachability analysis;
- automatic modification of `composer.json`;
- automatic execution of upgrades;
- proprietary cloud analysis;
- a new public vulnerability-identification system;
- a replacement for CVE, GHSA, OSV, Packagist, or FriendsOfPHP.

Keeping these out of scope is intentional. The value proposition is remediation quality, not breadth.

---

## 3. Design principles

### 3.1 Detection is an input

The remediation engine should assume that vulnerability intelligence already exists.

The project may aggregate and normalize advisory feeds, but identifying novel vulnerabilities is not the engine's responsibility.

### 3.2 Local analysis by default

All project-sensitive analysis runs locally, inside the user's Composer. No third-party service is
involved and nothing is sent anywhere Composer itself would not send it.

Two network interactions are inherent to solver-backed remediation and are documented rather than
denied: Composer's solver fetches package metadata from the project's configured repositories
(exactly as `composer update` does), and the default advisory lookup POSTs package names to
Packagist's advisory API (exactly as `composer audit` does; versions are not sent).

`--offline` refuses all network access and fails loudly on a cache miss instead of falling back.

### 3.3 Advisory-source neutrality

The core engine must not contain source-specific business logic.

Every upstream advisory source should be translated into a common internal representation.

### 3.4 Composer is the authority on solvability

The tool should not attempt to implement its own Composer-compatible dependency solver.

Composer's own solver should be used to determine whether candidate dependency graphs are actually valid.

### 3.5 Prefer explanation over magic

A remediation recommendation should be explainable.

The tool should expose:

- why a vulnerable package is present;
- whether it is direct or transitive;
- which root-controllable package determines it;
- why a safe version cannot currently resolve;
- what change permits it;
- what collateral changes occur;
- why one valid solution was ranked above another.

### 3.6 Fail conservatively

If the tool cannot prove a candidate remediation, it should not present that remediation as safe.

"No verified remediation found" is an acceptable and important result.

---

## 4. High-level architecture

```text
                        Public advisory sources
                   ┌──────────┬──────────┬──────────┐
                   │          │          │          │
                   ▼          ▼          ▼          ▼
              FriendsOfPHP   OSV      GHSA     other feeds
                   │          │          │          │
                   └──────────┴────┬─────┴──────────┘
                                  │
                                  ▼
                         Advisory compiler
                     fetch / parse / normalize
                    alias / dedupe / validate
                                  │
                                  ▼
                         Signed SQLite database
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
                    ▼                           ▼
              official DB                  local DB(s)
                    │                           │
                    └─────────────┬─────────────┘
                                  │
                                  ▼
 composer.json ───────────► Remediation engine ◄──────── composer.lock
                                  │
                                  ├── dependency graph
                                  ├── advisory matching
                                  ├── candidate generation
                                  ├── Composer solver adapter
                                  ├── ranking engine
                                  └── explanation engine
                                  │
                                  ▼
                             output layer
                         text / JSON / CI formats
```

The system naturally divides into two major components:

1. **Advisory compiler and database distribution**
2. **Local remediation engine**

These components should be independently testable and loosely coupled.

---

## 5. Advisory database subsystem

## 5.0 Position in the roadmap

Phases 0 and 1 do not need a database: the engine's `AdvisoryProvider` interface is implemented by
an adapter over Composer's own repository advisory API (Packagist by default) and by a JSON snapshot
reader used for fixtures and offline runs. The database is Phase 2. It is **built locally** by
`remediate db:build` from live sources; the same file can be published centrally and consumed with
`--database-location <path|URL>`, and the project's own signed release pipeline (§6) is the reference
instance of that sharing model rather than a separate product.

## 5.1 Purpose

The advisory database exists to provide the remediation engine with a normalized, deduplicated, local view of known package vulnerabilities.

It should be usable without internet connectivity once built or downloaded.

## 5.2 SQLite as the distribution format

SQLite is a strong fit because it provides:

- a single portable file;
- no daemon requirement;
- transactional consistency;
- indexed relational queries;
- read-only operation;
- easy inspection by users;
- mature tooling across platforms;
- suitability for signed immutable artifacts.

The official advisory database should normally be opened read-only.

## 5.3 Potential schema

An initial schema may contain the following logical entities.

### `advisory`

```text
id
canonical_id
summary
details
published_at
modified_at
withdrawn_at
```

### `advisory_alias`

```text
advisory_id
alias_type
alias_value
```

Examples:

```text
CVE-2026-12345
GHSA-xxxx-yyyy-zzzz
OSV-2026-123
```

### `package`

```text
id
ecosystem
name
```

For the initial implementation, ecosystem will normally be `Packagist` / Composer.

### `affected_range`

```text
advisory_id
package_id
range_type
range_expression
```

### `fixed_range`

```text
advisory_id
package_id
range_expression
```

### `advisory_source`

```text
advisory_id
source_name
source_record_id
source_url
source_modified_at
source_license
```

### `severity`

```text
advisory_id
scheme
value
vector
```

This should support multiple severity schemes rather than assuming CVSS exclusively.

### `reference`

```text
advisory_id
reference_type
url
```

## 5.4 Deduplication

Deduplication should occur primarily through known aliases.

Example:

```text
OSV record A
  aliases: CVE-2026-12345, GHSA-AAAA-BBBB-CCCC

FriendsOfPHP record B
  cve: CVE-2026-12345
```

These should result in one logical advisory with multiple source records.

When alias relationships are insufficient, fuzzy or heuristic merging should initially be avoided unless it can be made deterministic and well tested.

False deduplication is more dangerous than duplication.

## 5.5 Conflicting sources

Different advisory sources may disagree on:

- affected versions;
- fixed versions;
- severity;
- publication status;
- package identity;
- withdrawal status.

The compiler must retain source provenance so disagreements remain inspectable.

The first implementation should prefer conservative behaviour.

Possible policy:

- union affected ranges when credible sources disagree;
- preserve every source's original range;
- emit a conflict flag;
- avoid silently discarding contradictory data.

The precise policy should be configurable later, but hidden conflict resolution should be avoided.

---

## 6. Advisory database build and release model

## 6.1 Polling

Upstream sources may be polled frequently, for example hourly.

Polling frequency and artifact publication frequency are deliberately separate concepts.

A build cycle is:

```text
poll sources
    │
    ▼
parse
    │
    ▼
normalize
    │
    ▼
deduplicate
    │
    ▼
canonicalize
    │
    ▼
calculate logical dataset hash
    │
    ├── unchanged ──► no database release
    │
    └── changed ────► build + sign + publish database
```

## 6.2 Publish only on meaningful change

A new advisory artifact should be released only when the normalized canonical security dataset changes.

Changes that should trigger publication include:

- new advisory;
- modified affected range;
- modified fixed range;
- advisory withdrawal;
- alias addition or correction;
- package correction;
- severity change if severity is part of the canonical dataset;
- source conflict resolution that changes the normalized result.

Changes that should not necessarily trigger publication include:

- retrieval timestamps;
- whitespace differences;
- irrelevant upstream field order;
- source metadata not included in the canonical data model.

## 6.3 Database version format

Database artifact versions use a date/hour scheme based on publication time.

Normal release:

```text
YYYY-MM-DD.HH
```

Example:

```text
2026-01-01.01
2026-01-07.22
```

Emergency rebuild or hot patch within the same hour:

```text
YYYY-MM-DD.HH.N
```

Example:

```text
2026-01-01.01
2026-01-01.01.1
2026-01-01.01.2
```

The `.0` form is implicit and omitted.

This is a project-specific artifact version and is not Semantic Versioning.

## 6.4 Historical lookup semantics

Only meaningful database releases need to exist.

If a caller asks for the database state as of timestamp `T`, the defined behaviour should be:

> Return the newest database release whose publication timestamp is less than or equal to `T`.

Example:

```text
available:
  2026-01-01.01
  2026-01-07.22

requested:
  2026-01-05 12:00 UTC

returned:
  2026-01-01.01
```

This provides reproducibility without publishing duplicate hourly artifacts.

## 6.5 Latest manifest

The project should expose a small signed manifest such as:

```json
{
  "version": "2026-01-07.22",
  "database": "db-2026-01-07.22.sqlite",
  "sha256": "...",
  "published_at": "2026-01-07T22:08:17Z",
  "last_successful_poll": "2026-01-10T15:00:17Z",
  "previous": "2026-01-01.01"
}
```

This distinction is important:

- `published_at` tells the user when the dataset last changed;
- `last_successful_poll` tells the user whether ingestion is still healthy.

A quiet advisory period should not be indistinguishable from a failed build pipeline.

## 6.6 Artifact integrity

At minimum, releases should provide:

```text
db-2026-01-07.22.sqlite
db-2026-01-07.22.sqlite.sha256
db-2026-01-07.22.sqlite.sig
latest.json
latest.json.sig
```

The CLI should:

1. verify the signed manifest;
2. identify the required database artifact;
3. download it;
4. verify the hash;
5. install it atomically;
6. retain the previous version for rollback where practical.

---

## 7. Local and organisational advisories

Official advisory data should not need to be modified in place.

The engine should support one or more additional local databases or files.

Example:

```text
official.sqlite
company-security.sqlite
project-overrides.json
```

The logical advisory set is the union of these sources.

This allows organisations to represent private vulnerabilities such as:

```text
company/internal-package <2.1.4 vulnerable
```

without publishing them or altering the signed public database.

Local advisory precedence and override semantics should be explicit and deterministic.

---

## 8. Project input model

The primary project inputs are:

```text
composer.json
composer.lock
```

The tool may also need access to:

- current PHP version;
- installed PHP extensions;
- Composer version;
- platform overrides from Composer configuration;
- repository declarations;
- stability constraints;
- lockfile metadata.

The objective is to reproduce Composer's actual resolution context as closely as possible.

---

## 9. Dependency graph model

The tool must distinguish:

- root requirements;
- direct dependencies;
- transitive dependencies;
- development dependencies;
- platform dependencies;
- replaced/provided packages;
- conflicts;
- virtual packages.

A graph node might contain:

```text
PackageNode
  name
  version
  source_type
  is_root_requirement
  is_dev
  requires[]
  required_by[]
```

For every vulnerable package, the engine should be able to produce all relevant dependency paths to the root.

Example:

```text
root
└── drupal/core-recommended
    └── symfony/http-foundation
```

Multiple parents must be handled correctly:

```text
root
├── package/a
│   └── vulnerable/package
└── package/b
    └── vulnerable/package
```

A remediation that fixes one path but leaves another constraint blocking the safe version is not valid.

---

## 10. Vulnerability matching

For each locked package:

1. locate advisory records matching the package name;
2. evaluate the locked version against affected ranges;
3. group aliases referring to the same vulnerability;
4. record the dependency paths through which the package is present;
5. determine whether the package is directly controlled by the root project.

The result is a set of `Finding` objects.

Possible conceptual model:

```text
Finding
  advisory
  locked_package
  locked_version
  dependency_paths[]
  root_controlled
  candidate_fixed_versions[]
```

---

## 11. Remediation candidate generation

This is the core intellectual component of the project.

For each finding, the engine should determine the nearest changeable dependency or dependencies that can permit a safe graph.

### 11.1 Direct vulnerable dependency

Example:

```text
root
└── vulnerable/package
```

Questions:

- does the existing root constraint already permit a safe release?
- is the lockfile merely stale?
- does the root constraint need widening or changing?
- would remediation cross a major-version boundary?

### 11.2 Transitive vulnerable dependency

Example:

```text
root
└── parent/package
    └── vulnerable/package
```

Questions:

- does the parent constraint already permit a fixed child version?
- if yes, is a partial update sufficient?
- if no, what is the smallest parent upgrade that permits one?
- if multiple parents require the vulnerable package, which combination of upgrades is necessary?

### 11.0 Candidates are Composer commands (decided)

Every candidate *is* one concrete `composer update` invocation: an allow list, a transitive mode
(`-w` / `-W`), temporary constraints (`--with`, valid for transitive packages since Composer 2.4),
`--minimal-changes` (Composer 2.9+), and optionally a root constraint change applied to a scratch
copy of `composer.json`. Validation runs exactly that invocation; the recommendation prints exactly
that invocation. Candidates are generated least invasive first:

1. `composer update V` (lock merely stale);
2. `composer update V -w -m --with 'V:<fixed range>'`;
3. `composer update A -W -m --with 'V:<fixed range>'` for the nearest root-required ancestor `A` on
   each path, then further ancestors, then the union of all nearest parents when several block;
4. widen `A`'s root constraint to the next caret range, then update it with all dependencies;
5. (opt-in) require `V` directly with the fixed range.

The fixed range is derived from the advisory's affected range as its complement above the locked
version; downgrades are never proposed.

Because `-m` still moves the *named* package to its newest allowed version, a validated parent
update is refined by a bounded downward search (`--with 'A:>current,<newest'`) for the lowest
parent version that still admits the fix, which is then pinned as `composer update A:x.y.z -W -m`.

### 11.3 Deep transitive dependency

Example:

```text
root
└── package/a
    └── package/b
        └── vulnerable/package
```

The engine should search upward through controllable dependency boundaries until it finds candidate interventions that Composer can resolve.

The tool must avoid suggesting that the developer add a transitive package as a new direct dependency merely to force a version unless such behaviour is explicitly requested as an advanced strategy.

---

## 12. Composer solver integration

The project should use Composer's solver as the source of truth for candidate validity.

Two implementation strategies should be evaluated during prototyping:

### 12.1 Composer as a library

Use `composer/composer` directly and construct candidate resolution requests in process.

Advantages:

- structured access to dependency information;
- no fragile CLI parsing;
- potentially better performance;
- deeper explanation possibilities.

Risks:

- coupling to Composer internals;
- API stability;
- version compatibility complexity.

### 12.2 Composer as a subprocess

Create isolated temporary project state and invoke Composer commands with machine-readable output.

Advantages:

- uses the installed Composer behaviour exactly;
- lower coupling to internals;
- easier compatibility with multiple Composer releases.

Risks:

- slower candidate evaluation;
- output parsing;
- subprocess complexity;
- temporary filesystem management.

**Decision:** in-process first, subprocess as fallback. Each candidate runs `Composer\Installer`
in dry-run mode against a fresh `Composer` instance created from a scratch copy of the project with
plugins and scripts disabled. `Installer::getLockTransaction()` and the virtual lock cached by
`Locker::setLockData(..., $write = false)` expose the resulting package set in memory, so nothing is
written. The subprocess route (`composer update … --no-install` in the scratch copy, reading the
written lock) exists for environments where the API is unavailable. Composer 2.10's advisory pool
blocking is disabled inside solves so results are identical across Composer versions; the planner
performs its own advisory check on every result.

Composer's advisory classes are `@internal` and changed in every release from 2.7 to 2.10; they are
touched only inside one adapter, with `composer audit --locked --format=json` as a second adapter.

---

## 13. Candidate validation strategy

A candidate remediation must be tested without modifying the user's working tree.

Possible workflow:

```text
current project metadata
        │
        ▼
create isolated candidate state
        │
        ▼
apply hypothetical root/package change
        │
        ▼
invoke Composer solver
        │
        ├── fail ──► reject candidate
        │
        └── resolve
             │
             ▼
       inspect resulting graph
             │
             ▼
       re-evaluate advisories
             │
        ┌────┴────┐
        │         │
     vulnerable   clean
        │         │
      reject    valid candidate
```

A successful solve alone is insufficient.

The resulting graph must also be checked to ensure the vulnerability has actually disappeared, that
no advisory absent from the original lock was introduced, and that something actually changed.

---

## 14. Candidate ranking

Several valid candidate graphs may remove the same vulnerability.

The ranking engine should favour minimal disruption.

A preliminary scoring function could consider:

```text
score =
  root_dependency_changes * W1
+ major_version_changes    * W2
+ package_changes          * W3
+ package_removals         * W4
+ package_additions        * W5
+ total_version_distance   * W6
+ stability_penalties      * W7
```

Weights should not be hard-coded permanently without evidence.

The initial implementation may use deterministic priority rules instead:

1. no root constraint changes;
2. no major-version changes;
3. fewest changed packages;
4. fewest direct dependency changes;
5. fewest removals/additions;
6. smallest version movement.

This will be easier to reason about and test initially.

---

## 15. Multi-vulnerability planning

A project may contain many findings.

The naive approach is to remediate each independently, but this can produce redundant or conflicting recommendations.

Example:

```text
CVE-A affects package/x
CVE-B affects package/y

both are resolved by updating framework/root-package once
```

The engine should eventually search for combined remediation plans.

Initial versions may:

- generate per-finding plans;
- identify identical or overlapping candidate upgrades;
- collapse obvious duplicates.

A later optimization phase can treat remediation as a global graph-planning problem.

---

## 16. Output model

Human-readable output is a core feature, not decoration.

Example:

```text
CVE-2026-12345
────────────────────────────────────────
Affected
  symfony/http-foundation 6.4.21

Introduced by
  root
  └── drupal/core-recommended 11.4.2
      └── symfony/http-foundation 6.4.21

Fixed versions
  >=6.4.24

Current state
  The vulnerable package is transitive.
  The current parent constraint does not permit a fixed release.

Recommended remediation
  drupal/core-recommended 11.4.2 -> 11.4.3

Composer validation
  PASS

Expected changes
  3 packages updated
  0 added
  0 removed
  0 root constraints added

Recommended command
  composer update drupal/core-recommended -W -m
```

## 16.1 Machine-readable output

JSON output should expose the same semantic structure.

Potential top-level fields:

```text
analysis_metadata
findings[]
remediation_plans[]
unsolved_findings[]
database_metadata
composer_environment
```

This will support CI integration, IDE tooling, bots, and downstream systems.

---

## 17. Reproducibility

Every report should identify enough state to reproduce the result. Note that solver results also
depend on the package metadata served by the repositories at analysis time, which no hash of the
project can pin; test fixtures therefore freeze that metadata (§22.2).

Suggested metadata:

```text
engine_version
database_version
database_sha256
composer_version
php_version
composer_json_sha256
composer_lock_sha256
analysis_timestamp
```

An optional analysis identifier could be derived from stable inputs:

```text
sha256(
  composer.json
  + composer.lock
  + advisory_database_hash
  + remediation_engine_version
  + relevant_platform_state
)
```

This makes security findings auditable and repeatable.

---

## 18. Privacy and offline behaviour

A core product promise should be:

> **No third party sees your dependency graph. Network use is exactly what `composer update` itself
> would do against the repositories you already use.**

The earlier phrasing "your dependency graph never leaves your machine" was not achievable for a
solver-backed tool: Composer must fetch metadata for candidate versions from the configured
repositories, and the default advisory lookup sends package names to Packagist as `composer audit`
does. Both are documented in the privacy page of the docs site. A default analysis therefore
performs the same requests an update would, and no others.

Suggested command model:

```bash
composer-remediate db:update
composer-remediate plan
```

The first command may access the network.

The second should operate entirely locally.

An explicit strict mode may enforce this:

```bash
composer-remediate plan --offline
```

If any component attempts remote access under strict offline mode, execution should fail rather than silently fall back to network behaviour. Offline mode is implemented with Composer's `COMPOSER_DISABLE_NETWORK`, which serves cached metadata and fails on anything uncached; a warm Composer cache or a local advisory database is required.

The tool runs inside the user's Composer, so private repositories and `auth.json` credentials are
used exactly as Composer uses them; no separate configuration is needed.

---

## 19. CLI concept

Possible initial commands:

```text
composer-remediate plan
composer-remediate audit
composer-remediate db:status
composer-remediate db:update
composer-remediate db:list
composer-remediate db:use <version>
composer-remediate explain <advisory-id>
```

The project should avoid excessive CLI surface area before the remediation engine is stable.

A minimal v0.1 might expose only:

```text
plan
db:update
db:status
```

---

## 20. Exit codes

CI behaviour should be deterministic.

Potential initial scheme:

```text
0  no vulnerable dependencies detected
1  vulnerable dependencies detected, remediation available
2  vulnerable dependencies detected, no verified remediation found
3  analysis/configuration error
4  advisory database unavailable or invalid
5  Composer solver failure / incompatible environment
```

This should be finalized only after real CI use cases are tested.

---

## 21. Security of the tool itself

Because the project participates directly in dependency-remediation decisions, its own supply chain must be treated carefully.

Requirements should include:

- signed database artifacts;
- reproducible or auditable database build process;
- pinned build dependencies where practical;
- release checksums;
- provenance metadata;
- no automatic execution of arbitrary commands from advisory data;
- careful handling of malicious package metadata;
- temporary-directory isolation during solver experiments;
- no mutation of the user's project during `plan` mode.

Longer term, release provenance and signed software artifacts should be considered for the CLI itself as well.

---

## 22. Testing strategy

The remediation engine will live or die on fixture quality.

### 22.1 Unit tests

Unit-test:

- advisory normalization;
- alias resolution;
- range evaluation;
- graph traversal;
- root-control detection;
- candidate scoring;
- database queries;
- conflict handling.

### 22.2 Historical vulnerability fixtures

The most important tests should be real historical Composer dependency graphs.

Each fixture freezes **both** the advisory snapshot and the package metadata: it carries a static
Composer repository (`repo/packages.json`, served via a `file://` URL with packagist.org disabled)
holding every version the solver may consider, an `advisories.json` in the Packagist API shape, the
platform (`config.platform`) to resolve against, and an `expected.json` with the command a competent
human would run. Without frozen metadata the "smallest upgrade" changes whenever upstream publishes
a release. `bin/build-fixture.php` produces fixtures from a real project.

For example:

- Drupal projects;
- Symfony applications;
- Laravel applications;
- packages with vulnerable direct dependencies;
- packages with vulnerable transitive dependencies;
- packages with multiple parents;
- vulnerabilities requiring parent upgrades;
- vulnerabilities requiring framework upgrades;
- vulnerabilities with no currently valid fix.

Each fixture should record the remediation a competent human would choose.

The engine's output should be compared against that expected result.

### 22.3 Solver regression matrix

The project should eventually test against multiple Composer versions and relevant PHP versions.

Composer behaviour itself evolves, so solver integration must be regression-tested.

---

## 23. Initial proof-of-concept milestone

Before investing heavily in packaging, branding, or OWASP project submission, prove the remediation algorithm.

Suggested milestone:

> Collect five real historical vulnerable Composer lockfiles and automatically generate the same minimal remediation a competent human would choose for at least four of them.

The five cases should include:

1. direct dependency, safe version already permitted;
2. transitive dependency, safe version already permitted;
3. transitive dependency requiring direct parent upgrade;
4. deep transitive dependency requiring framework/root package upgrade;
5. no valid safe resolution under current platform constraints.

If the prototype handles these convincingly, the project has a meaningful technical core.

---

## 24. Suggested implementation phases

### Phase 0 — research prototype

- ddev environment, CI, documentation site with decision records;
- fixture harness with frozen package metadata and advisory snapshots;
- dependency paths, advisory matching (including `replace`), candidate generation as commands,
  in-process solver validation, lowest-parent-version descent, deterministic ranking, text output;
- `composer remediate` plugin command;
- five real historical fixtures; go/no-go gate: the planner reproduces the human choice for at
  least four.

### Phase 1 — deterministic single-finding remediation (release 0.1)

- hardening, classified solver failures;
- JSON output with reproducibility metadata;
- merge per-finding commands into one combined command and re-verify;
- `--offline`, `--ignore`, `config.audit.ignore` / `config.policy` support;
- Composer 2.4 as the runtime floor (2.9 for `-m`), PHP 8.1+;
- first Packagist release.

### Phase 2 — advisory database: build locally, share centrally

- source adapters (OSV, FriendsOfPHP, Packagist API, private overrides);
- normalization, aliases, deduplication, conflict flags;
- `remediate db:build` producing a local SQLite file; `--database-location` to use a shared one;
- reference shared instance: signed artifacts, latest manifest, publish-on-change pipeline.

### Phase 3 — practical ecosystem support

- Drupal fixture corpus;
- Symfony fixture corpus;
- Laravel fixture corpus;
- Composer version matrix;
- CI integration;
- local/private advisories.

### Phase 4 — global planning

- combine multiple findings;
- deduplicate overlapping remediations;
- rank graph-wide candidate plans;
- identify one upgrade that fixes several advisories.

### Phase 5 — optional automation

Only after the planner is trustworthy:

- optional `--apply` mode;
- generated patch for `composer.json`;
- lockfile update in an isolated branch/worktree;
- rollback guarantees.

---

## 25. Potential future extensions

These should remain explicitly secondary to the core remediation engine.

Possible future capabilities include:

- reachability hints;
- VEX generation;
- SBOM integration;
- IDE integrations;
- pull-request bots;
- package-maintainer mode;
- policy rules;
- organisation-specific severity overrides;
- advisory confidence scoring;
- explanation of why no safe remediation exists;
- comparison of multiple safe strategies;
- historical as-of analysis;
- integration with OSV, GitHub, or commercial SCA export formats.

The project should resist expanding into generic AppSec functionality unless it directly improves Composer remediation.

---

## 26. Positioning

The project should consistently describe itself around remediation rather than scanning.

Recommended language:

> **A local, open-source Composer vulnerability remediation planner that traces vulnerable dependencies to the packages you control and uses Composer's solver to identify the smallest verified upgrade that removes them.**

Short form:

> **From vulnerable dependency to verified Composer fix.**

The distinction should remain clear:

```text
composer audit
    ↓
what is vulnerable?
    ↓
Composer Remediation Planner
    ↓
what should I change, and can Composer prove it works?
```

---

## 27. Initial success criteria

The project is worth continuing if the first serious prototype can demonstrate all of the following:

- identify vulnerable locked dependencies accurately;
- explain the full dependency path;
- distinguish direct and transitive control;
- identify the dependency that must actually change;
- generate more than one valid candidate where appropriate;
- use Composer to prove whether each candidate resolves;
- reject candidates that leave the vulnerability present;
- consistently rank the lowest-impact solution first;
- run without sending project dependency information off-machine;
- reproduce results against a pinned advisory database artifact.

If these are achieved, the project is more than another security wrapper. It becomes a genuine Composer remediation engine with a clear technical niche.
