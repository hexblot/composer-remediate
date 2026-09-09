# Composer Remediation Planner — Product Pitch

## The problem

Composer already tells developers when a dependency is vulnerable. That is useful, but it stops at the point where the hard question begins:

> **What exactly should I change to remove the vulnerability with the smallest safe impact on the dependency graph?**

For direct dependencies, the answer may be obvious. For transitive dependencies, it often is not. A vulnerable package may be several layers deep, pinned by constraints that the application does not directly control. Updating the vulnerable package itself may be impossible, unsafe, or simply wrong.

Existing Composer security tooling is strong at **detection**. The missing layer is **remediation planning**.

## The idea

Build a free, open-source, local-first remediation engine for Composer projects, delivered as a
Composer plugin (`composer remediate`) so it runs inside the user's own Composer with their
repositories, authentication and platform configuration.

The tool will:

- consume `composer.json` and `composer.lock`;
- identify vulnerable direct and transitive dependencies from one or more advisory sources;
- trace each vulnerable package back to the nearest dependency the project can actually control;
- determine which candidate upgrades can remove the vulnerability;
- use Composer's own dependency solver to validate those candidates;
- rank valid solutions by minimum blast radius;
- explain the result in Composer-native terms;
- produce the exact remediation command a developer can run.

The goal is not to replace `composer audit`.

The goal is to start where `composer audit` ends.

## Example

A conventional scanner reports:

```text
symfony/http-foundation 6.4.21 is vulnerable
CVE-2026-XXXXX
Fixed in >=6.4.24
```

The remediation planner should instead produce something closer to:

```text
Vulnerability
  CVE-2026-XXXXX

Affected package
  symfony/http-foundation 6.4.21

Dependency path
  root
  └── drupal/core-recommended 11.4.2
      └── symfony/http-foundation 6.4.21

Analysis
  The vulnerable package is transitive.
  Its current parent constraint does not permit a safe release.

Lowest-impact valid remediation
  drupal/core-recommended 11.4.2 -> 11.4.3

Verified result
  symfony/http-foundation 6.4.21 -> 6.4.24
  3 packages changed
  0 packages removed
  0 root constraints added
  vulnerability removed

Recommended command
  composer update drupal/core-recommended -W -m
```

The difference is fundamental:

**Detection says what is wrong. Remediation planning says what to do about it.**

## Why this is interesting

The Composer ecosystem already has mature components for most of the difficult primitives:

- dependency metadata;
- lockfiles;
- constraint resolution;
- vulnerability feeds;
- Composer's dependency solver;
- native security auditing.

What appears to be missing is a focused tool that combines those pieces into a verified remediation workflow.

This makes the project technically meaningful without requiring another vulnerability database, another PHP static analyzer, or another generic SCA scanner.

## Core principles

### 1. Local-first

All analysis runs locally. No third party sees the dependency graph; there is no service, account
or telemetry.

Network use is exactly what `composer update` itself would perform against the repositories the
project already uses: Composer's solver needs package metadata for the versions it considers, and
the default advisory lookup sends package names (not versions) to Packagist, as `composer audit`
does. A strict `--offline` mode refuses any network access and works when Composer's cache is warm
or a local advisory database is used.

### 2. FOSS

The complete tool, remediation engine, database format, build pipeline, and advisory compiler should be open source.

No cloud dependency. No telemetry requirement. No account. No gated enterprise-only remediation logic.

### 3. Advisory-source neutral

The engine should not depend on a single vulnerability feed.

Potential sources include:

- FriendsOfPHP Security Advisories;
- OSV;
- GitHub Security Advisories;
- Packagist / Composer advisory data;
- custom organisational advisory feeds.

Sources are normalized into a common local database before analysis.

### 4. Solver-backed recommendations

The tool should not merely infer that an upgrade *ought* to work.

Candidate remediations should be validated using Composer's own dependency solver wherever possible.

A recommendation should therefore mean:

> **This proposed dependency graph resolves successfully and removes the affected version.**

### 5. Minimal blast radius

Several valid fixes may exist.

The tool should prefer the smallest safe change, taking into account factors such as:

- number of changed packages;
- number of root dependencies changed;
- major-version movement;
- removals or replacements;
- constraint changes;
- framework-level upgrades;
- total graph churn.

### 6. Explain before automating

Initial releases should recommend, not modify.

A first-class command might be:

```bash
composer-remediate plan
```

Automatic mutation can come later, once the planner has proven reliable.

## Advisory database: build it yourself, or share one

Advisory data is pulled from live sources (Packagist, OSV, FriendsOfPHP, private feeds) and compiled
locally into a SQLite database. Because the result is a single portable file, a team or the project
itself can publish it and users point at a shared copy with `--database-location` instead of
rebuilding on every run.

The project's own published database is the reference instance of that sharing model: a build
pipeline polls upstream sources frequently, normalizes and deduplicates records, signs the file, and
publishes a new artifact only when the canonical dataset changes.

Example versions:

```text
db-2026-01-01.01.sqlite
db-2026-01-01.01.1.sqlite
db-2026-01-07.22.sqlite
```

Normal releases use:

```text
YYYY-MM-DD.HH
```

Emergency rebuilds or hot patches within the same hour use:

```text
YYYY-MM-DD.HH.N
```

The default `.0` is omitted.

A `latest` manifest or alias points to the newest published database.

The important semantic rule is:

> **A database release exists only when the normalized advisory dataset changes.**

No duplicate hourly artifacts need to be published when upstream data is unchanged.

## Strategic position

The project should not position itself as:

- a PHP vulnerability scanner;
- a Composer audit replacement;
- a static analysis tool;
- a new advisory database.

A better description is:

> **A local, open-source Composer vulnerability remediation planner that traces vulnerable dependencies to the packages you control and uses Composer's solver to identify the smallest verified upgrade that removes them.**

## Why it could matter

A successful project would fill a gap between vulnerability detection and actual developer action.

That gap is highly visible during real incident response, CI failures, dependency maintenance, and framework upgrades.

It also creates a strong technical identity around a problem that is narrow enough to own, useful enough to attract adoption, and deep enough to support continued development, research, articles, and conference talks.

The best outcome is not necessarily that the project remains forever separate from Composer or other tooling.

If its remediation model is eventually adopted upstream, that would still validate the work and establish the project as the place where the problem was solved first.
