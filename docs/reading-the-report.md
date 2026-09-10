# Reading the report

Every format (text, HTML, JSON, SARIF, CycloneDX, GitLab) carries the same content. This page walks
through the text report section by section and defines the terms that appear in all of them.

## Header and warnings

```text
Composer Remediate — 2 findings in /srv/app
Advisories: advisories from packagist.org
Solver: in-process Composer 2.10.3 dry-run (fallback: `composer update --no-install` in a scratch directory)
Warning: ...
```

The header names the advisory source and the solver route, so a report can be reproduced. Warnings
are conditions that make the result weaker than it looks and deserve a reader's attention before the
findings do:

| Warning starts with | Meaning |
|---|---|
| `Advisory source "…" only knows advisories for the current lock` | The source was a `composer audit` dump; candidate locks could not be checked for other advisories. |
| `N advisory matches ignored per configuration` | `--ignore`, `config.audit.ignore` or `config.policy` suppressed findings. |
| `Ignore hygiene: …` | Ignore entries that match nothing in this lock; stale configuration. |
| `Coverage gap: …` | An advisory database record about a locked package (or one it replaces or provides) could not be interpreted when the database was built; the package is treated as unaffected by that record. A lock with gaps and no findings exits `4`, not `0`, unless `--accept-coverage-gaps` is given. See [Advisory database](advisory-database.md#coverage-gaps). |
| `Advisory database refresh failed …` / `Offline: using the advisory database cached …` | The advisories are older than the run; their age is given. |
| `… was downloaded without a published sha256 …` | The database in use was never verified against a checksum. |
| `<package>: the recommended command moves … to a version that still carries another advisory` | Blocking risk, see below. |

A gate that wants to be strict about any of these can read the `warnings` array of the JSON report.

## One finding

```text
CVE-2024-45411
────────────────────────────────────────────────────────────
Affected
  twig/twig v3.10.3
  CVE-2024-45411 (PKSA-6319-ffpf-gx66): Twig has a possible sandbox bypass
    https://github.com/advisories/GHSA-6j75-5wfj-gh66
    affected versions: >=1.0.0,<1.44.7|>=2.0.0,<2.16.0|>=3.0.0,<3.11.0|>=3.12.0,<3.14.0
Introduced by
  root
  └── drupal/core-recommended 10.3.1
      └── twig/twig v3.10.3  (requires ~v3.10.2)
Current state
  Transitive dependency.
Recommended remediation
  drupal/core-recommended 10.3.1 -> 10.3.4
  twig/twig v3.10.3 -> v3.14.0
Composer validation
  PASS  3 packages changed, 0 added, 0 removed, 0 root constraints changed
Expected changes
  drupal/core 10.3.1 -> 10.3.4
  drupal/core-recommended 10.3.1 -> 10.3.4
  twig/twig v3.10.3 -> v3.14.0
Recommended command
  composer update drupal/core-recommended:10.3.4 -W -m
Other candidates
  rejected: composer update twig/twig
      resolves, but twig/twig ends at v3.10.3 which is still affected by CVE-2024-45411
```

- **Affected**: the locked package and every advisory on it. Several advisories on one package are
  always handled together; the command must escape all of them. `(replaces x/y)` after the package
  means the advisory is about a package this one replaces or provides. With an
  [advisory database](advisory-database.md#exploit-data-epss-and-cisa-kev) carrying exploit data, an
  advisory line is followed by `EPSS 0.93 (97th percentile)` and, when CISA lists the CVE as exploited
  in the wild, `listed in CISA KEV since 2026-02-01`; findings are ordered by that urgency, so the
  first finding in the report is the one to fix today.
- **Introduced by**: the dependency paths from the root package down to the vulnerable one, with
  the constraint each link places on the next. Up to five paths are printed; the JSON report has up
  to ten and the total count.
- **Current state**: direct or transitive, and whether it is a development requirement only. An
  **Abandoned** line follows when Packagist marks the vulnerable package or a package on its
  dependency path abandoned, with the replacement Packagist names: an abandoned parent will not ship
  the release that lifts its pin, and an abandoned vulnerable package will not ship a fix.
- **Recommended remediation**: what moves. For a transitive package this names the parent that is
  updated and the version the vulnerable package lands on.
- **Composer validation**: `PASS` means Composer's own solver resolved the command in a dry run and
  the resulting lock no longer contains the advisory. This line also counts changed, added and removed
  packages and any root-constraint change, and flags a major version change.
- **Expected changes**: the full lock diff the command produces (first thirty entries).
- **Recommended command**: the exact command to run. It is the request that was verified, including
  any `--with` constraint, `-m`, and platform flags the analysis was run with.
- **Other candidates**: what else was tried and why it lost or was rejected, with the solver's own
  explanation. Candidates listed as "not tried" were skipped because a better one already existed or
  the solve budget ran out.

Notes that may appear between remediation and validation:

- **Constraint drag**: the only fix requires widening a constraint in `composer.json`; the note names
  the root requirement that blocks every fix within the current constraints and the constraint the
  recommendation widens it to. The command then starts with `composer require --no-update …`.
- **Blocking risk**: the command moves a package to a version that still carries another, already
  present, advisory. Composer 2.10 and newer refuse such updates by default (advisory blocking); the
  command may need that advisory ignored in `config.policy` or blocking disabled to run.
- **Note: installs pre-release versions**: no stable release satisfies the constraints yet.

## When there is no fix

```text
Recommended remediation
  No verified remediation found (none).
```

The word in parentheses is the outcome, and it matters for gating:

| Outcome | Meaning | Exit code |
|---|---|---|
| `none` | Every candidate was solved and none removes the advisory within the current metadata. Usually a platform or constraint bound; the rejected candidates say which. | 2 |
| `none found within the search budget` | `--max-candidates` or `--solve-budget` cut the search short. A fix may exist outside the bounded search; raise the limits to look further. | 2 |
| `unknown: solver error` | At least one solve failed inside Composer. The absence of a fix is not established. | 3 |
| `unknown: network failure while solving` | Package metadata could not be fetched. Retry, or warm the cache. | 5 |

A finding without a fix is never silently equal to a finding with no vulnerability: exit code 2 is
only returned when the search completed.

## Summary

```text
Summary
  Findings: 2 advisories on 2 packages, 2 with a verified fix
  You can fix all 2 findings with:
    composer update symfony/http-foundation symfony/process
    (2 packages changed, verified by Composer)
  Gate: --fail-on high, 1 of 2 packages count towards the exit code (1).
```

The summary merges the per-package winners into one command and verifies it with a further solve.
It reads "You can fix all N findings with …", or "… fixes k of N findings" when some have no reachable
fix, or lists per-package commands when no single command resolves. `[baselined]` marks packages
accepted through `--baseline`; the Gate line shows how `--fail-on` and the baseline shaped the exit
code.

## Exit codes

| Exit | Meaning |
|---|---|
| `0` | No known vulnerabilities in the lock (after `--fail-on` and baseline), and no coverage gap about a locked package unless `--accept-coverage-gaps` was given |
| `1` | Vulnerabilities found and every gated one has a verified fix |
| `2` | At least one gated vulnerability has no verified fix, and every solve completed |
| `3` | Tool error: no lock file, bad option, or a solver error left an outcome unknown |
| `4` | Advisory data unavailable: the source could not be read or fetched, an incomplete source cannot verify candidates, or records about locked packages could not be read (coverage gaps) and were not accepted |
| `5` | Package metadata could not be fetched while solving |

## The same content in other formats

- **JSON** (`--format=json`, `--output=x.json`): one object per finding with `remediation.status`
  (`verified` or `none`), `remediation.outcome`, `remediation.command`, `remediation.blocking_risk`,
  `constraint_drag`, the full `candidates` list, `solver_runs` and `search_exhausted`; the `summary`
  block carries the combined command and the gate counts; `warnings` is the list above. The schema is
  published at `docs/schema/report.schema.json`.
- **HTML** (`--output=x.html`): a self-contained page with the same sections, a summary table and
  collapsible candidate lists; advisory links are anchors only for `http(s)` URLs.
- **SARIF** (`--output=x.sarif`): one rule per advisory, one result per vulnerable package located
  at its `composer.lock` line, the recommended command in the message. For GitHub Code Scanning.
- **CycloneDX** (`--output=x.cdx.json`): the lock as an SBOM with vulnerabilities and their
  recommendation attached.
- **GitLab** (`--output=gl-dependency-scanning-report.json`): the dependency-scanning report format
  for GitLab's security dashboard, solution field holding the command.

`--format` selects what goes to standard output; `--output` writes files and can be repeated. See
[CI integration](ci-integration.md) for how to gate on these.
