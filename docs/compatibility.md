# Compatibility

A version number is a promise about what will keep working. This page says which parts of the tool
that promise covers, so that "breaking change" is a matter of fact rather than of opinion.

Versions follow [Semantic Versioning](https://semver.org/). A change to anything listed under
[what is covered](#what-is-covered) requires a major release.

!!! note "While the version is 0.x"

    The promise below is not yet in force. Releases before 1.0 may change any of it in a minor
    version, and the [changelog](https://github.com/hexblot/composer-remediate/blob/main/CHANGELOG.md)
    says when they do. The list is published now because it is what 1.0 will commit to, and because
    knowing which surfaces are meant to be stable is useful before they are.

## What is covered

**Exit codes.** `0` no vulnerabilities, `1` vulnerabilities with a verified remediation, `2` at least
one vulnerability without one, `3` tool error, `4` advisory data unavailable, `5` package metadata
could not be fetched. These are what pipelines gate on, so their meanings do not change and no code
is reassigned. A new code may be added in a minor release only for a condition that previously exited
`3`.

**Command names.** `remediate`, `remediate:db-build`, `remediate:db-status` and `remediate:pr-body`.

**Command-line options.** The name of an option, whether it takes a value, and what it does. Adding
an option is a minor release. Removing or renaming one, or changing what a value means, is a major
release, and never happens without the deprecation period below.

**The JSON report.** The document carries a `schema_version` and is described by a published schema.
That schema rejects unknown properties, so a consumer validating strictly would break on a field that
simply appeared; `schema_version` therefore increases on any change to the document's shape,
additions included.

Two URLs, and which you use matters. [`report-v1.schema.json`](schema/report-v1.schema.json)
describes `schema_version` 1 and will not change: pin that one.
[`report.schema.json`](schema/report.schema.json) always describes the version the tool emits today,
so it moves when `schema_version` does. Every report the test suite renders is validated against the
schema, and the two files are checked against each other, so neither can drift from the code or from
the other.

**The other report formats.** SARIF 2.1.0, CycloneDX 1.6 and the GitLab dependency-scanning report
conform to their own specifications. What is promised here is which specification version is emitted,
and that a report validates against it.

**The advisory database, as published.** The SQLite file carries its own `schema_version`, and a
reader refuses a file it does not understand rather than guessing. The download URLs are stable: the
`advisory-db-latest` release keeps serving `advisories.sqlite`, `advisories.sqlite.sha256` and
`latest.json` under the same names, dated releases are never deleted, and the fields already in
`latest.json` keep their names and meanings.

**The GitHub Action.** The names of its inputs and outputs, and what they do.

## What is not covered

**The PHP classes.** Everything under the `Remediate\` namespace is internal. This is a command-line
tool and a Composer plugin, not a library: extend or call into it and a patch release may move the
ground under you. If you want a stable interface, run the command and read the JSON report.

**What the tool recommends.** Which command comes back, and whether a finding has a fix at all,
depends on the advisory data and on Composer's resolver. Both move. A different recommendation for
the same lock file next week is the tool working, not a compatibility break.

**Anything written for a person to read.** The text and HTML reports, their wording and layout, the
progress lines on the error stream, and the exact phrasing of warnings. Parse the JSON report
instead; that is what it is for.

**Where files are kept inside the cache directory,** apart from the database path you configure
yourself.

## Deprecation

An option or behaviour that is going away is deprecated first, in a minor release, and keeps working.
Using it prints a warning naming what to use instead, and the changelog entry says the same. It is
removed no sooner than the next major release. Nothing covered above is removed without that period.

A security fix is the exception. If a behaviour is unsafe it is changed as soon as there is a fix,
in whatever release carries it, and the changelog says plainly what changed and why.
