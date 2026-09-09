# Advisory database

By default `composer remediate` asks the configured repositories (Packagist) for advisories, the
same request `composer audit` makes. The advisory database is the alternative: a single SQLite file
built from live sources that you can keep locally, share inside a team, or download from a URL. It
makes runs fully offline, lets you pin the advisory state for reproducible results, and lets you add
private advisories.

## Build it

```bash
composer remediate:db-build
composer remediate:db-build --output=advisories.sqlite --source=osv --source=friendsofphp
```

Sources (all three by default):

| Source | What is fetched | Notes |
|---|---|---|
| `packagist` | Packagist's full advisory dump (`/api/security-advisories/?updatedSince=1`) | Aggregates FriendsOfPHP and GitHub; already keyed by package |
| `osv` | OSV's Packagist ecosystem archive (`all.zip`, ~10 MB) | Structured ranges and aliases; includes withdrawals |
| `friendsofphp` | The FriendsOfPHP/security-advisories repository (zip of the default branch, or `--friendsofphp-path` for a local checkout) | Per-branch version ranges in YAML |

The build normalises every range to a Composer constraint, merges records that share an identifier
(CVE, GHSA, PKSA, FriendsOfPHP file path), keeps every source's range, and flags packages on which
sources disagree (compared semantically, so `>=7,<7.4.4` and `>=7.0.0,<7.4.4` agree). It never merges on
fuzzy matches: false deduplication is worse than duplication.
Where sources disagree, matching uses the union of their ranges: a version any source calls affected
is treated as affected.

The default output path is `<composer cache dir>/remediate/advisories.sqlite`. A build takes well
under a minute and the file is a few megabytes.

### Private advisories

Advisories for internal packages, or for public packages your organisation assesses differently, go
in a JSON file in the Packagist API shape and are merged into the build with `--include`:

```json
{
  "advisories": {
    "company/internal-package": [
      {
        "advisoryId": "COMPANY-2026-001",
        "affectedVersions": "<2.1.4",
        "title": "Authentication bypass in the admin module",
        "link": "https://intranet.example/security/COMPANY-2026-001",
        "severity": "high",
        "reportedAt": "2026-01-15 10:00:00"
      }
    ]
  }
}
```

```bash
composer remediate:db-build --include=security/private-advisories.json
```

A private record that carries a public identifier (a `cve` field, or a GHSA id in `sources`) merges
with the public record for that advisory; otherwise it stays separate. The `source` table records it
as `local:<file name>`.

## Use it

```bash
composer remediate --database-location=advisories.sqlite
composer remediate --database-location=https://example.org/security/advisories.sqlite
REMEDIATE_DATABASE=/srv/advisories.sqlite composer remediate
```

Or per project in `composer.json`:

```json
{
  "extra": {
    "remediate": {
      "database": "https://example.org/security/advisories.sqlite"
    }
  }
}
```

Precedence: `--database-location`, then `REMEDIATE_DATABASE`, then `extra.remediate.database`. A URL
is downloaded into Composer's cache directory and refreshed when the copy is older than 24 hours;
with `--offline` the cached copy is used as is.

`composer remediate:db-status` shows where the database comes from, when it was built, which
sources contributed how many records, and the dataset hash.

## Sharing a database

The file is portable. A team builds it once (a scheduled CI job, for example), puts it on any web
server or release page, and every developer and pipeline points at the URL. Publish a new file only
when the **dataset hash** changes: it covers identifiers, aliases, ranges and withdrawals, but not
fetch timestamps, so an unchanged advisory set produces the same hash across builds.

### The reference instance

This project publishes a database built the same way, refreshed hourly and released **only when the
dataset hash changes**, as GitHub releases named `db-YYYY-MM-DD.HH` (a `.N` suffix disambiguates
several publications within one hour). A moving pointer release, `advisory-db-latest`, always holds
the newest files:

```text
https://github.com/hexblot/composer-remediate/releases/download/advisory-db-latest/advisories.sqlite
https://github.com/hexblot/composer-remediate/releases/download/advisory-db-latest/latest.json
https://github.com/hexblot/composer-remediate/releases/download/db-2026-09-09.15/advisories.sqlite
```

Pin the dated URL in CI configurations that must be reproducible; use the moving pointer for
convenience. `latest.json` carries `version`, `dataset_hash`, `sha256`, `published_at`, `previous`,
the per-source record counts and fetch times, and the download URL. Because the pipeline runs every
hour but publishes only on change, `published_at` tells you when the data last changed while the
workflow's run history tells you whether ingestion is still healthy; a quiet period and a broken
pipeline look different.

Every published database carries a GitHub build-provenance attestation. Verify a download with:

```bash
gh attestation verify advisories.sqlite --repo hexblot/composer-remediate
sha256sum -c advisories.sqlite.sha256
```

## Data licences

The database is aggregated data, not code, and the project's MIT licence does not cover it. GitHub
Security Advisories and OSV data are published under CC-BY 4.0; FriendsOfPHP/security-advisories
has its own terms in its repository. The `source` table keeps the provenance of every record so
attribution can be reproduced.
