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

### Exploit data: EPSS and CISA KEV

Every CVE in the database is enriched at build time with two facts that say how urgent it is, not
how severe it is labelled:

| Feed | What it says | Source |
|---|---|---|
| `epss` | [EPSS](https://www.first.org/epss/): the probability (0 to 1) that the CVE is exploited in the next thirty days, and its percentile among all scored CVEs | FIRST, refreshed daily (`epss_scores-current.csv.gz`) |
| `kev` | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog): the CVE is confirmed exploited in the wild, since the listed date | CISA's JSON catalogue |

Both are on by default; `--enrich=none` skips them, `--enrich=epss` or `--enrich=kev` keeps one, and
`--epss-file` / `--kev-file` read a downloaded copy instead of fetching. Only the CVEs that the
database's advisories name are stored, so the file grows by a few kilobytes. A feed that cannot be
fetched does not fail the build: the database is written without it, the reason is stored in its
metadata (`enrichment_errors`) and `remediate:db-status` shows it.

Reports use the data in three ways: findings are **ordered by urgency** (known exploited first, then
by EPSS, then by severity label; development-only findings stay last), each advisory line shows
`EPSS 0.93 (97th percentile); listed in CISA KEV since …`, and the summary counts the packages with a
KEV-listed advisory. The JSON report carries `epss`, `epss_percentile` and `kev_added` per advisory,
SARIF tags KEV-listed rules `known-exploited`, and the CycloneDX SBOM attaches the values as
properties. A database built without exploit data (or before this feature) still works; findings
are then ordered by severity alone and the report's advisory source says `no exploit data`.

The dataset hash that decides whether the [reference instance](#the-reference-instance) republishes
includes which CVEs are KEV-listed (a new listing changes what to fix first) but not EPSS scores,
which drift daily for most CVEs. Build locally when you need today's scores.

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
sources contributed how many records, the dataset hash, the exploit data it carries, and the
coverage gaps.

### Coverage gaps

Upstream data is not always readable: an OSV record may use a version scheme Composer cannot parse,
a FriendsOfPHP file may fail to parse, a Packagist entry may carry an affected range that is not a
constraint, or a package's whole entry may be something other than a list of advisories. The build
does not drop such data silently. Each failure is stored in the database as a **coverage gap** with
its source, identifier, the package it names and the reason. This includes the partial case: an OSV
record naming several packages is kept for the packages whose ranges can be read, and a gap is
recorded for each package whose range cannot. `composer remediate` prints a warning for every gap
that names a package in the lock (or a package the lock replaces or provides), and
the package is treated as unaffected by that record, and the report says so. A lock with such gaps
and no findings exits `4` (advisory data unavailable) rather than `0`: the source cannot vouch for it.
`--accept-coverage-gaps` restores exit `0` once the gaps have been read; the JSON report carries
`coverage_gaps` and `coverage_gaps_accepted`. `remediate:db-status` lists the gaps. Databases built
before gap tracking existed are flagged as such and count as a gap; rebuild them.

Private advisories are different: a record in an `--include` file that cannot be interpreted fails
the build, the same way an unparsable `--advisories-file` fails a run, because that data is yours to
fix. Every option of both commands is listed
in the [CLI reference](cli-reference.md).

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
sha256sum -c advisories.sqlite.sha256      # the sidecar is `sha256sum` output: digest and filename
```

What the client verifies on its own: when `--database-location` is a URL, the plugin also fetches
`<url>.sha256` and refuses a download whose digest does not match (exit 4). A URL without a sidecar
is refused as well, unless `--allow-unverified-database` is given, in which case the report says the
download was not verified; that outcome is
recorded next to the cached copy, and every later run that reuses the copy repeats the warning, so
the disclosure belongs to the bytes in use rather than to the request that fetched them. The attestation is
**not** checked automatically; it is there for `gh attestation verify` in a pipeline step, and the
trust the client places in a URL is the trust in TLS plus the publisher's checksum, nothing more.
The sidecar comes from the same host as the database, so it proves integrity in transit, not the
publisher's identity. For a database you do not publish yourself, pin the digest you trust with
`--database-sha256=<hex>`: the download and every later cached copy are checked against it, the
sidecar is not consulted, and a mismatch is fatal. Only `https://` URLs are downloaded; a plain
`http://` location, whether from the option, the environment or `composer.json`, is refused.

Cached downloads are refreshed after 24 hours. When the refresh fails (feed down, network error) the
cached copy is still used, but the report carries a warning with the age of the copy so a stale
database is never mistaken for current coverage. `--offline` uses the cache unconditionally and warns
in the same way.

## Data licences

The database is aggregated data, not code, and the project's MIT licence does not cover it. GitHub
Security Advisories and OSV data are published under CC-BY 4.0; FriendsOfPHP/security-advisories
has its own terms in its repository. The `source` table keeps the provenance of every record so
attribution can be reproduced.
