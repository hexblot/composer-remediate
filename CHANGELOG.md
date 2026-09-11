# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

Answers to a fourth adversarial adoption review (ten findings at c545e91, reproduced by the reviewer
with a separate harness), each with a regression test.

- **A scan never writes outside the checkout being scanned unless the operator asked.** The
  analysed project's `extra.remediate.database_path` must be a relative path inside the project (a
  parent that is a symbolic link out of it does not count); an absolute or escaping path is exit 3.
  A file at the database path that is not an advisory database is never replaced, and a download is
  validated as an advisory database before it is moved into place, so matching-checksum arbitrary
  content from a project-chosen source cannot land on disk. Before, an existing non-database file was
  treated as replaceable and the bytes were renamed into place unvalidated.
- **A project cannot poison the shared database.** A source chosen by the project's `composer.json`
  is kept in a file of its own under the cache directory and the report says the project chose it; a
  copy downloaded from one source is never accepted as current for another, whatever its build time
  says (the status file records the source); a local build that claims a build time in the future is
  not current either. Before, an empty database from one source passed as "confirmed current" for a
  second source through the newer-build rule.
- **`--database-sha256` constrains every path that selects a database**, including a local file
  named as the source, which used to return before the check. A pinned digest also lets a download
  proceed from a source that publishes no digest of its own, verifying against the pin.
- **Private advisories are not lost to a refresh.** A local build whose sources include `--include`
  files is never replaced by a download of the public database, even when that is newer; the report
  says the copy is kept and that public advisories published since are unknown, and
  `remediate:db-build --if-stale` with the same `--include` files is the refresh. `--rebuild-database`
  on `remediate`, which builds with the defaults, keeps such a copy too.
- **A verified fix cannot add a package the source cannot vouch for.** A candidate whose lock adds
  packages (or newly replaced or provided names) with unreadable advisory records is rejected with the
  reason, individually and in the combined command; `--accept-coverage-gaps` allows it and the gaps
  are listed on the recommendation (`coverage_gaps` in the JSON recommendation) and in the plan's gaps.
- **Unattributable records reach every scan.** Coverage gaps the build could not attribute to any
  package (malformed advisory containers) are part of every gap query and are reported with a warning
  that any package in the lock may be affected; a lock without findings exits 4 unless accepted. Before,
  scan-time queries selected only named packages and discarded them.
- **Coverage gaps are part of the dataset hash**, so a build whose gaps changed is published and a
  local copy with different gaps is not declared current. Before, only advisories and KEV listings
  hashed.
- **The exit code counts the combined command.** A finding without a standalone fix that the
  combined command fixes (a parent update removing the vulnerable child) no longer yields exit 2 when
  every finding is fixed by that command.
- **GitLab reports fail honestly.** `scan.status` is `failure` for exit 3, 4 and 5 and
  `scan.messages` carries the reason and every report warning, so an empty vulnerability list from a
  scan that could not establish coverage no longer reads as a clean result on the dashboard.
- **Recheck (six findings at a031e4a).** Content at a path the analysed project chose counts only
  when its bytes match what the publisher serves: no dataset-hash or newer-build acceptance, no
  private-build protection, no use during an outage (a checked-in empty database no longer passes as a
  newer local build). A dataset hash only counts for a local build or a copy downloaded from the same
  source, so an untrusted publisher copying a trusted publisher's hash into its metadata no longer
  survives a source switch; a copy downloaded from a source that is not configured is not used as the
  outage fallback either. Building a database over a downloaded copy retires the download's status
  record (and a status record older than the database is ignored), so a private rebuild at the shared
  path is protected from the first rebuild. The exit code counts the combined command per gated
  finding, so `--fail-on` and baselines no longer turn a fully fixed gate into exit 2. The
  project-source disclosure redacts URL credentials. Path confinement is checked before any directory
  is created, and a symbolic link anywhere on the way is rejected. The schema and the report guide say
  that `none` and `unsolved_findings` describe standalone remediation and that the combined command may
  still fix such a finding.
- **Third recheck (one finding at b8bf552).** Which configuration counts as the operator's is now
  decided from configuration the analysed project never contributed to (`Factory::createConfig()`:
  environment, the operator's global `config.json`, Composer's defaults). The previous check read
  Composer's merged `config.home`, which the project can set alongside `config.cache-dir`, so a
  repository could hold both sides of the comparison and have its own cache directory accepted as the
  operator's. Alongside it, TLS settings supplied by the project (`cafile`, `capath`, `disable-tls`)
  are reported, since Composer verifies the download with them.
- **Second recheck (two findings at c17b742).** The default database path follows the operator's
  cache configuration, never a `config.cache-dir` set by the analysed project's composer.json (Composer
  records the source of the value; a project file as the source is set aside with a note in the
  report), so a repository cannot pre-fill the default path. The status record that marks a copy as
  downloaded carries the digest of the bytes it describes and is retired only when the bytes change;
  the previous rule, which compared the database's own build time with the fetch time, let a publisher
  reclassify its download as a local build by writing a later timestamp.
- Documentation brought in line: SECURITY.md describes the download verification and the limits on
  what the analysed project may configure; the privacy promise names the publisher request and how to
  stop it; the report guide lists the new warnings.
- **An end-to-end test of the database's life** (`tests/Integration/DatabaseLifecycleTest.php`)
  runs the real command against a real HTTPS publisher (a PHP TLS server with a generated certificate,
  trusted through Composer's `cafile`) and asserts exit code, report warnings, provenance line, the file
  on disk and the publisher's request log together, through download, confirmation, replacement, an
  outage, a pinned digest and a project-chosen source. Its first run found that a downloaded copy whose
  publisher had used `--include` was mistaken for a local build with private advisories and kept
  instead of replaced; fixed (the protection applies to local builds only).

### Changed

- **The advisory database is the default source, kept current at a fixed path.** A run without
  options keeps a copy of the database this project publishes at
  `<composer cache dir>/remediate/advisories.sqlite` and checks it on every run against the
  publisher's `latest.json` (or `.sha256` sidecar): a copy with the same sha256 or dataset hash, or a
  newer local build, is used as it is; a missing or stale copy is replaced by a verified download.
  When the source cannot be reached the copy is used and the report says how old it is; when there
  is no copy at all the configured repositories are asked, as `composer audit` does, with a warning.
  Path (`--database-path`, `REMEDIATE_DATABASE_PATH`, `extra.remediate.database_path`), source
  (`--database-location`, now also a comma-separated list or a list in `composer.json`, tried in
  order) and `--database-max-age` (fail instead of warn when an unconfirmed copy is older than this)
  are independent settings with their own defaults. `--no-database` (or a source of `composer`)
  selects the repository API directly; a local path as the source is read as it is, as before;
  `--database-sha256` forbids the fallback. `--rebuild-database` on `remediate` and `--if-stale` on
  `remediate:db-build` build from the sources under the same freshness rule, so a CI cache of the
  path works with either. `remediate:db-status` prints the three settings, which are defaults, and
  the verdict; `remediate:db-build` writes to the configured path by default and a build with no
  options reproduces the published database. The hidden per-URL cache under Composer's cache
  directory is gone; the first run after upgrading downloads once into the new path.
  New network behaviour: a plain run contacts github.com once per run (a few bytes, no package names);
  see the privacy page for the three ways to stop it.
- CI: a push to `main` runs one canonical job (PHP 8.4, Composer latest, with PHPStan, Deptrac,
  coverage, badges and the generated-page checks); pull requests run the full PHP and Composer
  matrices, and a manual run has a `full` switch. Releases are cut from pull requests so the tag's
  tree has had the full run. The advisory database is polled every six hours instead of hourly; it is
  still published only when the dataset changed, and clients confirm their copy by content.
- Roadmap: Phase 7, goal-driven planning, added as a candidate after Phase 5, motivated by
  composer/composer discussion 12777 (a TYPO3 major upgrade blocked by a transitive package Composer's
  error never names); the design-decisions page records why a security fix is treated as one goal
  among others.

[Unreleased]: https://github.com/hexblot/composer-remediate/compare/v0.6.1...HEAD

## [0.6.1] - 2026-09-10

A housekeeping release so that a tag sits on a green CI run: the 0.6.0 commit shipped with a stale
generated case-studies page, which failed the PHP 8.4 job's staleness check while every test passed.
Deptrac now classifies third-party code too, and the README gained an architecture badge.

### Fixed

- `docs/case-studies.md` regenerated for the two combined commands that changed in 0.6.0 (BookStack
  socialite and Open Social); the CI check that compares the committed page with a fresh render had
  been failing since the release commit.

### Changed

- Deptrac classifies third-party code as layers of its own (`Semver`, `ComposerPlugin`,
  `ComposerApi`, `SymfonyConsole`, `SymfonyProcess`, `SymfonyYaml`) and each project layer states
  which it may use; the run fails on any dependency left unclassified (`--fail-on-uncovered`), so a
  new library or a new corner of Composer's API has to be allowed deliberately. The report went from
  296 uncovered dependencies to zero, with 468 allowed. The README carries an architecture badge fed
  by the PHP 8.4 CI job ("passing", or "failing (n)"), next to the coverage badge.

- The roadmap page records the assurance work alongside the phases (adversarial review and rechecks,
  the testing sprint, the Aikido answers, Deptrac) and marks Phase 5 as next.

[0.6.1]: https://github.com/hexblot/composer-remediate/releases/tag/v0.6.1

## [0.6.0] - 2026-09-10

A feature release with changed defaults. Global planning (Phase 4) searches for the smallest command
that fixes every finding and explains the search; the answers to an Aikido code scan make incomplete
advisory sources, unverified database downloads and unread coverage gaps fail closed, so exit codes can
differ from 0.5.0 in CI; three CLI options, a `combined_search` block in the JSON summary and Deptrac
layer rules arrive with it. The `Plan::SEVERITIES` constant is gone, replaced by the
`Engine\Advisory\Severity` enum.

### Added

- **Global planning (Phase 4).** The planner now searches for one command that fixes every finding
  with as little change as possible. The per-package winners are merged as before; when that merge
  does not resolve, or fixes only some findings, the search swaps in the next-ranked candidate of a
  finding that is in the way and tries again, within a budget of ten further solves, keeping the
  combination that fixes the most findings, then the smallest diff. A combination that fixes
  everything is then shrunk by dropping, in turn, each contribution whose package a sibling's fix
  already moves, and keeping the smaller command when it still fixes everything: in the BookStack
  socialite fixture `robrichards/xmlseclibs` leaves the command because the `onelogin/php-saml`
  update carries it, and in the Open Social fixture `twig/twig` leaves because the `drupal/core`
  update does. Every attempt is listed in the text and HTML summaries and
  in `summary.combined_search` of the JSON report, with the solver's reason, so the recommended
  command is explained rather than asserted. Tests: a merge that does not resolve until a
  lower-ranked candidate is swapped in, a merge that undoes one finding's fix, a shrink to a parent
  update that covers its sibling, and an exhausted search that keeps the best partial result.

### Changed

- **Structure.** The longest methods were split without behaviour change, after a reader pointed at
  them: `RemediateCommand::execute` now delegates to methods for report targets, runtime checks, the
  advisory source, the planner, gating and output; the global search's bookkeeping moved from the
  planner into `Engine\Plan\CombinedSearch`, with `repair()` and `shrink()` as separate steps;
  `TextRenderer` renders one report section per method; `CandidateGenerator` builds each candidate
  family in its own method; `RangeNormalizer::fromOsv` and `DatabaseWriter::write` are split by stage.
  Severity labels are an enum (`Engine\Advisory\Severity`) instead of a lookup table on `Plan`.
- **Architecture rules.** `deptrac.yaml` states the layers (Plugin → Command → Output → Engine →
  Advisory) and CI checks them on the PHP 8.4 job; `composer deptrac` runs them locally (Deptrac is
  installed under `tools/deptrac`, since it needs PHP 8.2 or newer). The first run found one
  violation, the advisory model reading the severity table from the plan class, which the enum fixes.
- Fixture reports under `tests/Fixture/third-party/*/reports` record the sha256 of the committed
  `composer.fixture.json` rather than of the scratch copy, whose injected repository path differed on
  every run; regenerating a report now yields the same bytes.

### Security

Answers to an Aikido code scan (nine findings), each with a regression test.

- **Incomplete advisory sources fail closed.** A source that only knows the current lock's
  advisories (`composer audit` output through `--advisories-file`, the audit fallback) cannot check a
  candidate lock, so the planner no longer verifies candidates against it: findings are reported with
  a blocker and no remediation, and the run exits 2 instead of recommending fixes verified against
  nothing. Before, the run warned and still reported the fixes as verified.
- **Coverage gaps gate the exit code.** A lock with no findings but with advisory records about
  locked (or replaced/provided) packages that the source could not read exits 4, not 0;
  `--accept-coverage-gaps` restores 0 once the gaps have been read. The JSON summary carries
  `coverage_gaps` and `coverage_gaps_accepted`. Gaps about packages a locked package replaces or
  provides are now reported at all; before, only the locked names were checked.
- **Advisory database downloads must be verified.** A URL without a published `<url>.sha256` and
  without an expected digest is refused; `--allow-unverified-database` restores the old warn-and-
  accept behaviour. `--database-sha256=<hex>` pins the digest the operator trusts, which is checked
  on the download and on every later use of the cached copy, and is the trust anchor for a database
  someone else publishes (the sidecar comes from the same host). Only `https://` locations are
  downloaded, wherever they are configured (option, environment or `composer.json`). Credentials
  embedded in a URL are redacted from every message and from the cache metadata. Symbolic links at
  the cache paths are refused and the cache directory is created private; the status file is written
  atomically.
- **A same-version lock change that moves the commit** (a re-tagged release, not only a moved dev
  branch) is now a change, so the release-age guard refuses it when the date is unknown or too young
  and reports it as one change of unclassifiable size.
- **One advisory id on two replaced components** (a CVE spanning several Symfony components under
  `symfony/symfony`) produced one finding; the finding key now includes the replaced target
  (`advisory@package/target`), so both are reported. Baseline entries for such findings use the new
  key.
- **Console output sanitised.** Advisory titles, links, upstream record ids, solver output and file
  names are stripped of control characters and escape sequences before they reach a terminal, and
  console formatting tags in them are escaped in decorated output (`Remediate\Output\ConsoleText`),
  so a crafted advisory cannot restyle the report or rewrite the line above it. `remediate:db-build`
  and `remediate:db-status` sanitise the upstream text they print.
- The GitLab pipeline verifies the Composer installer against its published signature instead of
  piping the download into PHP.
- The advisory-database release job runs in the `advisory-db` GitHub environment, whose
  deployment-branch policy admits only `main`. A `workflow_dispatch` from another branch executes
  that branch's copy of the workflow file, so no check inside the file (a pinned checkout ref, a
  validated input) can stop an actor with write access from running modified code with the
  release-capable token; the environment policy is enforced by GitHub before the job starts. A
  `github.ref` guard gives a clearer error for an accidental dispatch from a branch.

[0.6.0]: https://github.com/hexblot/composer-remediate/releases/tag/v0.6.0

## [0.5.0] - 2026-09-10

A feature release. The advisory database now carries exploit data (FIRST EPSS scores and CISA's
Known Exploited Vulnerabilities catalogue) and reports order findings by that urgency; abandoned
packages on a dependency path are named; and the Phase 3 fixture corpus is complete with five Drupal
and five Symfony cases, seventeen real historical projects in all. The GitHub workflows were hardened
after a scan.

### Added

- **Exploit data in the advisory database.** `remediate:db-build` enriches every CVE with its FIRST
  EPSS probability and percentile and its CISA KEV listing date (`--enrich`, on by default;
  `--epss-file` / `--kev-file` read local copies). Only the CVEs the database names are stored. A
  feed that cannot be fetched is recorded in the metadata and the build continues without it;
  `remediate:db-status` shows what the database carries. Reports order findings by urgency (known
  exploited first, then EPSS, then severity; development-only findings last), print `EPSS 0.93 (97th
  percentile); listed in CISA KEV since …` under each advisory, and count KEV-listed packages in the
  summary. JSON gains `epss`, `epss_percentile` and `kev_added` per advisory and
  `packages_known_exploited` in the summary; SARIF tags such rules `known-exploited`; CycloneDX and
  GitLab reports carry the values. The dataset hash includes KEV membership (a new listing changes
  what to fix first) but not EPSS scores. Databases built without the data still read; their reports
  say `no exploit data`. Tests: both feeds with scripted downloads and local files, build-to-report
  round trip, a failing feed, hash behaviour, an old database, ordering rules, every output format.
- **Abandoned packages on the dependency path.** When Packagist marks the vulnerable package or a
  parent on its path abandoned (the marker travels in `composer.lock`, so this needs no network), the
  report says so with the replacement Packagist names, under the finding and in the summary; JSON
  gains `abandoned` per finding and `packages_with_abandoned_dependency` in the summary; SARIF,
  CycloneDX and GitLab reports carry the names. The lock snapshot now preserves the marker. Tests:
  planner detection on a scripted lock, every output format.

- **Phase 3 fixture corpus complete: five Drupal and five Symfony cases.** New real historical
  fixtures: Mass.gov on Drupal 10.3 (the meta-package's tilde pins let every November 2024 fix through
  as a plain update; an abandoned Goutte on the path), Open Social's project template (the
  distribution's `~10.2.5` pin permits the Drupal 10.2.9 patch; Twig 3.14 needs a package the lock
  never had), Acquia CMS (Drupal 10.3 without `core-recommended`, a monorepo whose modules come from
  `path` repositories with branch aliases), wallabag (Symfony 5.4 on PHP 7.4: eleven of sixteen
  advisories fixable, Guzzle 5 stuck behind the root constraint and an abandoned adapter) and Mautic 5
  (a monorepo whose own `path` package pins PhpSpreadsheet below the fix). Each carries provenance,
  the reasoning behind the expected command and stored reports; the case-studies page grows with them.
- `bin/build-fixture.php` learned what these projects needed: it fetches the requirement closure of
  every version it keeps (metadata Composer never loaded for the locked graph), takes `path` /
  `artifact` packages from the lock file with their branch aliases and a neutral dist while dropping
  other versions of those names (a path repository takes precedence), splits and retries advisory API
  batches that come back unreadable, and stores fixture manifests as `composer.fixture.json` /
  `composer.fixture.lock`. `expected.json` gained `root_version` for projects whose dependencies
  conflict with the root package by version.

### Security

- GitHub workflows hardened after an Aikido scan: every action is pinned to a commit SHA with its
  version noted (and a Dependabot configuration keeps the pins current); no workflow expression is
  interpolated into a shell script any more, values reach scripts through the environment (the
  `force` input of the advisory-database workflow was the reported template-injection vector); the
  advisory-database workflow's write permissions moved from the workflow to its single job and the CI
  workflow defaults to read; every checkout runs with `persist-credentials: false` (the badge push
  and the release steps use explicit tokens). `bin/run-fixture.php` validates the fixture name before
  building a path from it.

### Changed

- Findings are ordered by urgency (see above); before, they were ordered by package name. The stored
  fixture reports and the case-studies page are regenerated accordingly.
- Test fixtures moved from `tests/Fixture/<name>` to `tests/Fixture/third-party/<name>`, and their
  manifests are stored as `composer.fixture.json` / `composer.fixture.lock`. The fixtures' historical
  lock files are vulnerable on purpose and raised hundreds of Dependabot alerts; GitHub's dependency
  graph parses every `composer.json` and `composer.lock` in a repository whatever the directory (the
  `third-party` name alone did not exempt them), and does not parse the renamed files.
  `bin/build-fixture.php` writes the new layout by default.

[0.5.0]: https://github.com/hexblot/composer-remediate/releases/tag/v0.5.0

## [0.4.2] - 2026-09-10

A correctness release answering the third adversarial recheck. The recheck of 0.4.1 confirmed the six
earlier findings as fixed and reported three new ones, all rated P1; each is fixed here with a test
that reproduces the reviewer's case, and the reviewer's closure pass on these fixes found nothing
further.

### Recheck (third round)

- The `composer audit --locked` fallback wired in 0.4.1 launched its child without `--no-plugins
  --no-scripts`, so Composer activated the analysed project's allowed plugins in that child: the
  compatibility-recovery route broke the plugin boundary the standalone binary exists to keep. The
  child now carries both switches. Covered by an integration test that installs a real plugin whose
  `activate()` writes a marker, shows that a plain `composer audit` does trigger it, and asserts the
  fallback adapter never does.
- OSV `limit` events: the normaliser kept the smallest of several limits and ignored an explicit
  `limit: "*"`. OSV's BeforeLimits predicate accepts a version below *any* limit, so the cap is the
  largest limit and a `*` limit lifts it; the old behaviour truncated genuinely affected versions
  (introduced 1.0.0 with limits 2.0.0 and 3.0.0 lost 2.x). Covered by unit tests for both shapes.
- Coverage gaps: a package whose value in a Packagist-shaped document is not a list of advisories
  (`{"advisories":{"acme/lib":"upstream-error"}}`) was skipped without a gap, so a private
  `--include` file with that shape built a clean database; it is now a gap for that package, which
  fails a private-file build and is retained for public feeds. An OSV record naming several packages
  recorded a gap only when *every* package's range was unreadable; a readable sibling hid the failure.
  The record is kept for the readable packages and a gap is recorded for each unreadable one.
  Covered by mapper, private-file and OSV-source tests.

[0.4.2]: https://github.com/hexblot/composer-remediate/releases/tag/v0.4.2

## [0.4.1] - 2026-09-10

A testing release. The suite grows from 111 to 171 tests and line coverage from 74% to 94%, with
no source file below 75%: the command layer, the advisory feed readers and both advisory adapters,
none of which had a test before, are now covered. Two defects surfaced on the way and are fixed
below, and the `composer audit` fallback that the design had promised since 0.1.0 is wired in.

### Added

- Tests: the command layer, driven through Composer's console application the way `composer
  remediate` runs, against the synthetic fixture. `remediate`: option validation (format, report
  spec, solver, release age), the lock-file check, the exit-code contract including a search budget
  too small to reach the fix, every report file format next to the JSON on standard output,
  `--format=none`, an unwritable report path, `--fail-on`, `--ignore`, the whole `--baseline` /
  `--update-baseline` workflow, `--offline`, advisory-source selection (missing snapshot, missing
  database via option, `REMEDIATE_DATABASE` and `extra.remediate.database`) and platform flags
  repeated in the recommended command. `remediate:db-build` from a local FriendsOfPHP checkout plus
  `--include`, the default build path, an unknown source; `remediate:db-status` on the result
  (metadata, sources, coverage gaps), on a missing file, via the environment variable, and on a
  database built before coverage gaps were recorded. Plugin capability and command registration.
- Tests: the feed readers with a scripted HTTP layer and archives built in the test. `ZipArchiveReader`
  (filtering, directory entries, a body that is not an archive, download failures, cleanup of the
  download); `OsvDumpSource` (alias ranking, ADVISORY reference as link, "MODERATE" mapped to
  medium, published/modified/withdrawn dates, several Packagist packages per document, other
  ecosystems ignored, invalid JSON and unreadable versions as coverage gaps, gaps reset per fetch,
  custom URL); `PackagistApiSource` (mapping, gaps, a body that is not an object, a document without
  `advisories`, transport failures); `FriendsOfPhpSource` from the GitHub archive (aliases, earliest
  branch time, non-Composer advisories skipped without a gap, scalar documents, empty ranges and
  invalid YAML as gaps naming the package from the path). The default advisory adapter
  `ComposerRepositoryAdvisoryProvider` with a fake Composer repository: conversion of full and partial
  advisories, per-package caching and incremental queries, merging across repositories with
  duplicate ids dropped, the failure when no repository provides advisories, transport failures,
  construction from a `RepositoryManager`. The `composer audit` fallback provider with a stand-in
  binary (leading noise before the JSON, one run per process, no JSON, undecodable JSON).
  `NormalizedAdvisory`, `Strategy` and `VersionStep` helpers.

### Changed

- The `composer audit --locked` fallback adapter, described in the design decisions since 0.1.0 but
  never wired in, is now used when Composer's in-process advisory API fails with a PHP error (a
  removed method or changed signature in Composer's `@internal` classes). The run switches once,
  the report's advisory source shows the fallback, and a warning explains that only current-lock
  advisories are known. Lookup failures are not retried through it: no repository providing
  advisories, or a network failure, still exits with "advisory data unavailable" rather than a clean
  result. Composer older than 2.4 is still rejected up front. Covered by unit tests of the switch
  (PHP error switches and warns once, lookup failures and ordinary exceptions propagate, the primary
  is not retried) and a command test that the default source with packagist.org disabled exits 4.

### Fixed

- FriendsOfPHP advisories lost their report date: the upstream files write `time: 2024-05-01 10:00:00`
  unquoted, which the YAML parser hands over as an integer timestamp, and the source only accepted
  text. Integer timestamps are now read, so `reportedAt` is populated for FriendsOfPHP records.
- Test bootstrap: Composer reads `$_SERVER` before `getenv()`, so the cache isolation was lost when
  the environment already exported `COMPOSER_CACHE_DIR` (DDEV does); tests now set both.

[0.4.1]: https://github.com/hexblot/composer-remediate/releases/tag/v0.4.1

## [0.4.0] - 2026-09-10

This release responds to an adversarial adoption review of 0.3.0 (twenty findings, nine rated as
able to undermine a security decision) and to the reviewer's recheck of the first response (six
remaining findings). Each item below names its change; the tests that establish it are listed in the
"Tests" bullets, and where a boundary is documented rather than removed the text says so.

### Recheck (second round)

- The subprocess solver pins `COMPOSER` to the scratch manifest. Before, the child inherited a
  `COMPOSER=/path/alternate.json` from the parent and updated the analysed project's real lock while
  the planner read the untouched scratch lock. Covered by an integration test that runs the real
  Composer binary with `COMPOSER` set to another manifest and asserts that file is unchanged.
- `composer-remediate` never includes any project's `vendor/autoload.php` (Composer's autoloader
  executes `autoload.files`, which is project code). It boots Composer from the phar it finds and
  registers the plugin's own classes through a PSR-4 mapping. Covered by an entry-point test that
  installs the binary in a project whose autoloader plants a probe and asserts the probe never runs.
- Database ingestion keeps coverage gaps: an upstream record the build cannot interpret is stored in
  a `gap` table with source, id, package and reason; `composer remediate` warns for every gap that
  names a package in the lock ("treated as unaffected by that record"); `remediate:db-status` lists
  them; databases built before gap tracking are flagged. A private `--include` file with an
  unreadable record fails the build, matching `--advisories-file`. Database reads use the strict range
  parser; the lenient one is gone.
- OSV events are evaluated per the specification: sorted by version, `introduced` opens an interval,
  the next `fixed`/`last_affected` closes it, and `limit` caps the whole range instead of closing an
  interval of its own. "introduced 1.0, fixed 1.1, limit 2.0" no longer marks 1.5 affected.
- The locator records whether a cached download was verified (`<cache>.status.json`) and repeats the
  disclosure on every cache hit, offline included; caches written by earlier versions are flagged as
  unverified.
- The fixture harness executes the printed command through a shell, verbatim, with a `composer` on
  PATH that adds `--no-install`; quoted constraints are no longer split on whitespace.
- Documentation regrouped by intent (Use it, Understand it, Integrate it, Evidence, Project) with
  three new pages: Reading the report, Comparison with other tools, and Case studies generated from
  the fixture corpus (`bin/case-studies.php`, checked for staleness in CI).

### Added

- `composer-remediate` binary: runs the same commands with the analysed project's plugins and
  scripts disabled from the first instruction, reusing the installed Composer for its classes and
  the fallback solver. `composer remediate` (the plugin command) keeps Composer's usual behaviour of
  activating the project's other allowed plugins at startup; SECURITY.md and the privacy page now
  state both boundaries precisely.
- `--solver=auto|in-process|subprocess`: the documented subprocess fallback is now wired. A
  candidate whose in-process solve errors (not a conflict, not a network failure) is retried through
  `composer update --no-install`; the report's solver line counts the retries.
- `--solve-budget` (default 60): hard ceiling on solver runs per finding across candidates, conflict
  expansion, parent descent and simplification. Every solve is counted; the report shows the count
  per finding (`solver_runs`) and in total, and a bounded search that finds nothing reads "none found
  within the search budget" instead of "none".
- Typed outcomes for findings without a fix: `none`, `none found within the search budget`,
  `unknown: solver error` (exit 3) or `unknown: network failure while solving` (exit 5). A tool
  failure can no longer produce the actionable-policy exit 2.
- `--ignore-platform-req` / `--ignore-platform-reqs` are repeated in every recommended command, so
  the printed command is the request that was verified.
- Blocking-risk note when a recommended command moves a package to a version that still carries
  another advisory (Composer 2.10+ advisory blocking may refuse it).
- Client-side sha256 verification of a downloaded advisory database against the publisher's
  `.sha256` sidecar; a missing sidecar and a stale cache reused after a failed refresh are reported
  as warnings with the cache age.
- `IgnorePolicy`: `config.audit.ignore` entries with `apply: block` and `config.policy.advisories`
  entries with `on-audit: false` no longer suppress findings; package rules are matched as packages
  (with their constraint), not as advisory ids.
- Tests: planner rules with a scripted solver (unknown severity, tool-error and network exits,
  combined-command cooldown, `--no-dev` baseline, all-advisory fixed range, platform flags, blocking
  risk, budget), parser strictness, OSV `versions`/`limit`/event order, ignore scoping, HTML link
  safety, fallback solver composition (with scripted routes), the real subprocess solver, the
  standalone entry point, database download/checksum/cache behaviour with a scripted HTTP layer,
  coverage gaps from build to report; freshly rendered JSON validated against the schema for every
  fixture; the synthetic fixture's recommended command executed verbatim by a shell with the real
  Composer binary and the resulting lock re-matched. Not covered by tests: the CLI driven against a
  live advisory repository, and the Composer 2.4 advisory adapter beyond the CI matrix job.

### Changed

- No advisory-capable repository, a malformed advisory document (an error payload, a malformed
  entry, an unparsable range) now stop the run with exit 4 instead of reading as a clean lock.
  `composer audit --format=json` output passed as `--advisories-file` is recognised as covering the
  current lock only.
- OSV normalisation honours explicit `versions` in addition to `ranges` and the `limit` event.
- Unknown *and unrecognised* severities count towards `--fail-on`.
- The combined command is held to the same rules as individual candidates: no new advisories and
  the `--min-release-age` cooldown; its simplified spelling is re-matched instead of inheriting the
  original's results. Releases without a known date are refused by the cooldown.
- Under `--no-dev` an untouched development finding is no longer counted as "newly introduced" by a
  production fix.
- The fixed range escapes every advisory known for the package, not only those affecting the locked
  version; ignored advisories do not shrink it.
- "Identical lock" for simplification now compares source and dist references and the
  production/development split, not only versions.
- `composerJsonPath()` / `lockPath()` follow `COMPOSER=alternate.json`.
- `--minimal-changes` is documented as a Composer 2.7.0 feature (2.9 extended it), and the subprocess
  solver's threshold follows. Composer older than 2.4 is refused at runtime. The Composer 2.4
  `SecurityAdvisory` class has no `severity` property; the adapter no longer reads it unconditionally.
- HTML reports turn only `http(s)` advisory links into anchors.
- `--min-release-age` rejects non-numeric input instead of coercing it to zero.
- The advisory-database workflow publishes `sha256sum` output (digest and filename) so
  `sha256sum -c` works as documented.
- README no longer claims the smallest fix; the search is bounded and ranked.
- JSON report (schema still version 1, additive): `solver_runs` and `search_exhausted` per finding,
  `outcome` on findings without a fix, `blocking_risk` on verified ones, `solver_runs` in the
  metadata.

## [0.3.0] - 2026-09-09

### Added

- SARIF 2.1.0 output (`--output=results.sarif`, `--format=sarif`) for GitHub Code Scanning: one rule
  per advisory with a numeric `security-severity`, one result per vulnerable package located at its
  `composer.lock` line, the verified command in the message.
- `--fail-on <severity>`: only findings at or above the threshold affect the exit code; findings of
  unknown severity always count. Shown in the summary and in the JSON report.
- Published JSON Schema for the report (`docs/schema/report.schema.json`), validated against every
  stored fixture report.
- Seven more historical fixtures (BookStack 2023 and 2024, Pixelfed, USAGov Drupal, Invoice Ninja,
  Kimai 1.x, Shopware 6.4.20.2), each with stored console, JSON, HTML and SARIF reports.
- Composer version matrix in CI: 2.4, 2.7, 2.8, 2.9 and latest on matching PHP versions.
- Generated CLI reference page, CI integration guide with gate policies.

### Changed

- Composer releases before 2.10 have no `Installer::getLockTransaction()`; the in-process solver
  now performs a lock-only update inside the scratch copy there and reads the lock back.
- Solver results are copied into detached package objects and cycles are collected after each
  solve; peak memory for 136 solves dropped from 1.5 GB to 87 MB.

[0.4.0]: https://github.com/hexblot/composer-remediate/releases/tag/v0.4.0

[0.3.0]: https://github.com/hexblot/composer-remediate/releases/tag/v0.3.0

## [0.2.0] - 2026-09-09

### Added

- `composer remediate:db-build`: builds a local SQLite advisory database from Packagist's full
  dump, OSV's Packagist archive and the FriendsOfPHP repository; records sharing an identifier are
  merged, every source's range is kept, semantic disagreements are flagged, and a dataset hash
  identifies the logical content. `--include` merges private advisories from a JSON file.
- `composer remediate --database-location=<path|URL>`, `REMEDIATE_DATABASE` and
  `extra.remediate.database` read advisories from such a database, also offline; URLs are cached.
- `composer remediate:db-status` shows provenance, source record counts and the dataset hash.
- A reference database published by this project as GitHub releases `db-YYYY-MM-DD.HH` (and the
  `advisory-db-latest` pointer), refreshed hourly and released only when the dataset changes, with
  sha256 and build-provenance attestation.
- Report summary at the end of every format: findings count and one verified command that fixes all
  findings, or how many of them it fixes.
- Generated CLI reference page (`docs/cli-reference.md`), CI integration guide, coloured console
  output, stored example reports per fixture.

### Changed

- `--offline` now also covers the advisory lookup; without a snapshot or database it exits 4 with a hint.
- Development-only findings are listed after production ones.

[0.2.0]: https://github.com/hexblot/composer-remediate/releases/tag/v0.2.0

## [0.1.0] - 2026-09-09

First release. A Composer plugin (`composer remediate`) that finds the smallest Composer-verified
`composer update` command removing each known vulnerability from `composer.lock`.

### Added

- Advisory matching from the configured repositories (Packagist by default) or a JSON snapshot
  (`--advisories-file`), including packages reached through `replace` and `provide`.
- Dependency paths to the root for every finding.
- Candidate commands from least to most invasive: plain update, update with dependencies, parent
  update with all dependencies, root-constraint widening, optional direct requirement
  (`--allow-direct-require`).
- Validation of every candidate with Composer's own solver in a dry run; the resulting lock is
  re-checked against the advisories.
- Lowest-working-parent-version search, conflict-driven discovery of sibling packages that pin the
  parent, and simplification of the winning command.
- Deterministic ranking: no root constraint changes, no major changes, no pre-releases, fewest
  changes, smallest version movement.
- One combined command for all findings, verified, with a report summary ("fixes k of n").
- Text (coloured in a terminal), HTML (self-contained) and JSON reports; `--format` for stdout and
  repeatable `--output` files.
- `--offline`, `--ignore`, `--no-dev`, `--ignore-platform-req(s)`; `config.audit.ignore` and
  `config.policy.advisories.ignore` are honoured.
- Exit codes: 0 clean, 1 fix available, 2 no verified fix, 3 error, 4 advisories unavailable,
  5 network failure during solving.
- Fixture harness with frozen package metadata and advisory snapshots; six fixtures including five
  real historical projects.

[0.1.0]: https://github.com/hexblot/composer-remediate/releases/tag/v0.1.0
