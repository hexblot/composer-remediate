# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- A coverage gap the current lock already carries no longer rejects candidates. A candidate is
  rejected only for gaps it introduces, on packages it adds. Records the database could not attribute
  to any package (today, two phpseclib records) apply to every lock alike, but they were counted
  against every candidate that added a package: a Drupal core security upgrade was reported as "no
  verified fix" until `--accept-coverage-gaps` was given. Those gaps are still disclosed for the run
  and still keep a lock without findings from exiting `0`.
- A local build at the database path could stand in for the published database however little it
  covered. A two-advisory test build, left in a Composer cache that DDEV shares between projects, was
  kept as "a local build with private advisories" and every project scanned against it, reporting few
  or no findings. A local build now counts in place of the publication only when it was built from
  every public feed the publication lists in `latest.json` (Packagist, OSV and FriendsOfPHP by
  default). A newer partial build is replaced by the download like any stale copy; a partial build
  carrying private advisories, which can be neither kept nor replaced without dropping something,
  stops the run with exit `4` and names the missing feeds and the three ways forward.

[Unreleased]: https://github.com/hexblot/composer-remediate/compare/v0.10.2...HEAD

## [0.10.2] - 2026-09-25

### Added

- `--exposed <package>` (repeatable) declares that a package handles untrusted input in this
  application. Its production findings are listed first, ahead of known-exploited and higher-severity
  ones elsewhere, because the operator knows something about the application no advisory feed does;
  the rest keep the planner's urgency order, and development-only findings stay last. It is applied to
  the finished plan, like the baseline, so it cannot change a recommendation, the combined command or
  the exit code, only the order. The text report tags such findings `[declared exposed]` and says why
  they come first, the HTML report shows an `exposed` badge, and a name that is not in the lock is
  reported as a warning. It is the escalating counterpart of `--ignore` and the baseline, and it is
  declared, never inferred.
- The JSON report carries `findings[].declared_exposed` and `summary.packages_declared_exposed`, so
  `schema_version` is **3**.
  [`report-v3.schema.json`](https://hexblot.github.io/composer-remediate/schema/report-v3.schema.json)
  is the copy to pin, and `report-v2.schema.json` is frozen at what 0.10.1 emitted.

### Changed

- The example reports under each fixture's `reports/` directory are now checked by the fixture tests:
  `bin/run-fixture.php --write-reports` and `FixtureTest` render them through one class, and a stored
  copy that differs from a fresh render fails the test, naming the command that regenerates it. They
  had drifted unnoticed from 0.9.1 to 0.10.0 because CI checked only the page generated from them. The
  Composer minor release they were recorded with is stored beside them: an older Composer (the
  Composer-version matrix) recommends different commands by design and is not compared, and a newer
  one fails until the reports are regenerated.

### Fixed

- Under GitHub Actions a conflict explanation in any report repeated Composer's errors as workflow
  commands (`::error ::…`), lines meant for the runner's log. They are left out, so a run in CI and one
  on a laptop explain a conflict in the same words.
- CI's canonical PHP 8.4 job piped PHPUnit into `tee` without `pipefail`, so it took `tee`'s exit
  status and passed with failing tests. It is the one job that runs on every push to `main`. The step
  now sets `pipefail`; the full matrix on pull requests was never affected.

## [0.10.1] - 2026-09-23

### Added

The three report additions from 0.9.1 now reach the **JSON report**, so what a person reads and what a
pipeline gates on say the same thing again. `schema_version` is **2**.

- `findings[].remediation.no_fix_within_locked_major` — why a widening is the only route left when the
  locked branch published no fix, and the alternative the planner cannot see.
- `findings[].remediation.conflict_entries` — the `conflict` entries for `composer.json` that keep a
  later update from resolving back below the fix, as `{package, constraint}` pairs.
- `findings[].remediation.capability_changes` — what the update changes about what a package may do,
  each with `kind`, `from`, `to`, a `runs_new_code` flag and a sentence for a person.
- `summary.packages_running_new_code` — the count a gate can key on: recommendations that let code run
  which could not run before.

[`report-v2.schema.json`](https://hexblot.github.io/composer-remediate/schema/report-v2.schema.json) is
published as the copy to pin; `report-v1.schema.json` is frozen at what 0.10.0 and earlier emitted, and
a test now holds every superseded schema to that. `docs/ci-integration.md` gains recipes for gating on
the new fields and for turning the conflict entries into a `composer.json` block.

**On the version number.** 0.9.1 kept these out of the JSON report precisely because a `schema_version`
increase is a minor rather than a patch. Shipping them in a patch is the thing that reasoning avoided;
it is permitted only because the compatibility promise is not in force before 1.0, and it is recorded
here rather than glossed. A consumer validating strictly against `report.schema.json` will see the
shape change in a patch release — pin `report-v1.schema.json` if that matters, and move when you are
ready.

### Fixed

- The example reports stored under each fixture's `reports/` directory had drifted since 0.9.1: CI
  regenerates `docs/case-studies.md` from them but never checked the reports themselves, so the
  capability notes, the conflict entries and the CycloneDX warnings were missing from the committed
  examples. All eighteen are regenerated.

## [0.10.0] - 2026-09-22

### Fixed

An eighth adversarial review and three rechecks of the answers to it: ten findings, nine fixed, each
with a reproduction the reviewer supplied and a regression test here that fails without the fix. Every
one reproduced; none was a false positive. Each recheck found the previous round's repairs incomplete —
four, then three, then one — and one of those was a defect introduced by the repair before it. Each is
listed below with what finally closed it. They cluster around safety state that changes
between components — what the run is allowed to do, which database it is reading, which files it
planned from, whether the advisory source can still answer — so several of the tests are contracts
rather than unit tests, because the defect was two components each being right on their own terms.

- **`--apply` under the standalone binary ran the project's code.** The binary forces
  `--no-plugins --no-scripts` so that nothing from an untrusted project executes; the apply subprocess
  is a second Composer and inherited neither, so a `pre-update-cmd` ran and the run exited `0`. An
  apply now repeats whatever restrictions the run was started with.
- **A fix stayed "verified" after the advisory source stopped being able to check it.** Completeness
  was established once, before planning; a source that degrades mid-run left "introduces no new
  advisories" being decided by data that only knows the current lock. The check now sits at each use.
  The recheck then found the run still reporting itself complete: rejecting the recommendation left
  exit `2`, which says "a vulnerability nothing can fix" — an answer — where the truth was that the run
  could not find out, and at `2` the SARIF and GitLab reports called the scan successful.
- **A failed scan left the previous report on disk.** Failures returned before rendering, so a CI step
  uploading `--output=scan.sarif` published the last successful run's clean result for a scan that
  never ran. All six formats now say the run did not complete, and the text and HTML reports no longer
  say "No known vulnerabilities" for a run that could not look. The first fix covered the paths that
  return an exit code; the recheck found three more that did not — a corrupt baseline, an invalid
  `--fail-on`, and an advisory database missing a table. The last escaped as an uncaught exception,
  which Symfony turns into exit `1`, the code for "vulnerabilities, every one with a verified fix", and
  the shipped action read that as success and carried on. Nothing now leaves the command without its
  reports, and the action refuses a report it cannot read. The second recheck found `emit()` still
  returning at the first destination it could not write, skipping every later one and stdout with them:
  one path under a missing directory was enough to leave a second `--output` holding the previous
  successful report. Every destination is now attempted; an unwritable one makes the run a tool error
  and decides nothing for the rest.
- **A forked worker could read a database that was swapped underneath it.** Reopening after a fork
  named the path, and a path is not a file. The first fix compared the database's `schema_version`,
  `dataset_hash` and `built_at`, which the recheck defeated by replacing the file with one that kept all
  three and had every advisory deleted: whoever can replace the file can write the fields it is judged
  by. It is now the digest of the bytes.

  The second recheck then found two more ways past that. The repair that tied the locator's decision to
  the reader hashed the path *after* deciding, so a replacement arriving during the publisher request
  was checked as the old file and trusted as the new one — rehashing asks the file who it is a second
  time and believes the second answer. Every way of settling on a database now states the digest it
  settled on, and the type system requires it, so no route can omit one. Separately, a database in WAL
  mode answers partly out of a `-wal` sidecar that no digest of the file covers: rows deleted into the
  WAL were invisible to the pin and a pinned database scanned clean. Such a database is refused, and the
  refusal names the checkpoint command that settles it.

  What all of those repairs had in common was checking the file at a moment — when it was located, when
  it was opened, when a worker reopened it — and a check at a moment says nothing about the planning
  that follows. The third recheck used that directly: a concurrent writer deleting a package's advisory
  rows between the first scan and candidate verification got the planner to approve a command
  introducing a package it had been told was vulnerable, a verified recommendation at exit `1` drawn
  from a database nobody had verified. Rechecking before every query would narrow that window without
  closing it, because the gap is between the check and the read. **A run now reads a private copy of the
  verified file**, made once and known only to that run, so the bytes that were verified are the bytes
  every later query and every forked worker sees. The published database is about 7 MB, so this is one
  copy per run.
- **An unreadable archive entry vanished from coverage.** Encrypted, corrupt or truncated members were
  skipped in silence, so a partial archive counted as complete. They are recorded as coverage gaps,
  and a reader with nowhere to record one refuses.
- **The `--apply` guard hashed the files after planning**, so an edit made during the search matched
  its own hash. Hashed before the search now. The recheck then deleted `composer.lock` during the
  search: the comparison was skipped when the file could not be read, treating the strongest evidence
  of interference as agreement. A missing input is a refusal.
- **CycloneDX dropped the warnings every other format carries**, including the analysed project's own
  advisory suppressions — the disclosure that explains an empty vulnerability list.
- **An unverified download vouched for itself.** A copy taken with `--allow-unverified-database` had
  its self-declared dataset hash accepted as proof it was current, so an empty database wearing the
  publisher's hash was held as confirmed while the publisher served an advisory it lacked.
- **The GitHub Action pushed to its own base** when `branch` and `base` matched, before the invalid
  pull request was refused. It now refuses first.

### Known

- **`MAX_PATHS` and `MAX_DEPTH` bound the returned paths, not the work of finding them** (finding 10,
  not fixed here). The whole recursive ancestor tree is expanded before either applies, so a layered
  graph costs far more than the result suggests: six extra packages took the same 200 paths from
  0.007 seconds to six seconds and 144 MiB. Two attempts at walking it a level at a time each changed
  which command the planner recommends on a real fixture, because the path set Composer's recursive
  expansion produces, and the order of it, decides which ancestors become candidates. A narrower
  recommendation is worth more than the saved seconds, so this stays open.

### Changed

- **Four invariants are now stated and enforced once, rather than defended case by case.** Both review
  rounds landed on the same shape of defect: two components each correct on their own terms, with the
  safety state between them held by convention. What the run may do, which database it is reading,
  which files it planned from, and whether the advisory source can still answer are now settled in one
  place each and inherited everywhere — the apply repeats the run's restrictions, the locator names the
  bytes and every reader is held to them, the plan carries its own failure and every renderer asks it.
  Where the rule could be made structural it was, so that the defect cannot be written again rather
  than being caught when it is; where it could not, a contract test states the invariant instead of the
  symptom.

- **A run whose advisory source cannot verify candidate locks now exits `4`, not `2`.** This is what
  the exit-code table has always documented for an incomplete source; the code did not follow it, in
  the case where the source starts incomplete as well as where it degrades mid-run. A pipeline treating
  `2` as "no fix available, warn" will now see `4`, "advisory data unavailable".

- `docs/reading-the-report.md` said every format carries the same content. It says what every format
  carries, and where a format carries less.
- `docs/privacy-and-network.md` repeated the standalone binary's safety claim without saying that it
  covers `--apply` too. It now distinguishes the binary's promise from the flag's.

## [0.9.1] - 2026-09-21

### Added

Three additions to the report, asked for in reactions to the project. All three are in the text and
HTML reports; the JSON document is unchanged, because its shape is a covered surface and an addition
to it increases `schema_version`. That is held for 0.10.0.

- **No fix on this branch**, under a constraint drag whose fix also leaves the locked major behind.
  Advisory ranges are per branch, so a fix on the locked branch would have been preferred over any
  major bump; the note says none was published, and names the alternative the planner cannot see — a
  maintained fork or a backport carrying the fix under a different package name. It is not shown when
  the fix stays within the locked major, where the widening is about the constraint that was written
  rather than the branch running out of releases.
- **Keep the fix**, under every recommendation that rests on a `--with` constraint: the `conflict`
  entry for `composer.json`, derived by inverting the fixed range the planner already computed
  (`>=3.14.0` becomes `"twig/twig": "<3.14.0"`). A `--with` constraint lives for one command and
  nothing in the lock records why the version went up, so a later update may resolve back into the
  affected range. Composer has no subcommand that writes a `conflict` entry, so it is shown as an edit
  rather than folded into the verified command.
- **Capability changes**, on a recommendation: a package type becoming `composer-plugin`,
  `autoload.files` or binaries appearing where there were none, and the source or dist host changing.
  Read from metadata the lock file and the solve already carry, so nothing is downloaded or unpacked.
  Shown rather than ranked on: the count of changed packages measures review burden, this measures
  reach. A package the command *adds* is reported only for the two capabilities that run without
  being called, since every new package brings its own everything.

The HTML report also gains the constraint-drag note, which until now appeared only in the text report.

## [0.9.0] - 2026-09-20

Groundwork for a stable 1.0. See [compatibility](https://hexblot.github.io/composer-remediate/compatibility/)
for what a version number will promise.

The release that makes a clean result mean something. Every reader of advisory data now refuses
rather than skips: anything a source could not interpret is recorded as a coverage gap, and a lock
carrying gaps is not called clean until they are read and accepted. That came out of a seventh
adversarial review and four rechecks of the answers to it, each of which found another way for data
read in part to read as complete: a range, an event, a container, a whole reader nothing had looked
at, and finally the identity a record is filed under.

What it costs: a run against a database with a gap about your lock exits `4` rather than `0` until
`--accept-coverage-gaps` is given. What it does not change: nothing is written to a project without
`--apply`, and no recommendation is made that a solve did not verify.

Adversarial testing of this tool uncovered malformed package metadata in a live GitHub Advisory
Database record, which kept the advisory from matching the Composer package it was about; the
correction was submitted upstream as
[github/advisory-database#9639](https://github.com/github/advisory-database/pull/9639). Until that is
merged and the feed rebuilt, the published database carries the record as a coverage gap naming no
package, which gates a scan that would otherwise be clean;
[coverage gaps](https://hexblot.github.io/composer-remediate/advisory-database/#coverage-gaps)
explains what to do with one.

### Fixed

- **A run that lost a worker reported solver runs nobody did.** When a planning worker dies, the
  packages it had not reached are planned in the main process instead. Each solve there counts itself
  as it happens, and the bookkeeping that carries a worker's count home then added the package's total
  a second time, because a plan made in a child has to be counted by the parent and a plan made by the
  parent has already counted itself. On the three-package run the regression test uses, a degraded run
  reported 19 solver runs for the 10 a healthy one does. Nothing was ever planned differently: the
  search budgets are counted per finding and were never fed from this number, which exists so that
  someone can reproduce a run and would have had them looking for work that never happened.

- **The pull-request action ignored `labels` and `draft` once the pull request existed.** Both inputs
  were honoured when the branch's pull request was created and never again, so a label added to the
  workflow later never reached the pull request the action keeps open. Labels are now re-applied on
  every run, where adding one it already carries changes nothing. `draft` is deliberately not
  re-applied: once a pull request is open, whether it is ready for review is a decision somebody made
  about it, and a nightly run that flipped it back would be arguing with them. Both inputs now say
  when they apply, in the action's own metadata and on the CI page. The action's test harness had the
  same blind spot: its `gh` stub reported no open pull request, so both of its runs took the create
  path and the update path shipped untested. Its second run now meets the pull request the first one
  opened.

- **Advisory data that could only be read in part became complete coverage.** A record with one range
  this could read and one it could not survived with the part that parsed, and nothing said the rest
  had been dropped; a document whose affected list was unreadable altogether was counted with the
  records that are simply about another ecosystem. A lock could be reported clean, with no coverage
  gaps and no warnings, against data that had been read in part. Anything unreadable is now a gap,
  attributed to its package where the record says which, and to none where it does not. That holds
  wherever the unreadable part sits, in either source. In an OSV record: a range that is not a range, an
  event that is not an event, an event boundary that is not a version, an event naming a boundary this
  does not know, a ranges or versions container that is not a container, a listed version that cannot
  be placed, an affected list that cannot be read at all, and a document where nothing survived, which
  must not be filed as belonging to another ecosystem since that is the one classification that records
  nothing. In a FriendsOfPHP advisory: a branch that cannot be read beside one that can, which was
  never looked at before. Where a record fails to be read in two ways at once, the part that named no
  package stays its own gap rather than being replaced by the packages the other parts happened to
  name, so a scan of some third package cannot read clean on it.

  The same rule now decides whose package a record is about, in all three readers. Only an identity the
  reader can read and finds to be another ecosystem's is out of scope. An OSV entry with no package at
  all, with no ecosystem, or with an ecosystem that is not text; a FriendsOfPHP advisory whose
  `reference` is missing, is not text, or is text naming no scheme; and, in either reader or in the
  Packagist shape that serves the API, `--include` files and `--advisories-file`, a name that is not a
  package name a lock could hold: each may be about a locked package, and each is now a gap. It is
  attributed to the package where something readable names it and to none where nothing does, because a
  name nothing can match attributes nothing. There is one definition of a package name now
  (`PackageName`, Composer's own syntax), and the readers share it.

  An npm entry and a `drupal://` advisory are still read as somebody else's and recorded as nothing, and
  the FriendsOfPHP reader now takes only the files laid out as `<vendor>/<package>/*.yaml`, so the
  repository's own workflow files are not advisories with unreadable packages.

  The name rule found a live one. The OSV feed's `GHSA-q97c-8qh3-fpc6` (CVE-2026-84308, private-key
  recovery in phpseclib) names its package `phpseclib`, with no vendor: it was being stored as an
  affected range under an identity no lock file can hold, so it matched nothing and said nothing, in
  every database this project has published. It is now a coverage gap, and since nothing in the record
  says which package it meant, it is an unattributed one, which gates any scan until the upstream
  record is fixed or the run passes `--accept-coverage-gaps`. The fix for the record itself is
  [github/advisory-database#9639](https://github.com/github/advisory-database/pull/9639).

  Two more ways a part could state nothing and be taken for a part stating that nothing is affected. A
  `ranges` or `versions` container present as null, which is not an absent one. And a part that
  constrains nothing at all: an OSV range whose event list is empty or never opens an interval, a
  FriendsOfPHP branch listing no versions. Each was silent whenever a readable sibling sat beside it.
  An event is also read whole rather than only as far as its first recognised key, so
  `{"introduced": "0", "fixed": ["unreadable"]}` no longer passes on the strength of its first half.

  A commit range is still skipped silently, because every record carrying one also carries the version
  range that matters. Measured against both real feeds before and after: the shape fixes cost nothing
  at all (5 coverage gaps in 6610 OSV records, none in 1648 FriendsOfPHP advisories, the same dataset
  hash either way), and the name rule costs exactly the one record above, 6 gaps in 6609 records. Every
  other shape answered here is one the public feeds do not currently contain, which is exactly why they
  went unnoticed.

- **Verifying the advisory database did not bind the scan to what was verified.** The action checked a
  file's build provenance and then named it by path, and a path stays refreshable: the scan that
  followed could replace the verified copy with a newer publication and read bytes nothing had
  checked. It now pins the verified digest, and the pin goes after the caller's own arguments so that
  an argument naming another source cannot select one that was never verified. Both the planning run
  and the applying run carry it, and the documented recipe for doing this by hand pins the digest too
  rather than naming the path alone.

- **A pinned digest could be sidestepped by naming a different advisory source.** `--advisories-file`
  was honoured before the database was looked at, so a run carrying both it and `--database-sha256`
  read the file and never checked the pin: an empty snapshot reported the lock clean, with or without
  `--apply`, and an incorrect digest went unnoticed. A pin is a statement that the operator will accept
  that database and nothing else, so naming another source in the same run is refused rather than one
  of the two being chosen silently. `--no-database` was already refused this way.

- **SARIF and CycloneDX called an incomplete scan successful.** A run that could not establish
  coverage exits 4, but its SARIF said `executionSuccessful` with an empty result list and no
  notification, and its CycloneDX carried an empty vulnerability list with nothing to say the scan had
  not finished. To anything reading those, that is a clean bill of health. Every format now takes its
  answer from one place, so none can call a run successful that another calls failed. The GitLab
  report was already right and is unchanged.

- **A baselined advisory went on gating the run through a severity it was accepted at.** Acceptance was
  checked against the package as a whole and the severity threshold against every advisory on it,
  including accepted ones, so a package with an accepted high-severity advisory and a new low-severity
  one gated under `--fail-on high`. Both tests now apply to the same individual advisory.

- **A reported command could mean something else when pasted into a shell.** What `--apply` records as
  having run was built by joining arguments with spaces, so a constraint like `--with acme/lib:>=1.2`
  became a redirection: a shell would write a file called `=1.2` and hand Composer no constraint.
  Recorded commands are rendered the same way printed recommendations always were.

- **Worker results and freshly built databases were created world-readable.** Both were written and
  then tightened, which leaves a window, and on a rename it is the new file's permissions that
  survive. Both are created owner-only now. They hold the shape of a private project, and a build with
  `--include` holds advisories the operator has not published.

- **A worker that died took the whole run with it.** A planning worker killed by the out-of-memory
  killer, which is what happens on a large lock file with too many workers, failed the run and
  discarded every package already planned. What it had finished is kept now, and whatever it had not
  reached is planned one at a time, with a warning in the report saying the run degraded. A killed
  worker also left a half-written result file behind, which nothing ever swept up.

- **A feed that answered with no data built a database missing that source, and nothing noticed.** An
  advisory feed returning a well-formed but empty answer, which is what a mirror serving a placeholder
  or a feed mid-incident does, produced no records and no error. The build published the result: a
  smaller database, checksum-verified, attested, fresh by every measure a client has, and missing a
  whole source. A lock with a vulnerability only that source knew about reported clean and exited `0`.
  Each downloaded feed now refuses an answer carrying neither advisories nor records it could not
  read, and the publishing workflow refuses to publish a dataset more than 5% smaller than the one it
  would replace. Records a feed sends that cannot be interpreted are unaffected: those are coverage
  gaps, which are reported and gate a clean result already. Found by an adversarial review of the
  advisory database's supply chain, which no previous review had taken as its subject.

- **A project could not name its own database path on Windows.** The guard that keeps
  `extra.remediate.database_path` inside the project compared a resolved path against the project root
  with a forward slash, and `realpath()` answers in the platform's own separator, so `C:\project\var`
  did not begin with `C:\project/` and every relative path was rejected as escaping. The comparison
  normalises separators now, and the resolved path comes back with one separator throughout instead of
  a `realpath()` joined to forward-slash segments. Found by running the suite on Windows for the first
  time.

### Added

- **The suite runs on Windows and macOS.** Every job had run on Linux, while what this tool does is
  filesystem work, subprocess execution and process forking, all of which differ elsewhere. The first
  run failed on both platforms and found the defect above, the same defect in the test server that
  stands in for a publisher, and three assumptions the tests were making about POSIX. A file mode of
  `0600` and a symbolic link cannot be had on Windows, so those cases are skipped there with the
  reason given; the limitation is documented, because a database built with `--include` carries
  advisories you did not publish and on Windows is left at whatever its directory grants.

- **A compatibility policy.** Which surfaces a version number covers, and which it does not. Exit
  codes, command and option names, the JSON report and its `schema_version`, the SARIF, CycloneDX and
  GitLab shapes, the published database URLs and `latest.json`, and the action's inputs and outputs
  are covered. Every PHP class in the namespace is internal, the recommendation itself moves when the
  advisory data moves, and anything written for a person to read may be reworded. The deprecation
  period is stated, so removing an option has a defined shape. Not in force while the version is 0.x.

- **A contract test suite** (`composer test:contract`), for the guarantees that hold the tool together
  rather than the behaviour of any one class. Advisory data that cannot be fully read never yields a
  clean result; what a scan consumes is what was verified; an incomplete run is never presented as
  successful by any format; files holding private data are owner-only from the moment they exist;
  acceptance and severity compose to the same answer however they are combined; a printed command
  parses back to the arguments it was built from. Each is checked over a range of inputs rather than
  the single case that first broke it, and writing them found one fault the review had not: CycloneDX
  reporting an incomplete scan as an empty bill of materials.

  The two invariants that describe a file's whole lifetime watch it while it is being written rather
  than inspecting it once it is finished, because a file created readable and tightened afterwards
  looks identical at the end and anyone on the machine could have read it in between. Both were
  checked against a deliberately reintroduced fault to confirm they notice.

- **The advisory database says how often its sources disagreed.** Sources that disagree about which
  versions an advisory affects are unioned, so a version any source calls affected is affected. That is
  the safe direction, and it also means one feed can widen a range on its own. The build has always
  counted how often that happened and then kept the number to itself; the report's source line now
  carries it.

- **The GitHub Action can verify the advisory database's build provenance.** Its new `verify-database`
  input takes the repository whose attestation must cover the database, and is empty by default. The
  database is fetched into a path the run controls first, so the file that is verified is the file that
  is used, and the same recipe by hand is in the documentation. The publish job also checks the
  artefact against its own checksum before attesting it, rather than putting a valid provenance
  signature on whatever arrived from the job that runs third-party code.

- **A schema URL that will not move.** `report-v1.schema.json` describes `schema_version` 1 and stays
  that way; `report.schema.json` continues to describe whatever the tool emits today. The
  compatibility page told consumers a version's schema stays published at its URL, which a single
  unversioned file could not have honoured.

- **Monitoring for the advisory database this project publishes.** It published nothing for three days
  this month and surfaced only because someone looked. A failed build or publish now opens an issue
  and comments on that one rather than filing another every six hours, and a run that finds nothing
  new checks how old the published copy is, failing past two days, so a pipeline reporting success
  while publishing nothing is no longer silent. The documentation says what watches it, how to verify
  the build attestation, and how to publish your own if this project stops.

## [0.8.1] - 2026-09-14

A performance release, and nothing about what a run concludes changes. Almost all of a run is
Composer solving, and the packages are planned independently of one another, so `--parallelize`
plans several at once. On a 201-package lock file with ten findings, four workers take the run from
45 seconds to about 15. The default is unchanged: without the flag, packages are planned one after
another exactly as before.

### Added

- **`--parallelize=<n>` plans several packages at once.** Searching within one finding cannot be split
  up, because each step reads the previous solver's output; across findings there is no such link, and
  that is where the work fans out. The result does not change: each worker plans its own packages from
  the same lock file, the same graph and the same advisory data, writes nothing another worker reads,
  and returns a value. The whole fixture corpus was checked report-for-report against a sequential run.
  Progress is still reported for every package, in the order the workers finish rather than the order
  of the list. `--parallelize=auto` uses one worker per processor core, at most four.

  Each worker runs its own Composer solves, so allow a few hundred megabytes of memory for each; the
  run above peaks at about 170 MB with one worker. Parallel planning is refused, and the report says
  so, where it would be unsound: on a machine that cannot fork (Windows, or PHP without `ext-pcntl`
  and `ext-posix`), and with an advisory source that holds a connection it cannot hand to a child
  process. The advisory database used by default re-opens itself in each worker; `--no-database`,
  which asks the configured repositories, plans one package at a time.

  Two optimisations were measured and rejected rather than built: reusing Composer instances between
  solves (building them is about a tenth of a solve, against sharing state that keeps every solve
  honest) and caching solves within a run (the commands tried are almost never repeated).

### Changed

- The [roadmap](https://hexblot.github.io/composer-remediate/roadmap/) is now only what is still to
  come; the seven completed phases and the assurance work behind them moved to
  [what has been delivered](https://hexblot.github.io/composer-remediate/delivered/).

- The package carries the `composer-plugin` keyword, which it had always been the type of but never
  declared, so it was missing from the Packagist tag that category is browsed by. Also `cve`,
  `advisories` and `supply-chain`.

## [0.8.0] - 2026-09-14

A feature release: the tool can now apply the fix it recommends, and open one pull request carrying
every fix it could verify. The default is unchanged and unchanged on purpose: without `--apply` nothing
in your project is written. It also says what it is doing while it works, after a first user on a large
lock file took several minutes of silent solving for a hang.

**Upgrading from 0.7.0.** Four of the security fixes below apply to code 0.7.0 shipped, and two of them
were rated P1 by the reviewer:

- The advisory database was fetched with an IO object carrying the analysed project's authentication,
  and Composer reads TLS settings out of `http-basic` credentials, so a project could influence which
  certificates authenticate a publisher you chose.
- A project could turn the advisory database off through `extra.remediate.database`, and it could do so
  around a `--database-sha256` pin, which is meant to be the trust anchor.
- `--no-project-ignores` discarded exceptions from your own configuration along with the project's.
- A database this tool builds was created world-readable, though a build with `--include` may carry
  private advisories.

Also fixed for 0.7.0 users: a handled download failure printed `Unhandled promise rejection …` on
Composer 2.4 to 2.9, which is every supported version but the newest.

The new writing features had a fresh adversarial adoption assessment covering the action, the apply
path, the security boundary, the reports and the tests. Nine findings across it and its recheck are
answered, each with a test, and the reviewer confirmed them fixed. They are new all the same: read a
pull request the action opens before you merge it, as you would anyone's.

### Added

- **It says what it is doing while it does it.** A run now reports how many locked packages it matched,
  how many packages need fixing, and which one it is working on, with a running count of solver runs;
  a first run that has to fetch the advisory database says so before it starts. Those lines go to the
  error stream, so a report on standard output is still only the report, and `-v` still adds every
  candidate command as it is tried. Reported by the first user to run this on a large lock file, who
  reasonably took several minutes of silence for a hang.

- **A GitHub Action that opens one pull request with the fixes applied (Phase 5, complete).**
  `action.yml` in this repository plans, applies with `--apply --apply-no-install`, and opens or
  updates a single pull request on one reused branch, rather than one pull request per package. It
  stops before touching anything when no finding has a verified fix, and again when the run changed
  neither the manifest nor the lock. The description is rendered by the new `remediate:pr-body`
  command from the JSON reports of the planning run and the applying run: which advisories closed,
  which survived and with what fix, what ran, and what the applying run warned about. It says plainly
  when a run changed the lock and closed nothing. Advisory text is escaped, since it is upstream data
  arriving in a rendered page. A fix that would edit `composer.json` is reported and not applied, since
  `--apply` refuses those without `--apply-root-constraints`.

- **`--apply` (Phase 5).** The recommendation can now be run rather than only printed. It executes the
  command the report shows, in the project, with the project's own Composer, and then plans again, so
  what you read afterwards is the state the run left behind and not a prediction of it. `composer.json`
  and `composer.lock` are copied outside the project before anything runs and the report says where.
  It refuses when there is no verified command to run, when the recommendation would edit
  `composer.json` (`--apply-root-constraints` permits it), when those files changed while the plan was
  being computed, and when they are already modified in a git checkout (`--apply-allow-dirty`
  permits it). `--apply-no-install` writes the lock and leaves `vendor/` alone, which is the shape a
  pull-request workflow wants. Nothing is applied without the flag: the default remains to recommend
  and write nothing.
- `Candidate` builds its command from argument lists (`requireArgumentLists()`, `updateArguments()`)
  that both the printed command and the applier use, so what a report promises and what `--apply` runs
  cannot drift apart.

### Security

Answers to a third adversarial adoption review, this one of `--apply` and the shipped action. Seven
findings, each with a test.

- **The downloader carries the operator's credentials and nothing else.** It was built from the
  caller's IO object, which holds authentication loaded from the analysed project; Composer reads TLS
  settings out of `http-basic` credentials, so a project could still decide which certificates
  authenticate a publisher the operator chose. A fresh IO is loaded from the operator's configuration
  alone.
- **A project cannot turn the advisory database off when a digest is pinned**, and cannot turn it off
  quietly at all: `extra.remediate.database` set to `composer` or `none` is disclosed like any other
  source the project chooses, on the error stream as well as in the report, since a run that fails
  afterwards has no report to carry it.
- **`--no-project-ignores` keeps the operator's own exceptions.** Which entries belong to the project
  is decided by reading the operator's configuration and the merged one and subtracting, not by asking
  Composer who wrote a key: it records one source per top-level key, so a project adding to
  `config.audit.ignore` made the operator's entries in that key look like its own, and dropping them
  discarded centrally approved exceptions.
- **The disclosures a run makes survive `--apply`.** The second plan is a fresh object, so what the
  first run said about where advisories came from and who chose that used to vanish exactly where a
  reviewer is looking at an automated change.
- **The action builds its branch from the base, before planning.** It planned and branched from
  whatever ref happened to be checked out, so a run on a feature branch carried unrelated commits into
  the pull request.
- **The action commits the two files it changed**, not the whole index, so a file staged by an earlier
  workflow step cannot ride along in a security pull request.
- **The token authenticates git as well as the API.** It is set on the remote rather than passed to
  the push, so fetches are authenticated too and `--force-with-lease` still has a remote-tracking ref
  to lease against.
- **The action's git calls override the checkout's authorization header.** The token went into the
  remote's URL, but `actions/checkout` leaves an `Authorization` header in `http.<server>/.extraheader`
  and git sends that instead, so the server answered the checkout's identity and a supplied token had no
  effect on a push the checkout credential could not make. Every call that talks to the remote now
  resets that header for the duration of the call, changing nothing in the workflow's own configuration.
- **A project widening a scoped exception of the operator's is reported as the project's.** Ownership
  compared rule names, so an operator excepting a package below one version and a project excepting the
  same package at any version looked like the same rule, and the widening passed undisclosed. Rules now
  carry their version constraint.
- **The action's script is a file, `action/run.sh`, with its own test harness**
  (`tests/Action/action-test.sh`, `composer test:action`), which runs that exact script against a local
  git remote with stubbed `composer` and `gh`. Three of the findings above live in decisions the PHP
  suite cannot reach, and the harness caught a fourth defect introduced by the fix for one of them. What
  it does not cover is which credential a server actually receives, which needs a real HTTP server; it
  checks that the calls carry the header reset.

Answers to an Aikido scan of the workflows.

- **No job both runs third-party code and holds a credential that can change the repository.** The
  advisory-database workflow is split: the build resolves Composer dependencies, runs this project's
  code and reads three upstream feeds with a read-only token, and hands its artefacts to a publish job
  that runs nothing but the attestation action and `gh`. Only that job has `contents: write`, and only
  it is bound to the `advisory-db` environment whose deployment-branch policy GitHub enforces. The CI
  matrix is read-only for the same reason, and the badges are pushed by a separate job that downloads
  two JSON files and nothing else. Composer installs run with `--no-plugins --no-scripts` in both
  workflows and in the GitLab template.
- **A database this tool builds is created readable by its owner alone** (`0600`, in a `0700` directory
  when it has to create one). A build with `--include` carries private advisories, and the default path
  is a cache directory other users of the machine can often list; sharing one is now a deliberate copy.

### Fixed

- **A handled download failure no longer prints an unhandled promise rejection.** Composer's
  `HttpDownloader::copy()` discards the rejected promise before Composer 2.10, and react/promise reports
  it on stderr when that promise is collected, so a run that dealt with an unreachable publisher
  cleanly, or a mirror that publishes a `.sha256` and no `latest.json`, printed
  `Unhandled promise rejection with Composer\Downloader\TransportException: ...` next to this tool's own
  explanation. Downloads now use the asynchronous form with a rejection handler, driven by a loop the
  locator owns, which behaves the same on every supported Composer version. Noticed in the output of a
  passing CI job.

### Changed

- Work reaches `main` through a pull request, one branch per unit of work; see the contributing page.
  CI follows: a push to `main` and a draft pull request run the single canonical job, and marking a
  pull request ready for review runs the full PHP and Composer matrices. Iterating in a draft therefore
  costs what a push used to, and the matrix is paid for once, when the work is done.

[0.10.2]: https://github.com/hexblot/composer-remediate/releases/tag/v0.10.2
[0.10.1]: https://github.com/hexblot/composer-remediate/releases/tag/v0.10.1
[0.10.0]: https://github.com/hexblot/composer-remediate/releases/tag/v0.10.0
[0.9.1]: https://github.com/hexblot/composer-remediate/releases/tag/v0.9.1
[0.9.0]: https://github.com/hexblot/composer-remediate/releases/tag/v0.9.0
[0.8.1]: https://github.com/hexblot/composer-remediate/releases/tag/v0.8.1
[0.8.0]: https://github.com/hexblot/composer-remediate/releases/tag/v0.8.0

## [0.7.0] - 2026-09-13

A feature release with changed defaults, and the answers to a second adversarial adoption review and
its four rechecks.

Advisories now come from the advisory database this project publishes, kept current at a fixed path
and confirmed by content on every run, so every report carries the same exploit data (EPSS, CISA KEV),
coverage-gap bookkeeping and merged sources rather than only the reports of users who configured a
database. A plain run therefore contacts github.com once per run; `--no-database`, `--offline` or a
local file as the source stop it, and the privacy page says so.

**Upgrading from 0.6.1.** Four of the security fixes below apply to code 0.6.1 actually shipped, and
one of them matters for anyone consuming the GitLab report: `scan.status` was written as `success`
even for a scan that exited 4 because advisory data was unavailable, so an empty vulnerability list
read as a clean result on the dashboard. The other three: a verified fix could add a package whose
advisory records the source could not read, coverage gaps that could not be attributed to a package
were dropped before they reached a scan, and a gate could exit 2 although the combined command fixed
every finding. The rest of the security work fixes the database-handling code introduced in this
release, which 0.6.1 does not contain. Exit codes can change in both directions, so re-check a gate
that treats them strictly.

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
- **Second recheck (two findings at c17b742).** The default database path follows the operator's
  cache configuration, never a `config.cache-dir` set by the analysed project's composer.json (Composer
  records the source of the value; a project file as the source is set aside with a note in the
  report), so a repository cannot pre-fill the default path. The status record that marks a copy as
  downloaded carries the digest of the bytes it describes and is retired only when the bytes change;
  the previous rule, which compared the database's own build time with the fetch time, let a publisher
  reclassify its download as a local build by writing a later timestamp.
- **Third recheck (one finding at b8bf552).** Which configuration counts as the operator's is now
  decided from configuration the analysed project never contributed to (`Factory::createConfig()`:
  environment, the operator's global `config.json`, Composer's defaults). The previous check read
  Composer's merged `config.home`, which the project can set alongside `config.cache-dir`, so a
  repository could hold both sides of the comparison and have its own cache directory accepted as the
  operator's. The rule now lives in `Engine\Advisory\Db\OperatorConfiguration`, and an audit of every
  other place the analysed project's configuration reaches the run applied it to two more: TLS settings
  supplied by the project (`cafile`, `capath`, `disable-tls`), since Composer verifies the download with
  them, and the advisories the project suppresses through `config.audit.ignore` or
  `config.policy.advisories`, whose entries are now named in the report as the project's rather than the
  operator's. Both are disclosures, not refusals: they are the point of those settings for a project you
  own.
- **Fourth recheck (three findings).** The origin test accepted any configuration file below the
  operator's home directory, so a checkout inside `COMPOSER_HOME` had its own `composer.json` (or an
  `auth.json` beside it) read as the operator's; only Composer's two global files, compared by resolved
  path, count now. Everything this tool fetches on the operator's behalf, the advisory database and the
  build's feeds, now uses the operator's TLS configuration and credentials rather than the merged
  project configuration: a project-supplied `config.cafile` can no longer make a publisher the operator
  rejected acceptable, which a report warning did not prevent. `--no-project-ignores` drops the ignore
  entries the analysed project's own composer.json carries, for a gate that does not take a
  repository's word that a finding is accepted; without it they still apply and the report names them.
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
  coverage, badges and the generated-page checks). Pull requests run the full PHP and Composer
  matrices whatever they touch, and a manual run has a `full` switch. Releases are cut from pull
  requests so the tag's tree has had the full run; the path filter that skips documentation commits
  applies to pushes only, since on a pull request it would skip the matrix on a release commit, which
  is the changelog and the status paragraph and nothing else. The advisory database is polled every six hours instead of hourly; it is
  still published only when the dataset changed, and clients confirm their copy by content.
- Roadmap: Phase 7, goal-driven planning, added as a candidate after Phase 5, motivated by
  composer/composer discussion 12777 (a TYPO3 major upgrade blocked by a transitive package Composer's
  error never names); the design-decisions page records why a security fix is treated as one goal
  among others.

[0.7.0]: https://github.com/hexblot/composer-remediate/releases/tag/v0.7.0

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
