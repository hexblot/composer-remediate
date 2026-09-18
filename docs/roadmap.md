# Roadmap

This page is what is still to come. Everything already shipped is on
[what has been delivered](delivered.md), and the [design decisions](design-decisions.md) page
explains the reasoning behind the plan. The original pitch documents that started the project are in
the repository history (first commits on `main`).

## Delivered so far

| Phase | What it established |
| --- | --- |
| 0 | The algorithm, proved against five real historical fixtures |
| 1 | Deterministic single-finding remediation (release 0.1) |
| 2 | The advisory database: built locally, shared centrally |
| 3 | Ecosystem corpus, CI, Composer and PHP version matrices |
| 4 | Global planning: one command that fixes everything |
| 5 | Optional automation: `--apply` and a batched pull request |
| 6 | Integrations and prioritisation: SARIF, SBOM, EPSS and KEV, baselines |

The detail of each, and the assurance work behind them, is on
[what has been delivered](delivered.md).

## Phase 7 — goal-driven planning *(candidate, the next large piece of work)*

Motivating case: [composer/composer#12777](https://github.com/composer/composer/discussions/12777).
A TYPO3 12 project requires `typo3/cms-core` and one extension; the extension requires
`typo3/cms-dashboard`, which the project never lists. The documented major-upgrade command fails,
Composer's error names the extension as "locked and not requested" but never the dashboard package,
and adding it by hand makes the upgrade work. The planner's conflict-expansion step already reads
those "locked" lines, widens the allow list and retries, and the report prints the resulting command
with the solver's output as evidence. It does not run here only because nothing in that lock carries
an advisory. The engine finds the smallest verified change that reaches a goal; a security fix is one
goal, "this package at this constraint" is another.

- [ ] a goal as input (`package:constraint`, one or several) in place of an advisory: candidate
  generation takes the target constraint where it now takes the fixed range above the advisory;
  acceptance becomes "the target is satisfied and no advisories are introduced"
- [ ] a run with no advisory data at all is valid for a goal (today it exits 4), while the
  no-new-advisories rule still applies whenever data is available; the fail-closed paths get their own
  tests for this mode
- [ ] goal-aware ranking: widening a root constraint is a last resort for a security fix and the point
  of a major upgrade; constraint drag is reported as the plan, not as a finding
- [ ] the same reports, exit codes and global combination; several goals are planned jointly
- [ ] fixtures: the TYPO3 case above built with `bin/build-fixture.php`, and two or three more from
  Composer's discussions board, with the human-chosen command recorded as for the security fixtures
- [ ] `--apply` and the batched pull request from Phase 5 accept goals too

Boundary: the goal is a version constraint on a locked package. Interpreting release notes, judging
breaking changes or choosing the target version is out of scope; the user names the goal and the
planner finds the smallest verified command that reaches it.

## Report additions from community feedback *(small, next sprint)*

Suggested in reactions to the project; each is a line in the report, not an engine change.

- [ ] on a constraint-drag finding, say that no fixed release exists within the current major on the
  branch in use, and that a maintained fork or a backport published under another name, if one
  exists, is the alternative to the widening the report recommends (the planner already tries the
  same-branch backport first: advisory ranges are per branch, so a 2.x project gets the 2.x fix before
  any major bump is considered; what it cannot see is a fix under a different package name)
- [ ] under every recommendation that relies on a `--with` constraint, the persistent form of the same
  instruction: the `conflict` entry for `composer.json` (`"twig/twig": "<3.14.0"`, derived from the
  fixed range already computed) that keeps future updates from falling back below the fix and makes
  the resolver's error name the reason; Composer has no subcommand for `conflict`, so it stays a
  follow-up line rather than part of the verified command
- [ ] what the upgrade changes about what a package *can do*, as a note on the recommendation: the
  package type becoming `composer-plugin`, `autoload.files` (which runs on every request) or binaries
  appearing where there were none, and the source or dist host changing between the locked and the
  recommended version. All of it comes from metadata already diffed, so nothing is downloaded or
  unpacked; it is shown rather than folded into the ranking, because the count of changed packages
  measures review burden and this measures something else
- [ ] declared consequence hints: a way to say that a package handles untrusted input in this
  application, so that ordering reflects it. There is a suppressive side already (`--ignore`, the
  baseline) and no escalating one, and a reader's account of triaging four Dompdf findings ahead of
  one high-severity Guzzle advisory is the case for it. Declared, never inferred
- deliberately not adopted: a root `replace` to pin a transitive dependency (it tells Composer the
  root provides the package, which then stops being installed), distro backports (they patch PHP
  and system packages, not a project's `vendor` directory), and reachability analysis, which decides
  whether an application can actually reach a vulnerable function: a wrong "not reachable" is a silent
  miss, and PHP's dynamic dispatch, container wiring and string callables make that verdict too
  unreliable to put in front of a gate

## Before a stable 1.0

1.0 is a promise about stability rather than a feature count, so what stands in the way is not on the
lists above. Done so far: the suite runs on [Windows and macOS](contributing.md), a
[compatibility policy](compatibility.md) says which surfaces a version number covers, and the
advisory database this project publishes is watched rather than assumed to be working.

- [ ] soak time on `--apply`, which is the only thing that writes to a project and is the feature a
  1.0 invites people to run unattended on a schedule; this is a reason to wait rather than something
  to build
- [x] the sixth adversarial review, taken as the first review of the advisory database's own supply
  chain and of the parallel planning code. Seven findings, all answered: a feed answering with no data
  built a database missing that source and nothing noticed, a dead worker discarded the whole run, the
  count of disagreeing sources was computed and never shown, the published database's provenance was
  never checked by anything an adopter ran, the publish job attested bytes it had not verified, and the
  compatibility page promised a schema URL per version that one unversioned file could not honour. One
  reported finding was a false positive and is recorded as such below
- [x] a seventh adversarial review, which found that advisory data readable only in part became
  complete coverage: a lock could be reported clean, with no gaps and no warnings, against data read
  in part. Six more answered with it, including verification that bound a scan to a pathname rather
  than to the bytes it had checked. All seven came with runnable reproductions
- [ ] an eighth review once the report additions above have landed, taking the contract suite as a
  claim to attack rather than a reassurance
- deliberately not in 1.0: Phase 7 below. It is a new capability, not a hole in this one

## Assurance *(ongoing, alongside the phases)*

Work that does not add features but decides whether the recommendations can be trusted. What has
already been done is on [what has been delivered](delivered.md); each item there has a regression
test behind it, and the
[changelog](https://github.com/hexblot/composer-remediate/blob/main/CHANGELOG.md) has the details.
Still open:

- [ ] SonarQube itself in addition, for the complexity and duplication view a per-pull-request reviewer
  does not give (asked for, awaiting an answer)
- [ ] remaining long methods (`InProcessSolver::solve`, `DbBuildCommand::execute`,
  `HtmlRenderer::finding`, the planner's per-finding search) and the `PackageChange` kind constants
  as an enum
- [ ] a sixth adversarial review once the report additions above have landed, and a first one of the
  advisory database's own supply chain, which no review has taken as its subject yet
