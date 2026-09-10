# Comparison with other tools

Composer Remediate does one thing: given a vulnerable lock file, find the least invasive
`composer update` command that removes the vulnerability and prove it with Composer's solver. Most
neighbouring tools answer a different question, and some of them are better inputs to this one than
competitors. This page says where the line is, including where this tool adds nothing.

## Summary

| | Detects | Names the package to update | Handles transitive pins | Verifies the fix with the solver | Runs locally, no account | PHP / Composer |
|---|---|---|---|---|---|---|
| `composer audit` | yes | no | no | no | yes | yes |
| Composer 2.10 advisory blocking | at update time | no (you name it) | no | implicitly, for the package you named | yes | yes |
| Dependabot | yes | direct dependencies only | no | opens a PR whose lock resolved | hosted | yes |
| Renovate | yes | direct dependencies; transitive remediation is npm-only | no | opens a PR whose lock resolved | self-hosted or hosted | yes |
| Snyk | yes | yes, with upgrade advice | partly | no dry-run proof | account, cloud | yes |
| OSV-Scanner | yes | no | no | no | yes | yes |
| CVE Lite CLI (OWASP) | yes | yes, parent-aware | yes | no | yes | JavaScript / TypeScript only |
| **Composer Remediate** | input from any of the above | yes, nearest controllable parent | yes, including the lowest parent version that admits the fix | yes, every recommendation | yes | yes |

## `composer audit`

Composer's own auditor reports which locked packages have advisories and stops there. It is the
first half of the job and this tool consumes the same advisory data through the same Composer
classes. Where `composer audit` says "twig/twig 3.10.3 is affected", `composer remediate` says
"`composer update drupal/core-recommended:10.3.4 -W -m` removes it, changing three packages". Use
both: `audit` as the cheap gate, `remediate` when it fails.

## Composer 2.10 advisory blocking

Since 2.10, `composer update` refuses by default to install a version with a known advisory
(`config.policy.advisories.block`). Once you know which package to update, `composer update <A> -W -m`
therefore already yields a minimal change that avoids advisories. What blocking does not do is tell
you which `A` to name, search for the lowest `A` that admits the fix, explain why no `A` works, or
consolidate several findings behind one parent into one command. Those are the parts this tool adds.
Candidate solves here run with blocking disabled and re-check advisories on the result themselves,
so results are identical from Composer 2.4 to 2.10 and against any advisory source; the report flags
a **blocking risk** where 2.10's blocking would refuse a recommended command.

## Dependabot and Renovate

Both open pull requests that bump a *direct* dependency to a version without the advisory, and a PR
whose lock resolved is a form of verification. Neither reasons about transitive packages for Composer:
when `twig/twig` is pinned by `drupal/core-recommended`, there is no direct requirement to bump, and
the PR either never comes or bumps `drupal/core-recommended` to its newest release rather than the
lowest one that lifts the pin. Renovate's transitive remediation exists only for npm. This tool's
fixture corpus is full of exactly these cases; in two of them the project's own next commit was the
upgrade the planner recommends. Use Dependabot or Renovate to keep direct dependencies current, and
this tool for the transitive findings they cannot act on.

## Snyk

Snyk's upgrade advice is the closest analogue: it names the direct dependency whose upgrade removes a
transitive vulnerability. It is a commercial, cloud-hosted service, which means an account and your
dependency graph leaving your machine. It does not run the fix through Composer's solver before
suggesting it, so "upgrade X to Y" can still fail against your other constraints. Composer Remediate
is free software, runs where Composer runs, sends only what `composer update` itself would send (see
[Privacy and network behaviour](privacy-and-network.md)), and shows only commands that solved.

## OSV-Scanner and other scanners

OSV-Scanner, Trivy, Grype and similar tools read `composer.lock` and report advisories from OSV or
their own feeds, often across many ecosystems in one run. They are detection tools; none proposes or
verifies a Composer command. Their output is not an input format this tool reads directly, but the
advisory database built by `remediate:db-build` merges OSV, Packagist and FriendsOfPHP, so the same
advisory data is available offline (see [Advisory database](advisory-database.md)).

## CVE Lite CLI

[CVE Lite CLI](https://github.com/OWASP/cve-lite-cli), an OWASP project, is the inspiration for this
tool: local-first scanning of lockfiles with copy-and-run fix commands and parent-aware guidance for
transitive dependencies, for the JavaScript and TypeScript ecosystem. Composer Remediate applies the
same idea to PHP and adds solver verification of every recommendation, which the npm ecosystem's
`overrides` mechanism makes less necessary there and Composer's constraint model makes essential here.

## Where this tool adds nothing

- A direct dependency with a stale lock: `composer update <pkg>` is the answer and this tool will
  tell you so, after solving it, which costs a few seconds you did not need to spend.
- Reachability: whether the vulnerable code is actually called. Nothing here does static analysis.
- Vulnerabilities in PHP itself, extensions, or the operating system.
- Applying the fix: every release so far recommends and never modifies your project; `--apply` is on
  the [roadmap](roadmap.md).
