# Security Policy

Composer Remediate participates in dependency-remediation decisions, so its own security matters.
This policy covers the plugin code in this repository and the advisory database artifacts the
project publishes.

## Supported versions

| Version | Supported |
|---|---|
| `main` (unreleased) | Yes, security fixes land here first |
| Latest `0.x` release | Yes, until the next minor release |
| Older releases | No |

Once the project reaches 1.0, the latest minor release of the current major receives security fixes,
and the previous major receives them for six months after the new major ships. This table will be
updated with each release.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report vulnerabilities privately through GitHub's private vulnerability reporting for this
repository:

https://github.com/hexblot/composer-remediate/security/advisories/new

Include, where you can:

- the version or commit affected;
- a description of the issue and its impact, for example "a crafted advisory record makes the
  planner recommend a downgrade" or "a malicious `composer.json` in the analysed project executes
  code during planning";
- reproduction steps or a proof of concept;
- whether you want to be credited in the advisory.

You will receive an acknowledgement within 3 working days and a first assessment within 10 working
days. We will agree on a disclosure timeline with you; the default is coordinated disclosure within
90 days of the report, sooner when a fix is available.

If you cannot use GitHub's form, email the maintainer at the address listed in the `authors` field
of `composer.json` with "composer-remediate security" in the subject line.

## Scope

In scope:

- code execution or file modification triggered by analysing a project (the planner must never run
  project scripts or plugins, and must never write to the analysed project);
- incorrect remediation results caused by crafted advisory or package metadata, including
  recommending a version that is still vulnerable;
- tampering with or spoofing of published advisory database artifacts or their manifests;
- leakage of project data beyond what is documented in the privacy page.

Out of scope:

- vulnerabilities in Composer itself or in third-party packages the tool reports on (report those
  upstream; the [FriendsOfPHP security advisories](https://github.com/FriendsOfPHP/security-advisories)
  repository is the right place for PHP package advisories);
- the quality of advisory data from upstream sources;
- issues that require a compromised local machine or a compromised Composer installation.

## Security design notes

- Planning never executes the analysed project's scripts or plugins and never writes to its files.
  Candidate solves run in a temporary copy that is deleted afterwards.
- Advisory data is treated as untrusted input: it influences which versions are considered fixed,
  and every recommendation is still validated by re-checking the resulting lock against the same
  data. It is never executed or interpolated into commands without quoting.
- Published database artifacts will ship with checksums and signatures; see the roadmap.
