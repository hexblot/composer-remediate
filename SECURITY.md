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

- code execution or file modification triggered by analysing a project through the
  `composer-remediate` binary (nothing from the analysed project may run), and any write to the
  analysed project through either entry point;
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

- Two entry points with different guarantees. `composer remediate` is a Composer plugin command:
  Composer has already activated the analysed project's other allowed plugins before it runs, as for
  any Composer command; the planner itself then solves every candidate in fresh Composer instances
  with plugins and scripts disabled. `composer-remediate` (the shipped binary) forces
  `--no-plugins --no-scripts` from the first instruction and never includes a project's
  `vendor/autoload.php` (whose `autoload.files` are project code), so nothing from the analysed
  project executes, including when the binary is installed inside that project. Neither entry point
  writes to the analysed project; candidate solves run in a temporary copy that is deleted afterwards,
  and the subprocess solver pins `COMPOSER` to that copy so an inherited `COMPOSER` variable cannot
  point an update at the real lock file. Both properties have regression tests.
- Absence of data is never a clean result: no advisory-capable repository, a malformed advisory
  document or an unparsable range stop the run with exit 4 instead of reporting zero findings, and a
  solver or network failure during the search yields exit 3 or 5 rather than "no fix exists". An
  advisory database keeps the upstream records its build could not interpret as coverage gaps; a run
  reports every gap that names a package in the lock and every gap that could not be attributed to any
  package, exits 4 for a lock without findings unless the gaps are accepted, and rejects a fix that adds
  a package with such records unless they are accepted. Coverage gaps are part of the dataset hash, so a
  build whose gaps changed is published and is not mistaken for the same data.
- Advisory data is treated as untrusted input: it influences which versions are considered fixed,
  and every recommendation is still validated by re-checking the resulting lock against the same
  data. It is never executed or interpolated into commands without quoting.
- Published database artifacts ship with a sha256 sidecar, a `latest.json` (sha256, dataset hash,
  publication time) and a GitHub build-provenance attestation. The client refuses a download whose
  digest does not match the published one, does not download at all from a source that publishes no
  digest unless `--allow-unverified-database` is given (and then says so in every report that uses the
  copy), and honours `--database-sha256` as the trust anchor on every path that selects a database,
  including a local file named as the source. The attestation is verified with
  `gh attestation verify`, not by the plugin.
- The analysed project's `composer.json` is untrusted input. Its `extra.remediate.database` may choose
  the advisory source, but that source is kept in a file of its own and the report says the project
  chose it; its `extra.remediate.database_path` must be a relative path inside the project, and
  content at such a path counts only when it matches what the publisher serves; its `config.cache-dir`
  does not move the default database path, and which configuration counts as the operator's is decided
  from configuration the project never contributed to, so setting `config.home` as well changes
  nothing; TLS settings it supplies (`cafile`, `capath`, `disable-tls`) are reported. A scan
  never writes outside the checkout being scanned unless the operator asked for it (`--database-path`,
  `REMEDIATE_DATABASE_PATH`), never replaces a file that is not an advisory database, and never lets a
  copy downloaded from one source pass as current for another.
