# CI integration

`composer remediate` is designed to run as a gate. It needs only `composer.json` and
`composer.lock`, changes nothing, and reports through its exit code and its report files.

## Exit codes and what to gate on

| Exit | Meaning | Typical gate policy |
|---|---|---|
| `0` | No known vulnerabilities in the lock | pass |
| `1` | Vulnerabilities found **and** a verified fix exists | **fail**: the fix is one command away, apply it |
| `2` | At least one vulnerability has **no** verified fix | fail or warn, see below |
| `3` | Tool error (no lock file, bad option) | fail, fix the pipeline |
| `4` | Advisory data unavailable (network, bad snapshot) | fail or retry, this is infrastructure |
| `5` | Package metadata could not be fetched during solving | fail or retry, this is infrastructure |

Two sensible policies:

- **Strict**: anything other than `0` fails the job. Simple, and the right default for
  applications that must not ship known vulnerabilities.
- **Actionable**: fail on `1` (a verified fix exists and should be applied), report `2` as a warning
  (no fix exists yet; failing the build would block every deploy until upstream releases one), fail
  on `3` to `5` because the tool did not do its job. Record accepted risks with
  `config.audit.ignore` in `composer.json` so exit `2` stays meaningful.

Whichever you choose, keep the HTML or JSON report as a build artifact: the report says exactly
what to run.

## Installing in CI

The plugin is installed globally so it does not touch the project's `composer.json`:

```bash
composer global config --no-plugins allow-plugins.hexblot/composer-remediate true
composer global require hexblot/composer-remediate
```

Requirements: PHP 8.1+ and Composer 2.4+ (2.9+ for `--minimal-changes`). Solving needs package
metadata from your configured repositories, so cache Composer's cache directory between runs
(`composer config --global cache-dir` prints it; usually `~/.composer/cache` or
`~/.cache/composer`). Private repositories and `auth.json` work as they do for `composer update`.

## GitHub Actions

```yaml
name: dependency-remediation
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 6 * * 1-5'   # advisories arrive without commits; check on a schedule too

jobs:
  remediate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: shivammathur/setup-php@v2
        with:
          php-version: '8.4'
          tools: composer:v2
      - uses: actions/cache@v4
        with:
          path: ~/.cache/composer
          key: composer-${{ hashFiles('composer.lock') }}
          restore-keys: composer-
      - run: |
          composer global config --no-plugins allow-plugins.hexblot/composer-remediate true
          composer global require hexblot/composer-remediate
      - name: Plan remediation
        id: plan
        run: |
          set +e
          composer remediate --no-dev --output=remediation-report.html --output=remediation-report.json
          echo "code=$?" >> "$GITHUB_OUTPUT"
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: remediation-report
          path: remediation-report.*
      - name: Gate
        run: |
          case "${{ steps.plan.outputs.code }}" in
            0) echo "No known vulnerabilities." ;;
            1) echo "::error::Vulnerable dependencies with a verified fix. See the remediation report."; exit 1 ;;
            2) echo "::warning::Vulnerable dependencies without a verified fix yet. See the remediation report." ;;
            *) echo "::error::composer remediate failed (exit ${{ steps.plan.outputs.code }})."; exit 1 ;;
          esac
```

Switch the `2)` branch to `exit 1` for the strict policy. Add `--fail-on high` to the
`composer remediate` call to let low and medium findings pass without affecting the exit code
(unknown severities always count). To surface the recommended command in the job summary:

```bash
jq -r '.summary.combined_command // "no verified fix"' remediation-report.json >> "$GITHUB_STEP_SUMMARY"
```

### GitHub Code Scanning

`--output=results.sarif` writes a SARIF 2.1.0 file: one rule per advisory with a
`security-severity` score, one result per vulnerable package pointing at its line in `composer.lock`,
and the verified command in the message. Upload it and findings appear in the repository's Security
tab and as pull request annotations:

```yaml
      - run: composer remediate --no-dev --output=results.sarif --output=remediation-report.html || true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: composer-remediate
```

The `|| true` keeps the upload step reachable; gate on the exit code in a separate step as shown
above (or capture it with `set +e` as in the full example).

### SBOM with remediation

`--output=sbom.cdx.json` writes a CycloneDX 1.6 SBOM of the whole lock with every advisory attached
as a vulnerability and the verified command in its `recommendation`. Attach it as an artifact or feed
it to Dependency-Track, Grype or any other CycloneDX consumer.

## GitLab CI

```yaml
remediate:
  stage: test
  image: composer:2
  cache:
    key: composer-$CI_COMMIT_REF_SLUG
    paths: [.composer-cache]
  variables:
    COMPOSER_CACHE_DIR: $CI_PROJECT_DIR/.composer-cache
  before_script:
    - composer global config --no-plugins allow-plugins.hexblot/composer-remediate true
    - composer global require hexblot/composer-remediate
  script:
    - set +e
    - composer remediate --no-dev --output=remediation-report.html --output=remediation-report.json
    - code=$?
    - set -e
    - |
      case "$code" in
        0) echo "No known vulnerabilities." ;;
        1) echo "Vulnerable dependencies with a verified fix; see the report."; exit 1 ;;
        2) echo "Vulnerable dependencies without a verified fix yet; see the report."; exit 0 ;;
        *) echo "composer remediate failed (exit $code)."; exit 1 ;;
      esac
  artifacts:
    when: always
    paths: [remediation-report.html, remediation-report.json]
    expire_in: 30 days
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
    - if: $CI_PIPELINE_SOURCE == "schedule"
```

Use `allow_failure: { exit_codes: [2] }` instead of the `exit 0` branch if you prefer GitLab to show
the job as passed-with-warnings.

## Custom gates on the JSON report

The JSON report makes finer policies possible without parsing text:

```bash
# fail only on high or critical advisories that have a verified fix
jq -e '[.findings[] | select(.remediation.status == "verified")
        | select(any(.advisories[]; .severity == "high" or .severity == "critical"))] | length == 0' \
   remediation-report.json
```

```bash
# print the one command that fixes everything (or as much as possible)
jq -r '.summary | if .combined_command then
         "\(.combined_command)  (fixes \(.combined_fixes)/\(.combined_total))" else "no verified fix" end' \
   remediation-report.json
```

Fields worth knowing: `exit_code`, `summary.combined_command`, `summary.combined_fixes`,
`summary.combined_total`, `findings[].remediation.status` (`verified` or `none`),
`findings[].remediation.command`, `findings[].advisories[].severity`, `unsolved_findings[]`.

## Tips

- Run on a schedule as well as on pushes: advisories are published without any change to your
  repository.
- `--no-dev` gates production dependencies only; drop it to include tooling.
- Accepted risks belong in `composer.json` (`config.audit.ignore`, or `config.policy.advisories.ignore`
  on Composer 2.10+) so the same decision applies to `composer audit` and to this tool.
- For air-gapped runners, `--offline --advisories-file=<snapshot>` works with a warm Composer cache.
