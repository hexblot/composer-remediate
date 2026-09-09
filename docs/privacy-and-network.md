# Privacy and network behaviour

## The promise

> No third party sees your dependency graph. Network use is exactly what `composer update` itself
> would do against the repositories you have configured.

This is deliberately narrower than "fully offline". Composer's solver needs package metadata for
every version it considers, and it fetches that from the repositories in your `composer.json`,
normally packagist.org. A remediation planner that validates with Composer's solver therefore
performs the same metadata requests Composer performs during an update. Those requests reveal
package names to the repository, as any `composer update` does.

## What leaves the machine

| Data | Sent to | When |
|---|---|---|
| Package names in your lock file | Advisory source (Packagist by default) | Advisory lookup, Phase 0 and 1. Same request `composer audit` makes: a POST of up to 500 names per batch. Versions are not sent; matching happens locally. |
| Package names being resolved | Your configured Composer repositories | Solver validation, identical to `composer update`. Served from the Composer cache when possible. |
| Nothing else | | No telemetry, no accounts, no project files. |

Private repositories configured in `composer.json` or `auth.json` are used exactly as Composer
uses them, because the plugin runs inside your Composer.

## `--offline`

With `--offline` the planner sets Composer's `COMPOSER_DISABLE_NETWORK` before doing anything.
Composer then answers cached metadata as "not modified" and fails any request that is not in the
cache. If a solve needs metadata that is missing, the planner stops with a clear error instead of
falling back to the network.

The advisory database work in Phase 2 removes the first row of the table above: advisories are
read from a local SQLite file that you build yourself or download once.
