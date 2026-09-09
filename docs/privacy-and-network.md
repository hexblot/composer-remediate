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

## The plugin boundary

`composer remediate` is a plugin command. Composer activates every plugin the analysed project
allows while it discovers plugin commands, so by the time `remediate` runs those plugins have
already executed, exactly as they do for `composer install` or `composer show`. The planner itself
then builds fresh Composer instances with plugins and scripts disabled for every candidate solve and
never writes to the project. For a project you maintain, that is the expected behaviour of any
Composer command. For a project you do not trust, use the `composer-remediate` binary installed
alongside the plugin: it boots Composer with `--no-plugins --no-scripts` forced from the first
instruction, so nothing from the analysed project runs, and it applies `--offline` before any HTTP
client exists.

## `--offline`

With `--offline` the planner sets Composer's `COMPOSER_DISABLE_NETWORK` before it builds its own
Composer instance (with `composer remediate`) or before Composer boots at all (with
`composer-remediate`).
Composer then answers cached metadata as "not modified" and fails any request that is not in the
cache. If a solve needs metadata that is missing, the planner stops with a clear error instead of
falling back to the network.

With an [advisory database](advisory-database.md) (`--database-location`) the first row of the
table disappears: advisories are read from a local SQLite file you built yourself or downloaded
once, and no package names are sent anywhere for the advisory lookup. A database URL is fetched
along with its `.sha256` sidecar; the download is verified against it, and a refresh that fails
falls back to the cached copy with a warning in the report naming its age.
