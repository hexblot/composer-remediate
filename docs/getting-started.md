# Getting started

!!! warning "Pre-alpha"
    Nothing is published on Packagist yet. These instructions describe the intended
    installation path and the current development setup.

## Requirements

| Requirement | Minimum | Notes |
|---|---|---|
| PHP | 8.1 | |
| Composer | 2.4 | `composer audit` and transitive `--with` constraints appeared in 2.4 |
| Composer, full feature set | 2.9 | `--minimal-changes` (`-m`) appeared in 2.9; on older versions the planner omits it and warns that diffs may be larger |

## Installation (intended)

Globally, so it is available in every project without touching their `composer.json`:

```bash
composer global config allow-plugins.hexblot/composer-remediate true
composer global require hexblot/composer-remediate
```

Or per project as a dev dependency:

```bash
composer config allow-plugins.hexblot/composer-remediate true
composer require --dev hexblot/composer-remediate
```

## Usage

```bash
composer remediate            # analyse composer.lock, print a plan, change nothing
composer remediate --format=json
composer remediate --offline  # fail instead of touching the network (needs a warm Composer cache)
```

The plugin never writes to `composer.json`, `composer.lock` or `vendor/`. Every recommendation is a
plain `composer update` command you run yourself.

## Developing the plugin

The repository ships a [ddev](https://ddev.com) configuration; no local PHP is required.

```bash
ddev start
ddev composer install
ddev composer check          # phpstan level 8 + phpunit
ddev composer test:fixtures  # the historical fixture suite only
```

Documentation:

```bash
pipx run --spec mkdocs-material mkdocs serve
```
