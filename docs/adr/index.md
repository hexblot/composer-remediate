# Architecture decision records

Each record states the decision, the alternatives considered, and the consequences. Records are
numbered in the order they were made and are never deleted; a superseded record links to its
replacement.

| # | Decision | Status |
|---|---|---|
| [0001](0001-composer-plugin.md) | Ship as a Composer plugin, not a standalone CLI | accepted |
| [0002](0002-candidates-are-commands.md) | Remediation candidates are `composer update` commands | accepted |
| [0003](0003-in-process-solver.md) | Validate candidates with an in-process `Installer` dry-run, subprocess fallback | accepted |
| [0004](0004-privacy-promise.md) | Promise "no third party sees your graph", not "fully offline" | accepted |
| [0005](0005-advisory-database.md) | Advisory database is built locally from live sources and may be shared centrally | accepted |
| [0006](0006-frozen-fixtures.md) | Fixtures freeze package metadata, not just advisories | accepted |
| [0007](0007-composer-floor.md) | Composer 2.4 minimum, 2.9 for the full feature set | accepted |
| [0008](0008-isolate-internals.md) | Touch Composer's `@internal` classes only inside adapters | accepted |
| [0009](0009-parent-descent.md) | Search downwards for the lowest parent version that admits the fix | accepted |
| [0010](0010-disable-blocking-in-solves.md) | Disable Composer's advisory blocking inside candidate solves | accepted |
