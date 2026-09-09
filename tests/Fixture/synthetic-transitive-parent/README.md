# synthetic-transitive-parent

Synthetic fixture (not a historical project) used to prove the harness plumbing before real
fixtures are added.

- Root requires `acme/app-framework ^1.0`, locked at 1.0.0.
- `acme/app-framework 1.0.x` requires `acme/vuln-lib ~1.0.0`; the lock holds `acme/vuln-lib 1.0.1`.
- Advisory CVE-2026-00001 affects `acme/vuln-lib <1.1.0`.
- Available: app-framework 1.0.0, 1.0.1, 1.1.0 (requires vuln-lib ^1.1), 1.2.0 (^1.1, helper ^1.2), 2.0.0 (^2.0 everywhere).

Expected human choice: `composer update acme/app-framework:1.1.0 -W -m`, landing on app-framework 1.1.0 and
vuln-lib 1.1.1 with `acme/helper` untouched (2 changes). A plain `composer update acme/app-framework -W -m`
jumps to app-framework 1.2.0, which also drags `acme/helper` to 1.2.0 (3 changes); the planner's parent
descent finds the lower version. Updating vuln-lib alone yields 1.0.4, still
vulnerable; updating it with dependencies conflicts with the parent constraint `~1.0.0`; widening the
root constraint to `^2.0` is valid but changes three packages and crosses a major version.

The lock file was generated with Composer against `repo/packages.json`.
