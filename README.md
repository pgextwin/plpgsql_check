# plpgsql_check for Windows — pgextwin Step 16 technical pilot

[日本語](README_ja.md) | English

**Status: source integration proposed; NOT a published binary release.** This repository is intended for the `pgextwin` organization. It packages **unofficial** Windows x64 builds of [plpgsql_check](https://github.com/okbob/plpgsql_check). The project and its source are maintained by upstream, not by pgextwin.

## Source, compatibility and provenance

- Upstream stable release: [`v2.10.13`](https://github.com/okbob/plpgsql_check/releases/tag/v2.10.13) (published 2026-10-07 UTC).
- Annotated tag object SHA: `72fa03e2bfc78289bdb4ef732024eefb5e707c64`.
- Resolved pinned commit SHA: `61776b0af7418d3fd593cccea73178e3d93c9ee1`.
- PostgreSQL target majors: **15, 16, 17, 18** on Windows x64. Neither PostgreSQL 14 nor 19 is part of this pilot.
- Upstream release version is **2.10.13**, but `plpgsql_check.control` declares **SQL extension version 2.10**, installed from `plpgsql_check--2.10.sql`. This is intentional and verified against the pinned tree.
- License: upstream `LICENSE` contains MIT permission/notice text. The packaged license is byte-for-byte the upstream file; its Git blob SHA is `994f55c62ea0dfedfd915d1559f8f27d386d4989`.

## What is validated

The essential function of this extension is static checking of PL/pgSQL functions. CI starts an isolated PostgreSQL instance, creates an empty table and a PL/pgSQL function referencing `r.missing` in a loop over that empty table, and calls `plpgsql_check_function_tb` to check that the missing field is diagnosed **without executing the function**. The test then corrects the function, confirms the diagnostic is absent, and cleans up.

```sql
CREATE EXTENSION plpgsql_check;
CREATE TABLE public.t (a integer);
CREATE FUNCTION public.probe() RETURNS void LANGUAGE plpgsql AS $body$
DECLARE r record;
BEGIN
  FOR r IN SELECT a FROM public.t LOOP
    RAISE NOTICE '%', r.missing;
  END LOOP;
END;
$body$;
SELECT message, sqlstate, level
FROM plpgsql_check_function_tb('public.probe()'::regprocedure);
```

**Preloading:** Normal active diagnostics do not require `shared_preload_libraries` or `session_preload_libraries`. Optional passive tracing/profiling/shared-memory modes have different initialization and configuration considerations; they are **not validated by this pilot**. No background worker or client executable is required for this minimal use case.

## Installing a future validated ZIP

There are **no downloadable released ZIPs from this Step**. If a later release gate approves them, select the ZIP for your PostgreSQL major, stop your PostgreSQL server before replacing loaded binaries, then extract:

- `lib/plpgsql_check.dll` → PostgreSQL installation `lib/`.
- `share/extension/plpgsql_check.control` and `plpgsql_check--2.10.sql` → PostgreSQL installation `share/extension/`.
- Keep `LICENSE`, `UPSTREAM-README.md` and `PACKAGE-INFO.*` for attribution and provenance.

Restart the server as needed and execute `CREATE EXTENSION plpgsql_check;` in each intended database. Upstream documents optional modes and safety restrictions; refer to its README before enabling profiling/tracing in production.

## Build and CI integration

The [`pgextwin/build`](https://github.com/pgextwin/build) reusable **normal build** is referenced by an immutable full commit SHA. Four extension-owned Windows PowerShell hooks implement Hook Contract v1:

1. `build.ps1`: verify the checked-out upstream commit, PostgreSQL major, expected SQL/control files and Meson structure; discover SQL C entry points and PG_FUNCTION_INFO_V1 declarations; compare them against the independent 23-symbol export audit; generate a DEF file; adapt the *disposable* upstream Meson checkout; build with pinned Meson/Ninja and MSVC x64, and verify all required DLL exports using `dumpbin`.
2. `install.ps1`: copy the matching DLL, control file and upstream-provided SQL scripts into a disposable PostgreSQL installation.
3. `smoke-test.ps1`: initialize and start an isolated PG cluster without preload, test CREATE EXTENSION and the missing-record-field scenario, stop PG and remove temporary files in `finally`.
4. `package.ps1`: create and inspect a ZIP in `lib/`, `share/extension/` layout and preserve upstream license/readme.

The shared workflow handles Test Contract v2 validation, PACKAGE-INFO.json finalization, SPDX 2.3 SBOM generation, Grype **report-only** scanning, final checksums and CI artifacts. Normal CI does **not** produce build-provenance or SBOM attestations. The pilot workflow deliberately contains **no Release publishing job**. The Update Watch is release-metadata-only and can only create/update Issues; it never executes candidate sources, changes version pins or publishes binaries.

## Limitations / release gates

- Windows build, PostgreSQL startup, DLL symbols and functional assertions require actual GitHub Windows runner execution. These are **unverified until CI passes on all four majors**.
- The main CI validates the *active diagnostic path only*. Profiler, tracer, passive checks, shared mode, SQL upgrades and cross-major upgrades remain **not covered**.
- Windows PostgreSQL's `postgres.lib` and PL/pgSQL's dynamically loaded internal function surface are possible integration blockers. The build does not mask unresolved imports or test failures.
- The Meson DEF customization applies to an SHA-verified throwaway checkout only, never upstream. An unexpected source layout aborts the build.
- No GitHub Release, Distribution Catalog entry, website download URL or PG19 production metadata update is authorized here.

See [technical notes](docs/technical-pilot.md) for the intended quality gates and follow-up work.

## Local preflight

Run `python -m unittest discover -s tests -v` for offline structural sanity checks. Passing these checks does not replace Windows CI.
