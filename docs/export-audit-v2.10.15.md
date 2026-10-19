# plpgsql_check v2.10.15 — independent source-specific Windows export audit

Scope: GitHub-only source audit for the existing **normal and candidate** Windows CI, and the source-specific export guard used by formal Release builds. **Not** a new formal Release, signing approval, authorization to publish, or a waiver for any historical failed run.

## Fixed, reviewed identities

- Packaging manifest on protected main: `config/extension.json`, upstream `okbob/plpgsql_check`, tag `v2.10.15`, full SHA `0ac96adc13b34d071c4be8ba0ec4f73e6e7520f5`.
- GitHub public annotated upstream tag object `f37e7f26896ff20e15a7ff6add2793245270a9ad` resolves to **exactly** that commit. Do not describe this upstream tag as a verified cryptographic signature.
- [Immutable upstream SQL installer](https://github.com/okbob/plpgsql_check/blob/0ac96adc13b34d071c4be8ba0ec4f73e6e7520f5/plpgsql_check--2.10.sql) `plpgsql_check--2.10.sql`: 23 distinct `AS 'MODULE_PATHNAME', '<symbol>' LANGUAGE C` references.
- [Immutable upstream src directory](https://github.com/okbob/plpgsql_check/tree/0ac96adc13b34d071c4be8ba0ec4f73e6e7520f5/src): all **22 .c source files** obtained by GitHub GET at this exact SHA. `PG_FUNCTION_INFO_V1` references: `pragma.c` 1, `profiler.c` 9, `tablefunc.c` 12, `tracer.c` 1, all other C files zero; total **23 distinct**.
- Both 23-item sets exactly match the pre-existing reviewed `config/export-audit.json.requiredSqlSymbols`. No additions, removals, duplicate names or mismatches. Module magic `PG_MODULE_MAGIC` and `_PG_init` are still required by `windows/ci/build.ps1`. Export count is **48** = 23 SQL entry points + 23 `pg_finfo_*` + `Pg_magic_func` + `_PG_init`.
- Upstream `v2.10.14...v2.10.15` 22-commit comparison changes C sources and tests, but **not** `LICENSE`, `plpgsql_check.control` or the installed `plpgsql_check--2.10.sql`. The compilation and functional tests remain mandatory.

## Independent Windows corroboration

[Candidate Windows Run 39021934569](https://github.com/pgextwin/plpgsql_check/actions/runs/39021934569) is `workflow_dispatch`, first attempt, exact candidate head `4899b5c1da8e2fb681381fff4fa2ab41882cb0bc` and **SUCCESS**; all PG14–18 Windows jobs verified 48 DLL exports and executed real PostgreSQL `CREATE EXTENSION` / invalid-record-field functional checks. Package, SPDX and Grype **report-only** validation passed. Candidate audit bound all five SHA256 ZIP identities to immutable upstream source SHA. These unsigned candidate artifacts are **not** a substitute for new signed formal Release assets.

## Correction and non-bypass

Original unmodified postmerge [Run 39182588101](https://github.com/pgextwin/plpgsql_check/actions/runs/39182588101) detected a **stale old `upstreamCommit`** in `config/export-audit.json` after the reviewed v2.10.15 candidate was merged. PG14 stopped at `build.ps1:65` with **"A new formal release requires a source-specific independent export audit."** This was a correct fail-closed check, not an installer or license mismatch. That original failed run is never counted as SUCCESS.

This correction changes only the audit's reviewed `upstreamCommit` to the exact v2.10.15 source SHA, keeps the same 23 independently matched symbols and unchanged DLL/magic/SQL requirements, and adds tests that reject stale/tampered source identity or removal of the main-branch guard. **No skip condition, exception, silent approval, bypass, or production credential is introduced.**

## Acceptance boundary

Exact-head protected PR CI, native Windows 5/5 postmerge CI and all required checks are still mandatory; if a test fails, acceptance remains blocked. This is **normal build/source export readiness only**. Signing, Sigstore OIDC, independently isolated Writer credentials, verified manual Publisher evidence, formal Release, Catalog changes and public Website changes are **not claimed**. GO B/G4/G5 remain NO_GO and historical P1 DENY evidence remains unchanged.
