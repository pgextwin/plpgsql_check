# plpgsql_check v2.10.14 — Windows export ABI technical audit

Date: 2026-10-11 (JST)

## Pinned source and comparison

- Previously audited upstream: `okbob/plpgsql_check@61776b0af7418d3fd593cccea73178e3d93c9ee1` (v2.10.13).
- Newly audited upstream: `okbob/plpgsql_check@ccdbcce9de51f01e1138c270aeb9fe4e26c6e911` (v2.10.14).
- Immutable diff: https://github.com/okbob/plpgsql_check/compare/61776b0af7418d3fd593cccea73178e3d93c9ee1...ccdbcce9de51f01e1138c270aeb9fe4e26c6e911
- Comparison: 19 upstream commits, 47 changed files. Source/behavior and regression fixtures changed and **must not** be assumed functionally equivalent to v2.10.13, but no change in exported SQL/C binding identity was detected.
- `plpgsql_check--2.10.sql` was not among the changed files (the install SQL contract remains the same).
- Among changed `src/*.c` patches, no added/removed `PG_FUNCTION_INFO_V1`, `PG_MODULE_MAGIC` or `_PG_init` definitions/declarations were detected. SQL test fixture changes are not SQL MODULE_PATHNAME exports.

## Independent technical cross-check (no independent human PR approval)

The packaging `windows/ci/build.ps1` re-audits the actual pinned upstream checkout for every PG major. It verifies each of the **23** names in `config/export-audit.json` exists both in the actual `PG_FUNCTION_INFO_V1` C declarations and in `plpgsql_check--2.10.sql` MODULE_PATHNAME entry points, and rejects any extra/missing C or SQL symbols. It emits `pgextwin.exports.def` containing the 23 SQL entry points, 23 matching `pg_finfo_*` entry points, plus `Pg_magic_func` and `_PG_init`. The compiled DLL is checked with `dumpbin /exports` against all **48** names.

Evidence from the **successful, SHA-matched** [Windows candidate workflow_dispatch 38120999663](https://github.com/pgextwin/plpgsql_check/actions/runs/38120999663) and its 5 Windows PG14–18 jobs includes:

- PG14: `Verified 48 DLL exports for PG14 from pinned ccdbcce9de51f01e1138c270aeb9fe4e26c6e911.`
- PG18: `Verified 48 DLL exports for PG18 from pinned ccdbcce9de51f01e1138c270aeb9fe4e26c6e911.`
- PG15,16,17: same exact export-contract verification step, all jobs SUCCESS.
- [candidate-audit artifact 11694809453](https://github.com/pgextwin/plpgsql_check/actions/runs/38120999663/artifacts/11694809453) status VERIFIED for PG14–18; per-major ZIP/SBOM/Grype identities and SHA256 recorded.

## Acceptance and release boundary

This source-specific technical audit allows `config/export-audit.json.upstreamCommit` to be pinned to v2.10.14 **without changing its symbol names, counts, module magic or initializer**. On main and formal Release builds the pinned audit SHA must exactly match `config/extension.json.upstream.commit`; an unreviewed new upstream SHA remains fail-closed. A pull_request or owned candidate workflow may test new source without falsely authorizing formal release.

This audit does **not** approve a new Release and does not replace the final signed-build and promotion validation. Publishing remains main-only, human-operator initiated `workflow_dispatch` with explicit `confirm_release=PUBLISH`, full PG-major runtime/build validation, immutable upstream pin, attestation and SHA256 checks, and create-only tag reservation. Separate human approval and approval-JSON PR are not required.
