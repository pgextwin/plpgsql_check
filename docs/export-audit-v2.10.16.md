# plpgsql_check v2.10.16 — source-specific Windows export audit

Date: 2026-10-26 (JST). Nonpublishing technical source review for pgextwin/build#75.

## Immutable provenance

- Previously protected manifest source: `okbob/plpgsql_check@0ac96adc13b34d071c4be8ba0ec4f73e6e7520f5` (v2.10.15).
- Newly reviewed candidate source: `okbob/plpgsql_check@9a5c0ec4babebd5eb8e0db104c54f7ddb43fcc07` (v2.10.16).
- GitHub immutable compare: https://github.com/okbob/plpgsql_check/compare/0ac96adc13b34d071c4be8ba0ec4f73e6e7520f5...9a5c0ec4babebd5eb8e0db104c54f7ddb43fcc07 — 2 commits; 16 changed paths. Changes to behavior/tests are **not** assumed semantically equivalent.
- Independently retrieved upstream Git trees at both commits: `plpgsql_check--2.10.sql` blob `b7c9a172bd79f10fe15ba6417f14da1dce31e746`, `LICENSE` blob `994f55c62ea0dfedfd915d1559f8f27d386d4989`, `plpgsql_check.control` blob `ee008a0dc9f9d40545e59af2571983c794b574d0` are byte-identical at Git blob level.
- The only changed C blobs are `src/assign.c`, `src/check_function.c`, `src/plpgsql_check.c`; all other C blobs under `src/` are unchanged. Changes adjust record-field/tuple descriptor handling and the version string. No new/deleted `PG_FUNCTION_INFO_V1` exports or module entry-point declarations occur in those three changed files.
- Independently read **all 20 current `src/*.c` files** at exact new SHA, cross-checked `PG_FUNCTION_INFO_V1` symbol names against the immutable SQL installer's `AS 'MODULE_PATHNAME', '<symbol>' LANGUAGE C` declarations. Both lists contain **23 distinct and identical entries**, exactly those in `config/export-audit.json.requiredSqlSymbols`. Source module magic and `void _PG_init(void)` remain in `src/plpgsql_check.c`. Expected Windows export set remains 48 symbols (23 SQL entries, 23 `pg_finfo_` names, `Pg_magic_func`, `_PG_init`).

## Actual candidate corroboration and remaining gates

- Authentic schedule-created bot draft candidate [#79](https://github.com/pgextwin/plpgsql_check/pull/79) is **manifest-only**, source SHA `9a5c0ec4babebd5eb8e0db104c54f7ddb43fcc07`.
- Separate `workflow_dispatch` candidate [Run40227911216](https://github.com/pgextwin/plpgsql_check/actions/runs/40227911216) has App15368 PG14–18/resolver/required summary and independent ZIP/SPDX/Grype candidate-audit checks 8/8 SUCCESS; overall Run FAILURE due the source-specific audit regression on the previously unreviewed SHA. This proves candidate compilation/audit, **not** an approved native PR run or independent signature.
- The original `event=pull_request` run [40227913429](https://github.com/pgextwin/plpgsql_check/actions/runs/40227913429) is `action_required`, jobs 0. It must not be represented as successful.

## Approval boundary

The source-specific reviewed 2.10.16 ABI contract is stored in `config/export-audits/9a5c0ec4babebd5eb8e0db104c54f7ddb43fcc07.json`. Existing `config/export-audit.json` stays bound to v2.10.15 protected main. Selection is *by exact 40-character upstream SHA*; no mutable latest/ref, auto-approval or unverified audit identity. Export names, count, SQL/C identity and DLL `dumpbin` checks stay mandatory for each maintained PostgreSQL major.

Only after original required PR CI succeeds, protected main merge and **new** Windows main/push succeeds may the new source be considered for signed attestation and independently authorized formal publication. `manual-only`, `PUBLISH_DENY`, `GO B/G4/G5 NO_GO` are unchanged. This technical review itself is neither Release approval nor proof of signed/published assets.
