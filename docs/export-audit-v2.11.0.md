# plpgsql_check v2.11.0 — source-specific Windows export audit

Date: 2026-11-18 (JST). Nonpublishing technical source review for the v2.11.0
candidate (pgextwin/plpgsql_check#103).

## Immutable provenance

- Previously protected manifest source: `okbob/plpgsql_check@9a5c0ec4babebd5eb8e0db104c54f7ddb43fcc07` (v2.10.16).
- Newly reviewed candidate source: `okbob/plpgsql_check@e8bbdc6f5923c1096c6de52f93db83aa693e64d0` (v2.11.0).
- GitHub immutable compare: https://github.com/okbob/plpgsql_check/compare/9a5c0ec4babebd5eb8e0db104c54f7ddb43fcc07...e8bbdc6f5923c1096c6de52f93db83aa693e64d0 — 76 commits. Changes to behavior/tests are **not** assumed semantically equivalent.
- Independently retrieved upstream Git trees at both commits: `LICENSE` blob `994f55c62ea0dfedfd915d1559f8f27d386d4989` is byte-identical at Git blob level. `plpgsql_check.control` blob changed (`ee008a0dc9f9d40545e59af2571983c794b574d0` → `bdb7154d5f1792d2c48ff026222488cb24630464`, `default_version` `2.10` → `2.11`). The SQL installer was renamed `plpgsql_check--2.10.sql` (blob `b7c9a172bd79f10fe15ba6417f14da1dce31e746`) → `plpgsql_check--2.11.sql` (blob `07f3b7dbad1c734852c7ddb298a22a97a4b26a89`).
- 17 of the 20 `src/*.c` files changed; 3 unchanged. Independently read **all 20 current `src/*.c` files** at exact new SHA, cross-checked `PG_FUNCTION_INFO_V1` symbol names against the immutable SQL installer's `AS 'MODULE_PATHNAME', '<symbol>' LANGUAGE C` declarations. Both lists contain **23 distinct and identical entries**, exactly those in the new audit file — the same 23-symbol set as v2.10.16; no new/deleted exports. Source module magic and `void _PG_init(void)` remain in `src/plpgsql_check.c`. Expected Windows export set remains 48 symbols (23 SQL entries, 23 `pg_finfo_` names, `Pg_magic_func`, `_PG_init`).

## Version generalization

- The SQL extension version moved `2.10` → `2.11`, so the previously hardcoded
  `'2.10'` in `windows/ci/build.ps1`, `windows/ci/install.ps1`,
  `windows/ci/smoke-test.ps1`, and `tests/test_source_export_binding.py` is now
  derived from a real source (manifest `upstream.version` major.minor in the
  build/test path, the upstream control file's `default_version` in the
  install/smoke path) and cross-checked against the real upstream control file
  at build time. Any mismatch still fails closed. `config/export-audit.json`
  stays bound to the v2.10.15 protected main.

## Approval boundary

- The source-specific reviewed 2.11.0 ABI contract is stored in `config/export-audits/e8bbdc6f5923c1096c6de52f93db83aa693e64d0.json`. Existing `config/export-audit.json` stays bound to v2.10.15 protected main. Selection is *by exact 40-character upstream SHA*; no mutable latest/ref, auto-approval or unverified audit identity. Export names, count, SQL/C identity and DLL `dumpbin` checks stay mandatory for each maintained PostgreSQL major.

Only after original required PR CI succeeds, protected main merge and **new** Windows main/push succeeds may the new source be considered for signed attestation and independently authorized formal publication. `manual-only`, `PUBLISH_DENY`, `GO B/G4/G5 NO_GO` are unchanged. This technical review itself is neither Release approval nor proof of signed/published assets.
