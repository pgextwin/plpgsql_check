# plpgsql_check v2.11.1 — source-specific Windows export audit

Date: 2026-11-24 (JST). Nonpublishing technical source review for the v2.11.1 candidate (pgextwin/plpgsql_check#114).

## Immutable provenance

- The previous reviewed manifest source was `okbob/plpgsql_check@e8bbdc6f5923c1096c6de52f93db83aa693e64d0` (v2.11.0).
- The newly reviewed candidate source is `okbob/plpgsql_check@08fe12edb7a2ea4de15a43722729948414fce136` (v2.11.1). Candidate PR pgextwin/plpgsql_check#114 has branch `auto-candidate/3b6aea71a9523d2b431e` and head `20758d6e698a321b1fdfd8dd88b3c85602b6480b`.
- The immutable comparison shows 11 commits, ahead only. The review makes no assumption of semantic equivalence for behavior or test changes. [GitHub comparison](https://github.com/okbob/plpgsql_check/compare/e8bbdc6f5923c1096c6de52f93db83aa693e64d0...08fe12edb7a2ea4de15a43722729948414fce136)
- The upstream tarball review confirmed that `LICENSE` is byte-identical at both commits, with Git blob `994f55c62ea0dfedfd915d1559f8f27d386d4989`, a size of 1333 bytes, and SHA-256 `4a809aded5299bdab8903901a1a06bf1cafc6fec8bb4cd803b0389fc8333fe1f`. `plpgsql_check.control` has blob `bdb7154d5f1792d2c48ff026222488cb24630464` at both commits. Its `default_version` stayed at `'2.11'`, so no version generalization was needed. The `plpgsql_check--2.11.sql` installer is byte-identical at both commits, with blob `07f3b7dbad1c734852c7ddb298a22a97a4b26a89`.
- Six of the 20 `src/*.c` files changed (`src/check_expr.c`, `src/check_function.c`, `src/pldbgapi3.c`, `src/plpgsql_check.c`, `src/stmtwalk.c`, and `src/typdesc.c`). The other changed files were `src/plpgsql_check.h`, `META.json`, `meson.build`, seven `postgresql*.spec` files, `sql/plpgsql_check_nocrash.sql`, `expected/plpgsql_check_nocrash.out`, and `expected/plpgsql_check_nocrash_1.out`.
- The review read all 20 `src/*.c` files at the exact candidate SHA and cross-checked the `PG_FUNCTION_INFO_V1` symbol names against the SQL installer's `AS 'MODULE_PATHNAME', '<symbol>' LANGUAGE C` declarations. Both lists contain **23 distinct and identical entries**, matching the v2.11.0 audit exactly, with no new or deleted exports. `PG_MODULE_MAGIC` and `void _PG_init(void)` remain in `src/plpgsql_check.c`. The expected Windows export set remains 48 symbols (23 SQL entries, 23 `pg_finfo_` names, `Pg_magic_func`, and `_PG_init`).

## Approval boundary

- The source-specific reviewed 2.11.1 ABI contract is stored in `config/export-audits/08fe12edb7a2ea4de15a43722729948414fce136.json`. The existing `config/export-audit.json` stays bound to v2.10.15 protected main. Selection requires a verified audit identity matched by the exact 40-character upstream SHA. Export names, count, SQL/C identity, and DLL `dumpbin` checks stay mandatory for each maintained PostgreSQL major.

Only after the original required PR CI succeeds, the PR merges into protected main, and a **new** Windows main/push run succeeds may the new source be considered for signed attestation and independently authorized formal publication. The existing `manual-only`, `PUBLISH_DENY`, and `GO B/G4/G5 NO_GO` gates still apply. This technical review itself is neither Release approval nor proof of signed or published assets.
