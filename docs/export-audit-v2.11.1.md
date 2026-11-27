# plpgsql_check v2.11.1 — source-specific Windows export audit

Reviewed 2026-11-27 for the v2.11.1 candidate in [pgextwin/plpgsql_check#116](https://github.com/pgextwin/plpgsql_check/pull/116).

## Immutable provenance

- Previously reviewed source `okbob/plpgsql_check@e8bbdc6f5923c1096c6de52f93db83aa693e64d0` (v2.11.0). Newly reviewed source `okbob/plpgsql_check@08fe12edb7a2ea4de15a43722729948414fce136` (v2.11.1). The range contains 11 commits and 19 changed files. [Immutable upstream compare](https://github.com/okbob/plpgsql_check/compare/e8bbdc6f5923c1096c6de52f93db83aa693e64d0...08fe12edb7a2ea4de15a43722729948414fce136)
- The `LICENSE` blob is `994f55c62ea0dfedfd915d1559f8f27d386d4989` at both upstream commits and matches the candidate repository's license bytes. The control file and SQL installer also have identical blobs across the two upstream commits.
- Six of the 20 `src/*.c` files changed. I extracted every `PG_FUNCTION_INFO_V1` name from all 20 C files at the new SHA and independently extracted every `AS 'MODULE_PATHNAME', '<symbol>' LANGUAGE C` binding from `plpgsql_check--2.11.sql`. Both sets contain the same 23 distinct names. The C declarations occur in `pragma.c` (1), `profiler.c` (9), `tablefunc.c` (12), and `tracer.c` (1). Comparison with the v2.11.0 audit yielded zero additions and zero removals.
- `src/plpgsql_check.c` changed from blob `ccaf0acf970c7924c5a84bf8f2b32de7cda09ed0` to `73be39d8e724d81b27bfcfa25624cf681b1f9cb2`. It contains conditional `PG_MODULE_MAGIC_EXT` and `PG_MODULE_MAGIC` declarations and the `void _PG_init(void)` definition. The expected Windows DLL export set contains 48 names, with 23 SQL entry points, 23 corresponding `pg_finfo_` names, `Pg_magic_func`, and `_PG_init`.

## SQL extension version

- The control file declares `default_version = '2.11'` (blob `bdb7154d5f1792d2c48ff026222488cb24630464`). The installer is `plpgsql_check--2.11.sql` (blob `07f3b7dbad1c734852c7ddb298a22a97a4b26a89`).
- The Meson project version changed from `2.11.0` (blob `71017cc0cf04b47779927f2b7f8e255792653166`) to `2.11.1` (blob `1573430030cac8de07de737c1302919af4d8a756`). The candidate manifest's major.minor is `2.11`, matching the control file.

## Approval boundary

The [reviewed JSON record](../config/export-audits/08fe12edb7a2ea4de15a43722729948414fce136.json) binds the export contract to the full upstream SHA. Its symbol order comes from the pinned SQL installer. The Windows build selects the SHA-specific record and checks it against the C declarations, SQL bindings, and compiled DLL exports on each maintained PostgreSQL major.

This review covers the source export contract for candidate CI. Formal publication is governed by the repository's separate release process.
