# Step 16 handoff and release gating notes

## Provenance

The v2.10.13 tag is an **annotated** Git tag. Its tag-object SHA is `72fa03e2bfc78289bdb4ef732024eefb5e707c64`, and the peeled source commit SHA is `61776b0af7418d3fd593cccea73178e3d93c9ee1`. The build hook verifies `git rev-parse HEAD` against the peeled SHA **before** editing Meson in the ephemeral upstream checkout. The packaging hook checks the same immutable identity. GitHub Releases describe it as a non-prerelease, non-draft stable release published 2026-10-07 20:20:46 UTC.

## Architecture

- `pgextwin/build` is the owner of matrix selection, Chocolatey PostgreSQL, Test Contract JSON Schema, PACKAGE-INFO.json, Syft, Grype, checksums and artifacts.
- This repository owns the C/SQL-aware MSVC/Meson DEF adaptation, runtime diagnostic smoke test, package layout, source-license mirror and documentation.
- The regular pilot caller uses no attestation permissions and no release job; its reusable build SHA is `2c6cd6a5b122f0ba1870e9d70cb84cc949bd281d`.
- The upstream license mirror must exactly match the `LICENSE` in the pinned source; repository copy Git blob must equal `994f55c62ea0dfedfd915d1559f8f27d386d4989`.

## Windows export contract

The v2.10.13 `src/plpgsql_check.c` includes both PG_MODULE_MAGIC_EXT and PG_MODULE_MAGIC branches, selected by PostgreSQL headers, and declares `_PG_init`. The PostgreSQL `PG_MODULE_MAGIC_EXT` still exports **Pg_magic_func**, not a renamed PG18 entry point. The pinned SQL install file defines **23 distinct C entry points** (recorded independently in `config/export-audit.json`), each matched to a `PG_FUNCTION_INFO_V1` declaration across the pinned `src/*.c` source set. Discover these declarations in pinned `src/*.c`; audit every `AS 'MODULE_PATHNAME','Csymbol' LANGUAGE C` binding in SQL; generate an MSVC .def exporting the magic function, initializer, every declared function and matching `pg_finfo_` symbols. Include `.def` via `vs_module_defs` in the upstream Meson shared_module and validate the resulting undecorated exports with dumpbin. Stop if any SQL C entry point has no annotation or any export is missing.

## Functional validation

`detect-invalid-record-field` uses `plpgsql_check_function_tb(regprocedure)` on a function looping through an empty table, checks for a diagnostic mentioning its missing field, then replaces the function to use the real field and asserts zero matching diagnostics and zero error-level diagnostics. The SQL script uses `ON_ERROR_STOP`, fails with nonzero psql exit on unexpected SQL errors, and never treats a generic exception as proof of linting success. Test starts PostgreSQL with **no preload**. The temporary cluster is stopped and removed in `finally`; on failure the last server log lines are printed first.

## Explicit unresolved release gates

1. The `pgextwin/plpgsql_check` repository exists; create and validate an implementation PR against its main branch.
2. Verify pilot workflow on PG18, then PG15–17. Resolve any Meson/MSVC/import-library, SQL runtime, function-export or build compiler issues observed on actual Windows runners.
3. Run common Test Contract validator, PACKAGE-INFO validation, SPDX SBOM validation, Grype operational validation, final artifact and checksum consistency verification.
4. Review source changes, labels, permissions and licensing; merge PR **only after** passing Windows CI; confirm main CI. No release job exists in the pilot workflow.
5. Separate Step 17 gate: decide whether to add attested release workflow, verify provenance and SBOM attestations in a release build, publish Release after full matrix, then update Distribution Catalog and Website independently. Do not count this pilot as a successful release.
