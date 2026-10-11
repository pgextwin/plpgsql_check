# plpgsql_check for Windows — unofficial pgextwin binaries

[日本語](README_ja.md) | **English**

This repository builds **unofficial Windows x64 binaries** of [plpgsql_check](https://github.com/okbob/plpgsql_check) for maintained PostgreSQL 14, 15, 16, 17 and 18. **The historical first release covered only PG15–18; the latest verified release covers PG14–18.** It is independent of upstream and of the PostgreSQL project. The first production release is **`v2.10.13-windows.1`**. Release publication is gated by the full maintained-major Windows build/runtime matrix and artifact-attestation verification.

**Latest verified download:** [v2.10.14-windows.1](https://github.com/pgextwin/plpgsql_check/releases/tag/v2.10.14-windows.1) (PG14–18) · [all GitHub Releases](https://github.com/pgextwin/plpgsql_check/releases). The first historical release, [v2.10.13-windows.1](https://github.com/pgextwin/plpgsql_check/releases/tag/v2.10.13-windows.1), covered PG15–18 only. Do not substitute normal-CI artifacts for signed release packages.

## Exact version identity

| Identity | Value |
| --- | --- |
| Upstream repository | `okbob/plpgsql_check` |
| Upstream stable tag / release | `v2.10.14` / `2.10.14` |
| Upstream source commit | `ccdbcce9de51f01e1138c270aeb9fe4e26c6e911` |
| SQL extension `default_version` | `2.10` (not `2.10.14`) |
| Latest pgextwin Windows release | `v2.10.14-windows.1` (PG14–18) |
| Windows target | x64, PostgreSQL 14–18 (PG14 supported until 2026-11-12 EOL) |
| Upstream source license | MIT-style permission text, preserved verbatim in `LICENSE` |

The upstream control file sets `default_version = '2.10'`, and the installation script is `plpgsql_check--2.10.sql`. The packaging release number does **not** change the SQL extension version. PostgreSQL 14 is included in the latest `v2.10.14-windows.1` Release (but not the historical first `v2.10.13-windows.1` release), and is supported through 2026-11-12 EOL. PostgreSQL 19 is not covered.

## Download and installation

Select a **published and verified** ZIP for the **exact PostgreSQL major** installed on your Windows x64 machine:

- `plpgsql_check-v2.10.14-pg14-windows-x64.zip`
- `plpgsql_check-v2.10.14-pg15-windows-x64.zip`
- `plpgsql_check-v2.10.14-pg16-windows-x64.zip`
- `plpgsql_check-v2.10.14-pg17-windows-x64.zip`
- `plpgsql_check-v2.10.14-pg18-windows-x64.zip`

These builds are tested against the Windows PostgreSQL binaries installed by the pgextwin CI from version-pinned Chocolatey packages. They are **not guaranteed to be ABI-compatible** with every third-party Windows PostgreSQL distribution or different compiler/runtime configuration. Use the same PostgreSQL major and a compatible x64 server distribution; back up and test before deployment. Cross-major copying is unsupported.

Stop the PostgreSQL service before replacing existing loaded DLLs. Extract the ZIP and copy `lib/plpgsql_check.dll` to the server installation's `lib/`, and the contents of `share/extension/` to its `share/extension/`. Retain `LICENSE`, `UPSTREAM-README.md`, `PGEXTWIN-README.md`, `PACKAGE-INFO.txt`, and `PACKAGE-INFO.json` for attribution and source/build identity. Restart PostgreSQL as appropriate. Connect to each database that needs the extension and execute:

~~~sql
CREATE EXTENSION plpgsql_check;
SELECT extversion FROM pg_extension WHERE extname = 'plpgsql_check';
~~~

Normal active function checking does not need `shared_preload_libraries`. Optional profiler, tracer, passive/shared modes can require different configuration and are **not validated** by our release test. Follow upstream guidance before enabling them.

## Validated functionality (only)

CI starts a real isolated PostgreSQL server for each of PG14–18, installs the DLL/control/SQL, creates the extension, checks a missing record-field diagnostic *without executing the function*, then fixes the function and verifies the diagnostic disappears:

~~~sql
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
~~~

Change `r.missing` to `r.a` and check again. The release pipeline additionally verifies upstream source SHA/license, MSVC/Meson/Ninja build, required DLL exports, Windows PostgreSQL startup, ZIP layout, PACKAGE-INFO schema, SPDX 2.3 SBOM, and Grype scan execution.

**Not covered:** profiler, tracer, passive/shared modes, server-log assertions, SQL upgrade tests, and PostgreSQL cross-major upgrades. Do not interpret successful `CREATE EXTENSION` or this single smoke scenario as complete API validation.

## Checksums, SBOM, and GitHub Artifact Attestations

Release assets include one ZIP, corresponding `*.spdx.json` and `*.vulnerabilities.json` per PG major, plus `SHA256SUMS.txt`. Each ZIP contains validated `PACKAGE-INFO.json`; the SPDX 2.3 SBOM describes the finalized ZIP. The vulnerability JSON is a **report-only** Grype scan against the database available at build time: it does not block publication for detected CVEs, and zero findings do not prove an absence of vulnerabilities.

After downloading the files, verify SHA-256 (run PowerShell in the download directory):

~~~powershell
Get-Content .\SHA256SUMS.txt
(Get-FileHash .\plpgsql_check-v2.10.14-pg17-windows-x64.zip -Algorithm SHA256).Hash
~~~

Compare the hash with the corresponding entry (and similarly check every asset). The release publication workflow generates checksums from the same final artifact bytes published to GitHub Releases. The ZIP is **not repackaged after attestation**.

GitHub Artifact Attestations are stored in GitHub, **not** uploaded as separate Release asset files. With authenticated GitHub CLI, validate the downloaded ZIP and the reusable signer workflow:

~~~powershell
gh attestation verify .\plpgsql_check-v2.10.14-pg17-windows-x64.zip --repo pgextwin/plpgsql_check --signer-workflow pgextwin/build/.github/workflows/build-extension-attested.yml
gh attestation verify .\plpgsql_check-v2.10.14-pg17-windows-x64.zip --repo pgextwin/plpgsql_check --signer-workflow pgextwin/build/.github/workflows/build-extension-attested.yml --predicate-type https://spdx.dev/Document/v2.3
~~~

Repeat per PostgreSQL major. The release CI verifies both attestation types and also compares the verified SPDX predicate against the standalone SBOM. The caller repository is `pgextwin/plpgsql_check`; the signer workflow is in `pgextwin/build`, pinned by an immutable 40-character commit SHA.

## Build and release safety

Normal PR/main CI uses read-only Windows build and runtime validation. Formal releases require an explicit operator-initiated `promote.yml` workflow_dispatch from trusted `main` with `confirm_release=PUBLISH`, a merged automation-owned candidate PR, immutable watch/candidate-audit evidence, successful maintained-major PG14–18 attested Windows builds, and verified SHA256/SPDX/Grype assets plus GitHub build/SBOM attestations. The independent third-party PR review and separate approval-JSON PR are not required. A reserved tag is create-only; **never rerun a completed or partially staged Promotion to overwrite its tag or Release**. A staged Draft must be recovered and independently verified without regenerating artifacts. Historic `v2.10.13-windows.1` used a different, four-major release-branch flow.

See [historical Step 16 pilot notes](docs/technical-pilot.md) and the [shared supply-chain docs](https://github.com/pgextwin/build/blob/main/docs/artifact-attestations.md). A successful normal CI artifact is **not** a signed production release.
