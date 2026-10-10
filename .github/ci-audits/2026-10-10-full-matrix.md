# One-time pgextwin extension matrix revalidation

Date: 2026-10-10 (JST)

This non-functional audit marker requests a fresh full Windows CI matrix (PostgreSQL 15–18) as part of the organization-wide SBOM/Grype/release/catalog/website revalidation.

The existing `v2.10.13-windows.1` release already contains all ZIP, SPDX SBOM, Grype report, SHA256SUMS and attestations. This audit does **not** alter or republish its release artifacts. Full validation must succeed before the audit PR is merged.
