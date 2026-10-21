#!/usr/bin/env python3
"""Offline B1: delegated read-only gate and original candidate job isolation.

The exact human UPDATE Bash gate and 17-repo SHA cohorts run in the central
build required CI. These local hostile tests enforce protected immutable pins
and job-specific mutation permissions; they do not issue any credentials.
"""
from pathlib import Path
import re

PATH = Path(".github/workflows/update-watch.yml")
SHARED = "33853f3a4381bfc2d984fad371e5ba5c768595a5"
PIN = "16b886b9d06d6f389b369b87ce0c155767697ca0"


def verify(s):
    required = (
        "on:\n  workflow_dispatch:", "default: true",
        "permissions:\n  contents: read",
        "cancel-in-progress: false",
        "  authorize:\n    name: Shared strict operator preflight and GET-only update watch",
        "    permissions:\n      contents: read\n    uses: pgextwin/build/.github/workflows/operator-update-readonly.yml@" + SHARED,
        "      dry_run: ${{ inputs.dry_run }}",
        "      confirm_update: ${{ inputs.confirm_update }}",
        "      expected_main_sha: ${{ inputs.expected_main_sha }}",
        "      detector_sha: " + PIN,
        "  watch_candidate:\n", "  candidate:\n",
        "needs: authorize",
        "if: ${{ needs.authorize.outputs.mode == 'candidate' }}",
        "if: ${{ needs.authorize.outputs.mode == 'candidate' && needs.watch_candidate.result == 'success' }}",
        "uses: pgextwin/build/.github/workflows/check-extension-updates.yml@" + PIN,
        "uses: pgextwin/build/.github/workflows/candidate-update.yml@" + PIN,
        "candidate_policy_path: config/candidate-build.json",
        "dry_run: false",
    )
    for marker in required:
        if marker not in s:
            raise ValueError("Missing immutable delegated UPDATE contract: " + marker[:85])
    if s.count("dry_run: false") != 2 or s.count("dry_run: ${{ inputs.dry_run }}") != 1:
        raise ValueError("Unexpected candidate/readonly mode wiring")
    for forbidden in (
        "\n  schedule:", "\n  push:", "\n  pull_request:",
        "\n  repository_dispatch:", "\n  workflow_call:",
        "gh release ", "confirm_release=PUBLISH", "build-extension-attested.yml",
        "  watch_readonly:\n", "GH_TOKEN:", "secrets.", "persist-credentials: true",
    ):
        if forbidden in s:
            raise ValueError("Unapproved event, publication or credential path")
    if not re.search(r"(?m)^  authorize:\n(?:    .*\n)*?    permissions:\n      contents: read\n", s):
        raise ValueError("Delegated preflight must not get a write-capable token")
    wc = s.split("  watch_candidate:\n", 1)[1].split("  candidate:\n", 1)[0]
    candidate = s.split("  candidate:\n", 1)[1]
    if not re.search(r"(?m)^    permissions:\n      contents: read\n      issues: write$", wc):
        raise ValueError("Original Issue reconciliation authorization changed")
    if not re.search(r"(?m)^    permissions:\n      contents: write\n      pull-requests: write\n      actions: write$", candidate):
        raise ValueError("Original candidate writer authorization changed")


def main():
    src = PATH.read_text(encoding="utf-8")
    verify(src)
    mutations = (
        ("default: true", "default: false"),
        ("operator-update-readonly.yml@" + SHARED, "operator-update-readonly.yml@main"),
        ("      detector_sha: " + PIN, "      detector_sha: main"),
        ("      dry_run: ${{ inputs.dry_run }}", "      dry_run: false"),
        ("      expected_main_sha: ${{ inputs.expected_main_sha }}", "      expected_main_sha: 0"),
        ("    permissions:\n      contents: read\n    uses: pgextwin/build/.github/workflows/operator-update-readonly.yml",
         "    permissions:\n      contents: write\n    uses: pgextwin/build/.github/workflows/operator-update-readonly.yml"),
        ("needs.authorize.outputs.mode == 'candidate'",
         "needs.authorize.outputs.mode == 'read-only'"),
        ("needs.watch_candidate.result == 'success'",
         "needs.watch_candidate.result == 'failure'"),
        ("uses: pgextwin/build/.github/workflows/candidate-update.yml@" + PIN,
         "uses: pgextwin/build/.github/workflows/candidate-update.yml@main"),
        ("uses: pgextwin/build/.github/workflows/check-extension-updates.yml@" + PIN,
         "uses: pgextwin/build/.github/workflows/check-extension-updates.yml@main"),
        ("      issues: write", "      contents: write"),
        ("      actions: write", "      actions: read"),
    )
    for before, after in mutations:
        if before not in src:
            raise AssertionError("Missing hostile mutation anchor: " + before[:50])
        try:
            verify(src.replace(before, after, 1))
        except ValueError:
            continue
        raise AssertionError("Hostile mutation accepted: " + before[:50])
    print(f"PASS: delegated B1 immutable call, scoped writer jobs and {len(mutations)} hostile changes denied")


if __name__ == "__main__":
    main()
