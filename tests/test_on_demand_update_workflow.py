#!/usr/bin/env python3
"""B1 negative contract for the central scheduled candidate preflight.

Only the original local Issue and bot candidate jobs can mutate GitHub.
The central immutable scheduled gate has contents:read and admits candidates
only for a successful verified 17-extension fleet report on protected main.
PUBLISH and formal Releases are separate and never triggered by this watcher.
"""
from pathlib import Path
import re

PATH = Path(".github/workflows/update-watch.yml")
SHARED = "39a329fb5e7c7f801eef3a23688fdd76cce8b2ac"
PIN = "16b886b9d06d6f389b369b87ce0c155767697ca0"


def verify(src):
    required = (
        'on:\n  schedule:\n    - cron: "30 3 * * *"',
        "permissions:\n  contents: read",
        "cancel-in-progress: false",
        "  authorize:\n",
        "    name: Read-only latest 17-fleet success and exact protected main preflight",
        "    permissions:\n      contents: read\n    uses: pgextwin/build/.github/workflows/operator-update-auto.yml@" + SHARED,
        "      detector_sha: " + PIN,
        "  watch_candidate:\n", "  candidate:\n",
        "needs: authorize",
        "needs.authorize.outputs.mode == 'candidate'",
        "needs.watch_candidate.result == 'success'",
        "uses: pgextwin/build/.github/workflows/check-extension-updates.yml@" + PIN,
        "uses: pgextwin/build/.github/workflows/candidate-update.yml@" + PIN,
        "candidate_policy_path: config/candidate-build.json",
    )
    for marker in required:
        if marker not in src:
            raise ValueError("Missing pinned scheduled candidate contract: " + marker[:85])
    if src.count("dry_run: false") != 2:
        raise ValueError("original candidate-only jobs changed")
    # Both candidate jobs must retain this authorization, not just one.
    if src.count("needs.authorize.outputs.mode == 'candidate'") != 2:
        raise ValueError("both scoped candidate jobs must depend on candidate mode")
    for forbidden in (
        "\n  workflow_dispatch:", "\n  push:", "\n  pull_request:",
        "\n  repository_dispatch:", "\n  workflow_call:",
        "confirm_update", "expected_main_sha", "ShutenOishi",
        "gh release ", "confirm_release=PUBLISH", "build-extension-attested.yml",
        "operator-update-readonly.yml", "GH_TOKEN:", "secrets.",
        "persist-credentials: true", "watch_readonly:",
    ):
        if forbidden in src:
            raise ValueError("Unexpected human UPDATE, event, publication or credential path")
    watch = src.split("  watch_candidate:\n", 1)[1].split("  candidate:\n", 1)[0]
    candidate = src.split("  candidate:\n", 1)[1]
    if not re.search(r"(?m)^    permissions:\n      contents: read\n      issues: write$", watch):
        raise ValueError("original issue reconciliation permissions drifted")
    if not re.search(r"(?m)^    permissions:\n      contents: write\n      pull-requests: write\n      actions: write$", candidate):
        raise ValueError("original candidate writer permissions drifted")


def main():
    src = PATH.read_text(encoding="utf-8")
    verify(src)
    mutants = (
        ('cron: "30 3 * * *"', 'cron: "* * * * *"'),
        ('operator-update-auto.yml@' + SHARED, 'operator-update-auto.yml@main'),
        ('      detector_sha: ' + PIN, '      detector_sha: main'),
        ('    permissions:\n      contents: read\n    uses: pgextwin/build/.github/workflows/operator-update-auto.yml',
         '    permissions:\n      contents: write\n    uses: pgextwin/build/.github/workflows/operator-update-auto.yml'),
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
        ("  schedule:\n", "  workflow_dispatch:\n"),
    )
    for before, after in mutants:
        if before not in src:
            raise AssertionError("missing hostile fixture " + before[:60])
        try:
            verify(src.replace(before, after, 1))
        except ValueError:
            continue
        raise AssertionError("unsafe scheduled candidate mutation accepted: " + before[:60])
    print("PASS: scheduled immutable B1 candidate gate and " + str(len(mutants))
          + " hostile mutations; no human UPDATE or PUBLISH")


if __name__ == "__main__":
    main()
