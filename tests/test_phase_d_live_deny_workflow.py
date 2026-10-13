#!/usr/bin/env python3
"""#75: deny unsafe mutation of main-only inert authenticated negative probe."""
from pathlib import Path
import re

WORKFLOW = Path(".github/workflows/phase-d-live-deny-probe.yml")


def verify(workflow):
    required = (
        "on:\n  push:\n    branches:\n      - main\n    paths:\n      - .github/workflows/phase-d-live-deny-probe.yml",
        "permissions:\n  contents: read",
        "      contents: read",
        "      actions: read",
        "      checks: read",
        "      pull-requests: read",
        "      attestations: read",
        "github.event_name == 'push'",
        "github.repository == 'pgextwin/plpgsql_check'",
        "github.ref == 'refs/heads/main'",
        'PROBE_ACTOR" != "ShutenOishi"',
        'PROBE_ATTEMPT" != "1"',
        'EXPECTED_APP_ID" != "5295410"',
        'EXPECTED_CLIENT_ID" != "Iv23lidY1vsm7ZseyKe2"',
        'EXPECTED_INSTALLATION_ID" != "170837728"',
        "Checkout reviewed immutable read-only probe code",
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "repository: pgextwin/build",
        "ref: 0455cdef6e9ce2cb1cbb92ccd96e2a623eaba034",
        "persist-credentials: false",
        "actions/create-github-app-token@fee1f7d63c2ff003460e3d139729b119787bc349",
        "permission-administration: read",
        "permission-metadata: read",
        "owner: pgextwin",
        "repositories: plpgsql_check",
        "skip-token-revoke: false",
        'MINTED_INSTALLATION_ID" != "170837728"',
        'MINTED_APP_SLUG" != "pgextwin-classic-protection-audit"',
        "ADMIN_TOKEN: ${{ steps.auditor.outputs.token }}",
        "EVIDENCE_TOKEN: ${{ github.token }}",
        "GH_TOKEN: ${{ github.token }}",
        "python3 trusted-build/scripts/chat-pr-phase-d-live-deny-probe.py",
        "DRY_RUN_NEGATIVE_PROOF_ONLY; no Release, tag, Dispatch, or PUBLISH authorization",
    )
    for phrase in required:
        if phrase not in workflow:
            raise ValueError("protected-main read-only denial contract missing")
    if not re.search(r"(?m)^    if: \$\{\{ github.event_name == 'push' && github.repository == 'pgextwin/plpgsql_check' && github.ref == 'refs/heads/main' \}\}$", workflow):
        raise ValueError("job must execute only for pilot protected main push")
    for forbidden in (
        "\n  pull_request:", "\n  workflow_dispatch:", "\n  workflow_call:",
        "\n  schedule:", "\n  release:", "\n  repository_dispatch:",
        "permission-administration: write", "pull-requests: write",
        "contents: write", "actions: write", "attestations: write",
        "gh release ", "gh workflow run ", "gh api -X POST", "upload-artifact",
        "persist-credentials: true", "mutation {", "publishableReceipt=true",
        "token: ${{ secrets.", "secrets.GITHUB_TOKEN",
    ):
        if forbidden in workflow:
            raise ValueError("write, mutable ref or credential leakage risk")
    stages = [
        "Deny unknown App, operator, event, attempt or SHA before secret use",
        "Checkout reviewed immutable read-only probe code",
        "Mint existing single-repo Administration READ token",
        "Reject untrusted App installation identity",
        "Exercise authenticated missing-auth, draft and unsigned-candidate DENY",
        "Confirm only an expected negative audit, never publication",
    ]
    locations = [workflow.find(x) for x in stages]
    if any(x < 0 for x in locations) or locations != sorted(locations):
        raise ValueError("live denial probe preflight/scope step ordering changed")
    if workflow.count("python3 trusted-build/scripts/chat-pr-phase-d-live-deny-probe.py") != 1:
        raise ValueError("unreviewed multiple negative probes")


def main():
    content = WORKFLOW.read_text(encoding="utf-8")
    verify(content)
    mutations = [
        ("\n  push:", "\n  workflow_dispatch:"),
        ("branches:\n      - main", "branches:\n      - develop"),
        ("permission-administration: read", "permission-administration: write"),
        ("repositories: plpgsql_check", "repositories: catalog"),
        ("contents: read", "contents: write"),
        ("PROBE_ATTEMPT\" != \"1\"", "PROBE_ATTEMPT\" != \"2\""),
        ("PROBE_ACTOR\" != \"ShutenOishi\"", "PROBE_ACTOR\" != \"github-actions[bot]\""),
        ("ref: 0455cdef6e9ce2cb1cbb92ccd96e2a623eaba034", "ref: main"),
        ("EVIDENCE_TOKEN: ${{ github.token }}", "EVIDENCE_TOKEN: ${{ secrets.FOO }}"),
        ("python3 trusted-build/scripts/chat-pr-phase-d-live-deny-probe.py",
         "python3 untrusted-branch/scripts/chat-pr-phase-d-live-deny-probe.py"),
        ("DRY_RUN_NEGATIVE_PROOF_ONLY; no Release, tag, Dispatch, or PUBLISH authorization",
         "release enabled"),
    ]
    for n, (old, new) in enumerate(mutations):
        if old not in content:
            raise AssertionError(f"unsafe fixture not found {n}")
        try:
            verify(content.replace(old, new, 1))
        except ValueError:
            continue
        raise AssertionError(f"dangerous mutation {n} not denied")
    print("PASS: Phase D path-only, human main push, fixed read-only trust +",
          len(mutations), "negative workflow mutants")


if __name__ == "__main__":
    main()
