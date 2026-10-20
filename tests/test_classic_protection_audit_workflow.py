#!/usr/bin/env python3
"""Offline hostile-mutation guard for #75 nonpublishing main-only composite proof."""
from pathlib import Path
import re

WORKFLOW = Path("tests/fixtures/historical-workflows/classic-protection-audit.yml")

def verify(text):
    required = (
        "on:\n  push:\n    branches:\n      - main\n    paths:\n      - .github/workflows/classic-protection-audit.yml",
        "github.event_name == 'push'",
        "github.repository == 'pgextwin/plpgsql_check'",
        "github.ref == 'refs/heads/main'",
        'PROBE_ACTOR" != "ShutenOishi"',
        'PROBE_ATTEMPT" != "1"',
        'EXPECTED_APP_ID" != "5295410"',
        'EXPECTED_CLIENT_ID" != "Iv23lidY1vsm7ZseyKe2"',
        'EXPECTED_INSTALLATION_ID" != "170837728"',
        "repository: pgextwin/build",
        "ref: b63f9c9cbe66748fe10707961fd31a236664f8ca",
        "persist-credentials: false",
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/create-github-app-token@fee1f7d63c2ff003460e3d139729b119787bc349",
        "permission-administration: read",
        "permission-metadata: read",
        "repositories: plpgsql_check",
        "owner: pgextwin",
        "skip-token-revoke: false",
        'MINTED_INSTALLATION_ID" != "170837728"',
        'MINTED_APP_SLUG" != "pgextwin-classic-protection-audit"',
        "https://api.github.com/installation/repositories?per_page=100",
        'scope["total_count"] != 1',
        'scope["repositories"][0].get("full_name") != "pgextwin/plpgsql_check"',
        'AUDIT_TOKEN: ${{ steps.auditor.outputs.token }}',
        "trusted-build/scripts/classic-composite-protection.py",
        "composite.collect_verified_composite(",
        "composite.CompositeReader(token)",
        'reason = rest_reasons.get(str(exc), "REST_POLICY_DENIED")',
        '"BRANCH_SUMMARY_CHECKS_MISMATCH"',
        '"PUSH_RESTRICTIONS_ABSENT"',
        '"ADMIN_ENFORCEMENT_UNPROVEN"',
        'expected_main_sha=os.environ["GITHUB_SHA"]',
        'proof.get("status") != "VERIFIED_CLASSIC_COMPOSITE_READ_ONLY"',
        'proof.get("snapshotCount") != 2',
        'proof.get("bypassEvidence") != "GRAPHQL_ZERO_FOR_REST_OMISSION"',
        'proof.get("pushEvidence") != "GRAPHQL_UNRESTRICTED_FOR_REST_OMISSION"',
        'proof.get("independentPushUnrestricted") is not True',
        'proof.get("independentEffectiveRefZero") is not True',
        'proof.get("mainSha") != os.environ["GITHUB_SHA"]',
        'proof.get("publishableReceipt") is not False',
        'print("DENY: stage=" + stage + "; reason=" + reason + "; publishableReceipt=false")',
        "raise SystemExit(1)",
        "DRY_RUN_CONTEXT_ONLY; no Release, tag, Dispatch, or publication authorization",
    )
    for term in required:
        if term not in text:
            raise ValueError("isolated composite main-only proof contract missing")
    for forbidden in (
        "\n  pull_request:", "\n  workflow_dispatch:", "\n  schedule:",
        "\n  workflow_call:", "upload-artifact", "gh release ",
        "gh workflow run ", "permission-administration: write",
        'print(exc)', 'print(str(exc))', 'traceback.print_exc',
        'mutation {', 'mutation(', 'github.event_name == \'pull_request\'',
    ):
        if forbidden in text:
            raise ValueError("unauthorized trigger, write or possible leak")
    if not re.search(r"(?m)^permissions:\n  contents: read$", text):
        raise ValueError("default token permissions not read-only")
    if not re.search(r"(?m)^    permissions:\n      contents: read$", text):
        raise ValueError("job token permissions not read-only")
    ordered = (
        "Deny unexpected identity, event or missing App variables",
        "Checkout reviewed audit code",
        "Mint single-repo Administration read-only installation token",
        "Deny a different App installation",
        "Verify one-repo scope and two full same-token REST GraphQL snapshots",
    )
    locations = [text.find(x) for x in ordered]
    if any(x < 0 for x in locations) or locations != sorted(locations):
        raise ValueError("credential used before protected-main guard")
    if text.count('expected_main_sha=os.environ["GITHUB_SHA"]') != 1:
        raise ValueError("composite must bind exact current main SHA once")
    if "except Exception as exc:" not in text:
        raise ValueError("no exception denial")
    if text.count("composite.collect_verified_composite(") != 1:
        raise ValueError("unexpected composite collector count")


def main():
    text = WORKFLOW.read_text(encoding="utf-8")
    verify(text)
    mutations = (
        ("\n  push:", "\n  pull_request:"),
        ("permission-administration: read", "permission-administration: write"),
        ("repositories: plpgsql_check", "repositories: catalog"),
        ("github.ref == 'refs/heads/main'", "github.ref != 'refs/heads/main'"),
        ('PROBE_ATTEMPT" != "1"', 'PROBE_ATTEMPT" != "99"'),
        ('proof.get("publishableReceipt") is not False',
         'proof.get("publishableReceipt") is False'),
        ('proof.get("bypassEvidence") != "GRAPHQL_ZERO_FOR_REST_OMISSION"',
         'proof.get("bypassEvidence") == "GRAPHQL_ZERO_FOR_REST_OMISSION"'),
        ('proof.get("pushEvidence") != "GRAPHQL_UNRESTRICTED_FOR_REST_OMISSION"',
         'proof.get("pushEvidence") == "GRAPHQL_UNRESTRICTED_FOR_REST_OMISSION"'),
        ('proof.get("independentPushUnrestricted") is not True',
         'proof.get("independentPushUnrestricted") is True'),
        ('proof.get("snapshotCount") != 2', 'proof.get("snapshotCount") != 1'),
        ('expected_main_sha=os.environ["GITHUB_SHA"]',
         'expected_main_sha="0" * 40'),
        ("composite.CompositeReader(token)", "composite.CompositeReader('other-token')"),
        ("ref: b63f9c9cbe66748fe10707961fd31a236664f8ca", "ref: main"),
    )
    for i, (before, after) in enumerate(mutations):
        if before not in text:
            raise AssertionError(f"test mutation fixture missing {i}")
        try:
            verify(text.replace(before, after, 1))
        except ValueError:
            continue
        raise AssertionError(f"hostile mutation {i} not DENIED")
    print("PASS: main-only nonpublishing composite proof +", len(mutations),
          "adversarial workflow mutations")


if __name__ == "__main__":
    main()
