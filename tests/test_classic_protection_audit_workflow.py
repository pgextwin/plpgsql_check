#!/usr/bin/env python3
"""Offline contract guard for Issue #75 main-only, nonpublishing Classic read proof.

This checks the trust boundary; it deliberately does not load secrets or issue requests.
"""
from pathlib import Path
import re

WORKFLOW = Path(".github/workflows/classic-protection-audit.yml")


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
        "ref: 657a9e3c28d6cdbff16ef54e3bad4fe61c4fa8f7",
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
        "trusted-build/scripts/classic-protection-audit.py",
        "collect_verified_classic(",
        'expected_main_sha=os.environ["GITHUB_SHA"]',
        'proof.get("publishableReceipt") is not False',
        "print(\"DENY: authenticated Classic API proof incomplete or unavailable\")",
    )
    for term in required:
        if term not in text:
            raise ValueError("required isolated-auditor contract element missing")
    # This workflow has NO PR, Dispatch, schedule or workflow-call entrypoint.
    for forbidden in ("\n  pull_request:", "\n  workflow_dispatch:", "\n  schedule:",
                      "\n  workflow_call:", "upload-artifact", "gh release ",
                      "gh workflow run ", "permission-administration: write"):
        if forbidden in text:
            raise ValueError("unsafe trigger, publishing action or permission")
    if not re.search(r"(?m)^permissions:\n  contents: read$", text):
        raise ValueError("default GitHub token is not read-only")
    if not re.search(r"(?m)^    permissions:\n      contents: read$", text):
        raise ValueError("job GitHub token is not read-only")
    ordered = (
        "Deny unexpected identity, event or missing App variables",
        "Checkout reviewed audit code",
        "Mint single-repo Administration read-only installation token",
        "Deny a different App installation",
        "Verify exact token repository scope and two live Classic API snapshots",
    )
    locations = [text.find(x) for x in ordered]
    if any(i < 0 for i in locations) or locations != sorted(locations):
        raise ValueError("secret minting occurs before trusted event guard")
    if "raise SystemExit(1)" not in text or "except Exception as exc:" not in text:
        raise ValueError("API errors may not fail closed")
    # A fail-closed diagnostic has an exclusively fixed code vocabulary; it
    # must not echo the underlying token, raw API body, or exception string.
    for term in (
        'stage = ["SCOPE_GET"]',
        "policy_codes = {",
        'stage[0] = "SCOPE_VALIDATE"',
        'stage[0] = "PINNED_READER_LOAD"',
        "class StageReader:",
        'stage[0] = "FINAL_RECEIPT_DENY_CHECK"',
        "def classify_rest_bypass(details):",
        'return "BYPASS_ABSENT"',
        'return "BYPASS_NULL"',
        'return "BYPASS_NOT_OBJECT"',
        'return kind.upper() + "_ABSENT"',
        'return kind.upper() + "_NOT_LIST"',
        'return kind.upper() + "_NONEMPTY"',
        'return "ALL_THREE_EXPLICITLY_EMPTY"',
        'print("DIAGNOSTIC: rest_bypass_shape=" + classify_rest_bypass(value))',
        'query = """query {',
        'ref(qualifiedName: "refs/heads/main")',
        'bypassPullRequestAllowances(first: 1)',
        'method="POST",',
        'data=json.dumps({"query": query}',
        'trusted-build/scripts/classic-graphql-bypass.py',
        'validate_effective_ref_bypass_zero(',
        'expected_main_sha=os.environ["GITHUB_SHA"]',
        'print("PASS: GraphQL effective refs/heads/main bypass count exactly zero; publishableReceipt=false")',
        'reason = gql_reasons.get(str(exc), "GRAPHQL_CONTRACT_DENIED")',
        'reason = policy_codes.get(str(exc), "CLASSIC_CONTRACT_DENIED")',
        'print("DENY: stage=" + stage[0] + "; reason=" + reason + "; publishableReceipt=false")',
    ):
        if term not in text:
            raise ValueError("fixed, sanitized fail-closed diagnostics missing")
    # A GraphQL POST must be an immutable read-only query, not a mutation.
    if 'mutation {' in text or 'mutation(' in text or '/graphql/mutation' in text:
        raise ValueError("GraphQL mutation forbidden")
    if text.count('"https://api.github.com/graphql"') != 1:
        raise ValueError("unexpected or missing GraphQL endpoint")
    if 'gql_proof.get("publishableReceipt") is not False' not in text:
        raise ValueError("GraphQL proof cannot authorize publishing")
    if 'module.collect_verified_classic(' not in text:
        raise ValueError("REST Classic verifier has been bypassed")
    if 'print(exc)' in text or 'print(str(exc))' in text or 'traceback.print_exc' in text:
        raise ValueError("untrusted exception could leak sensitive contents")
    if "AUDIT_TOKEN: ${{ steps.auditor.outputs.token }}" not in text:
        raise ValueError("scoped token is not isolated to the audit reader")


def main():
    text = WORKFLOW.read_text(encoding="utf-8")
    verify(text)
    mutations = (
        ("\n  push:", "\n  pull_request:"),
        ("permission-administration: read", "permission-administration: write"),
        ("repositories: plpgsql_check", "repositories: catalog"),
        ("github.ref == 'refs/heads/main'", "github.ref != 'refs/heads/main'"),
        ("PROBE_ATTEMPT\" != \"1\"", "PROBE_ATTEMPT\" != \"99\""),
        ("publishableReceipt\") is not False", "publishableReceipt\") is False"),
        ("expected_main_sha=os.environ[\"GITHUB_SHA\"]", "expected_main_sha='0' * 40"),
    )
    for before, after in mutations:
        if before not in text:
            raise AssertionError("fixture mutation does not match source")
        try:
            verify(text.replace(before, after, 1))
        except ValueError:
            continue
        raise AssertionError("hostile workflow mutation was not denied")
    print("PASS: nonpublishing trusted-main App read-only workflow contract and 7 denial mutations")


if __name__ == "__main__":
    main()
