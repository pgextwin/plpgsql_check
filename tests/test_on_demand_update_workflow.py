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
SHARED = "9ec4dde0b6defabc10cf3527c06cb69c13e5a7ff"
STAGE = "dbf7365ae702ddc19e094205f8343ec555125d9c"  # verified six-blob scheduled closure; non-schedule audit pins remain separate
SIGNED_AUDIT_PIN = SHARED  # exact protected central publication policy; signer stays independently pinned
SCHEDULED_SHARED = "d8904ebc377e33034b71108d42de940d6b6c9979"  # read-only central receipt pin; candidate writers stay STAGE
NATIVE_READERS_SHARED = SHARED  # same reviewed protected policy, exact read-only observer
NATIVE_PR_AUDIT_SHARED = SHARED  # original PR association stays independently enforced
PIN = "16b886b9d06d6f389b369b87ce0c155767697ca0"


def verify(src):
    required = (
        'on:\n  schedule:\n    - cron: "30 * * * *"',
        "permissions:\n  contents: read",
        "cancel-in-progress: false",
        "  authorize:\n",
        "    name: Read-only latest 17-fleet success and exact protected main preflight",
        "    permissions:\n      contents: read\n    uses: pgextwin/build/.github/workflows/operator-update-auto.yml@" + SCHEDULED_SHARED,
        "      detector_sha: " + PIN,
        "  watch_candidate:\n", "  candidate:\n",
        "needs: authorize",
        "needs.authorize.outputs.mode == 'candidate'",
        "needs.watch_candidate.result == 'success'",
        "uses: pgextwin/build/.github/workflows/check-extension-updates.yml@" + STAGE,
        "uses: pgextwin/build/.github/workflows/candidate-update.yml@" + STAGE,
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
        "\n  workflow_dispatch:", "\n  pull_request:",
        "\n  repository_dispatch:", "\n  workflow_call:",
        "confirm_update", "expected_main_sha", "ShutenOishi",
        "gh release ", "confirm_release=PUBLISH",
        "operator-update-readonly.yml", "GH_TOKEN:", "secrets.",
        "persist-credentials: true", "watch_readonly:",
    ):
        if forbidden in src:
            raise ValueError("Unexpected human UPDATE, event, publication or credential path")
    # Read-only candidate main observation is allowed ONLY for manifest merges.
    # This must never change the original scheduled candidate/UPDATE contracts.
    expected_push = """  push:
    branches: [main]
    paths:
      - "config/extension.json"
"""
    if expected_push not in src:
        raise ValueError("exact protected-main manifest-only push filter missing")
    required_observer = (
        "  candidate_main_merge_observation:\n",
        "github.event_name == 'push'",
        "github.ref == 'refs/heads/main'",
        "github.event.created == false",
        "github.event.deleted == false",
        "      actions: read",
        "      pull-requests: read",
        "uses: pgextwin/build/.github/workflows/automatic-postmerge-audit-readonly.yml@"
        + NATIVE_READERS_SHARED,
    )
    if src.count("  push:\n") != 1 or src.count("  candidate_main_merge_observation:\n") != 1:
        raise ValueError("duplicate or ambiguous read-only observer")
    for marker in required_observer:
        if marker not in src:
            raise ValueError("missing pinned read-only main observer " + marker)
    observer = src.split("  candidate_main_merge_observation:\n", 1)[1].split("\n  candidate_attested_build:\n", 1)[0]
    for prohibited in ("contents: write", "actions: write", "issues: write",
                       "pull-requests: write",
                       "secrets.", "GH_TOKEN:", "workflow_dispatch", "confirm_release",
                       "gh release ", "ref: main", "persist-credentials: true"):
        if prohibited in observer:
            raise ValueError("unsafe observer privilege or mutable Release path")
    for name, following, workflow in (
        ("candidate_native_pr_audit", "candidate_main_merge_observation", "verify-native-pr-candidate.yml"),
        ("candidate_main_merge_observation", "candidate_attested_build", "automatic-postmerge-audit-readonly.yml"),
    ):
        reader = src.split("  " + name + ":\n", 1)[1].split("\n  " + following + ":\n", 1)[0]
        perms = reader.split("    permissions:\n", 1)[1].split("    uses:", 1)[0]
        actual = dict(re.findall(r"^      ([a-z-]+): ([a-z]+)$", perms, re.M))
        if actual != {"contents": "read", "actions": "read", "pull-requests": "read", "checks": "read"}:
            raise ValueError("native reader must have exact read-only Check Runs access")
        expected = (NATIVE_PR_AUDIT_SHARED if name == "candidate_native_pr_audit"
                    else NATIVE_READERS_SHARED)
        if workflow + "@" + expected not in reader:
            raise ValueError("native reader immutable exact-role repair pin missing")
    # The attested job is distinct from the read-only observer. It may attest,
    # but it can never mint a public Release, tag or privilege escalation.
    if src.count("\n  candidate_attested_build:\n") != 1:
        raise ValueError("exactly one shared signer job required")
    signer = src.split("\n  candidate_attested_build:\n", 1)[1].split("\n  candidate_signed_audit:\n", 1)[0]
    signed_required = (
        "    needs: candidate_main_merge_observation",
        "github.event_name == 'push'",
        "github.ref == 'refs/heads/main'",
        "needs.candidate_main_merge_observation.result == 'success'",
        "needs.candidate_main_merge_observation.outputs.verified_signed_build_intent == 'true'",
        "    permissions:\n      contents: read\n      id-token: write\n      attestations: write\n      artifact-metadata: write",
        "uses: pgextwin/build/.github/workflows/build-extension-attested.yml@5756b3c5136a8bf4db710016cfe97555f0a71c6d",
        "extension_config_path: config/extension.json",
        "test_contract_path: config/test-contract.json",
    )
    for marker in signed_required:
        if marker not in signer:
            raise ValueError("signed-build gate or immutable source changed: " + marker)
    for forbidden in ("contents: write", "actions: write", "pull-requests: write",
                      "secrets.", "workflow_dispatch", "gh release ", "confirm_release",
                      "publish-release", "catalog", "@main"):
        if forbidden in signer:
            raise ValueError("signed-build job gained publication or extraneous permissions")
    # The new final audit is a separate strictly read-only job, not an
    # extension of the original signer or an additional Publisher.
    if src.count("\n  candidate_signed_audit:\n") != 1:
        raise ValueError("signed candidate auditor must be unique")
    auditor = src.split("\n  candidate_signed_audit:\n", 1)[1].split(
        "\n  merged_candidate_scheduled_oidc:\n", 1)[0]
    # A second reusable caller (even to the same immutable SHA) is ambiguous.
    if len(re.findall(r"(?m)^\s+uses:\s+", auditor)) != 1:
        raise ValueError("signed audit must have exactly one reusable workflow caller")
    for required in (
        "needs: [candidate_main_merge_observation, candidate_attested_build]",
        "needs.candidate_attested_build.result == 'success'",
        "needs.candidate_main_merge_observation.outputs.verified_signed_build_intent == 'true'",
        "    permissions:\n      contents: read\n      actions: read\n      attestations: read",
        "verify-signed-candidate-readonly.yml@" + SIGNED_AUDIT_PIN,
    ):
        if required not in auditor:
            raise ValueError("signed audit missing prior verified BUILD, immutable SHA or READ permissions")
    for forbidden in ("contents: write", "actions: write", "id-token: write",
                      "attestations: write", "issues: write", "pull-requests: write",
                      "secrets.", "workflow_dispatch", "gh release ", "@main"):
        if forbidden in auditor:
            raise ValueError("signed audit gained publication or mutable privileges")
    # Independent nonpublishing scheduled requalification is NOT a second
    # legacy main/push signed-auditor caller; validate it separately.
    if src.count("\n  merged_candidate_scheduled_oidc:\n") != 1:
        raise ValueError("exactly one isolated merged candidate signing lane required")
    merged = src.split("\n  merged_candidate_scheduled_oidc:\n", 1)[1]
    required_merged = (
        "needs: authorize",
        "github.event_name == 'schedule'",
        "github.ref == 'refs/heads/main'",
        "needs.authorize.result == 'success'",
        "needs.authorize.outputs.mode == 'none'",
        "    permissions:\n      contents: read\n      actions: read\n      checks: read\n      pull-requests: read\n      id-token: write\n      attestations: write\n      artifact-metadata: write",
        "uses: pgextwin/build/.github/workflows/requalify-merged-candidate-signed.yml@12e9c809d963c82735e23680ac1838693a6de356",
    )
    for marker in required_merged:
        if marker not in merged:
            raise ValueError("merged schedule signer immutable safety contract drift: " + marker)
    if len(re.findall(r"(?m)^    uses:\s+", merged)) != 1:
        raise ValueError("merged signer has ambiguous reusable callers")
    for unsafe in ("contents: write", "actions: write", "pull-requests: write",
                   "workflow_dispatch", "gh release", "secrets.", "GH_TOKEN:",
                   "confirm_release", "publish-release", "@main"):
        if unsafe in merged:
            raise ValueError("merged signer added publication privilege")
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
        ('      checks: read', '      checks: write'),
        ('      checks: read', ''),
        ('verify-native-pr-candidate.yml@' + NATIVE_PR_AUDIT_SHARED,
         'verify-native-pr-candidate.yml@main'),
        ('verify-native-pr-candidate.yml@' + NATIVE_PR_AUDIT_SHARED,
         'verify-native-pr-candidate.yml@2b2903e463d28891b5688bf4546da99a299c3684'),
        ("verify-signed-candidate-readonly.yml@" + SIGNED_AUDIT_PIN,
         "verify-signed-candidate-readonly.yml@main"),
        ("verify-signed-candidate-readonly.yml@" + SIGNED_AUDIT_PIN,
         "verify-signed-candidate-readonly.yml@a3546d2ff536fc02c0736e687f9a2451460ded26"),
        ("verify-signed-candidate-readonly.yml@" + SIGNED_AUDIT_PIN,
         "verify-signed-candidate-readonly.yml@" + SIGNED_AUDIT_PIN
         + "\n    uses: pgextwin/build/.github/workflows/verify-signed-candidate-readonly.yml@" + SIGNED_AUDIT_PIN),
        ("needs.candidate_main_merge_observation.outputs.verified_signed_build_intent == 'true'",
         "needs.candidate_main_merge_observation.outputs.verified_signed_build_intent == 'false'"),
        ("build-extension-attested.yml@5756b3c5136a8bf4db710016cfe97555f0a71c6d", "build-extension-attested.yml@main"),
        ("      attestations: write", "      attestations: read"),
        ('    branches: [main]', '    branches: [develop]'),
        ('      - "config/extension.json"', '      - ".github/workflows/update-watch.yml"'),
        ('automatic-postmerge-audit-readonly.yml@' + NATIVE_READERS_SHARED,
         'automatic-postmerge-audit-readonly.yml@main'),
        ('      pull-requests: read', '      pull-requests: write'),
        ('cron: "30 * * * *"', 'cron: "* * * * *"'),
        ('operator-update-auto.yml@' + SCHEDULED_SHARED, 'operator-update-auto.yml@main'),
        ('operator-update-auto.yml@' + SCHEDULED_SHARED,
         'operator-update-auto.yml@' + SHARED),
        ('operator-update-auto.yml@' + SCHEDULED_SHARED,
         'operator-update-auto.yml@39a329fb5e7c7f801eef3a23688fdd76cce8b2ac'),
        ('operator-update-auto.yml@' + SCHEDULED_SHARED,
         'operator-update-auto.yml@b852a8bbececa3e9f2c3de274db69bc7d0304f46'),
        ('      detector_sha: ' + PIN, '      detector_sha: main'),
        ('    permissions:\n      contents: read\n    uses: pgextwin/build/.github/workflows/operator-update-auto.yml',
         '    permissions:\n      contents: write\n    uses: pgextwin/build/.github/workflows/operator-update-auto.yml'),
        ("needs.authorize.outputs.mode == 'candidate'",
         "needs.authorize.outputs.mode == 'read-only'"),
        ("needs.watch_candidate.result == 'success'",
         "needs.watch_candidate.result == 'failure'"),
        ("uses: pgextwin/build/.github/workflows/candidate-update.yml@" + STAGE,
         "uses: pgextwin/build/.github/workflows/candidate-update.yml@main"),
        ("uses: pgextwin/build/.github/workflows/check-extension-updates.yml@" + STAGE,
         "uses: pgextwin/build/.github/workflows/check-extension-updates.yml@main"),
        ("      issues: write", "      contents: write"),
        ("      actions: write", "      actions: read"),
        ("requalify-merged-candidate-signed.yml@12e9c809d963c82735e23680ac1838693a6de356",
         "requalify-merged-candidate-signed.yml@main"),
        ("needs.authorize.outputs.mode == 'none'",
         "needs.authorize.outputs.mode == 'candidate'"),
        ("\n  merged_candidate_scheduled_oidc:\n",
         "\n  unapproved_schedule_signer:\n"),
        ("  schedule:\n", "  workflow_dispatch:\n"),
    )
    for before, after in mutants:
        if before not in src:
            raise AssertionError("missing hostile fixture " + before[:60])
        try:
            # The native PR audit also legitimately has pull-requests: read.
            # Mutate the final, exact main-push observer instead of that sibling.
            if before == '      pull-requests: read':
                # Target legacy read-only main observer, not new signer.
                observer_at = src.index("  candidate_main_merge_observation:\n")
                at = src.index(before, observer_at)
                altered = src[:at] + after + src[at + len(before):]
            else:
                altered = src.replace(before, after, 1)
            verify(altered)
        except ValueError:
            continue
        raise AssertionError("unsafe scheduled candidate mutation accepted: " + before[:60])
    print("PASS: scheduled immutable B1 candidate gate and " + str(len(mutants))
          + " hostile mutations; no human UPDATE or PUBLISH")


if __name__ == "__main__":
    main()
