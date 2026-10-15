#!/usr/bin/env python3
"""B1: deny hostile mutations of the explicit manual-update pilot."""
from pathlib import Path
import re

WORKFLOW = Path(".github/workflows/update-watch.yml")


def verify(text):
    required = (
        "on:\n  workflow_dispatch:",
        "required: true\n        type: boolean\n        default: true",
        "permissions:\n  contents: read",
        "cancel-in-progress: false",
        "if: ${{ needs.authorize.outputs.mode == 'read-only' }}",
        "if: ${{ needs.authorize.outputs.mode == 'candidate' }}",
        "if: ${{ needs.authorize.outputs.mode == 'candidate' && needs.watch_candidate.result == 'success' }}",
        "EVENT_NAME: ${{ github.event_name }}",
        "REPO: ${{ github.repository }}",
        "REF_NAME: ${{ github.ref }}",
        "HEAD_SHA: ${{ github.sha }}",
        "RUN_ATTEMPT: ${{ github.run_attempt }}",
        "ACTOR: ${{ github.actor }}",
        "TRIGGERING_ACTOR: ${{ github.triggering_actor }}",
        "DRY_RUN: ${{ inputs.dry_run }}",
        "CONFIRM_UPDATE: ${{ inputs.confirm_update }}",
        "EXPECTED_MAIN_SHA: ${{ inputs.expected_main_sha }}",
        '"$EVENT_NAME" != "workflow_dispatch"',
        '"$REPO" != "pgextwin/plpgsql_check"',
        '"$REF_NAME" != "refs/heads/main"',
        '"$RUN_ATTEMPT" != "1"',
        '"$DRY_RUN" == "true"',
        '"$DRY_RUN" == "false"',
        '"$ACTOR" != "ShutenOishi"',
        '"$TRIGGERING_ACTOR" != "ShutenOishi"',
        '"$CONFIRM_UPDATE" != "UPDATE"',
        '"$EXPECTED_MAIN_SHA" =~ ^[0-9a-f]{40}$',
        '"$EXPECTED_MAIN_SHA" != "$HEAD_SHA"',
        'if [[ -n "$CONFIRM_UPDATE" || -n "$EXPECTED_MAIN_SHA" ]]',
        "echo 'mode=read-only' >> \"$GITHUB_OUTPUT\"",
        "echo 'mode=candidate' >> \"$GITHUB_OUTPUT\"",
        "uses: pgextwin/build/.github/workflows/check-extension-updates.yml@16b886b9d06d6f389b369b87ce0c155767697ca0",
        "uses: pgextwin/build/.github/workflows/candidate-update.yml@16b886b9d06d6f389b369b87ce0c155767697ca0",
    )
    for item in required:
        if item not in text:
            raise ValueError("B1 contract missing: " + item[:60])
    forbidden = (
        "\n  schedule:", "\n  push:", "\n  pull_request:", "\n  repository_dispatch:",
        "\n  workflow_call:", "gh release ", "confirm_release=PUBLISH",
        "pgextwin/build/.github/workflows/build-extension-attested.yml",
    )
    if any(item in text for item in forbidden):
        raise ValueError("Unapproved trigger/signing/publication path")
    if len(re.findall(r"(?m)^    uses: pgextwin/build/\.github/workflows/candidate-update\.yml@", text)) != 1:
        raise ValueError("Candidate reused unexpectedly")
    if not re.search(r"(?ms)^  watch_readonly:\n.*?^    permissions:\n      contents: read\n      issues: read\n.*?^      dry_run: true$", text):
        raise ValueError("Read-only permission or dry-run contract changed")
    if not re.search(r"(?ms)^  watch_candidate:\n.*?^    permissions:\n      contents: read\n      issues: write\n.*?^      dry_run: false$", text):
        raise ValueError("Mutating watch path changed")
    if not re.search(r"(?ms)^  candidate:\n.*?^    permissions:\n      contents: write\n      pull-requests: write\n      actions: write\n.*?^      dry_run: false$", text):
        raise ValueError("Candidate permission or mode changed")
    if text.count("dry_run: false") != 2 or text.count("dry_run: true") != 1:
        raise ValueError("Unexpected candidate or dry-run path")
    if 'if [[ "$DRY_RUN" == "true" ]]; then' not in text or 'elif [[ "$DRY_RUN" == "false" ]]; then' not in text:
        raise ValueError("No separate mode partition")
    locations = [text.find(k) for k in ("  authorize:", "  watch_readonly:", "  watch_candidate:", "  candidate:")]
    if any(x < 0 for x in locations) or locations != sorted(locations):
        raise ValueError("Authorization must come first")


def main():
    text = WORKFLOW.read_text(encoding="utf-8")
    verify(text)
    mutants = (
        ("on:\n  workflow_dispatch:", "on:\n  schedule:"),
        ("default: true", "default: false"),
        ('"$REF_NAME" != "refs/heads/main"', '"$REF_NAME" != "refs/heads/develop"'),
        ('"$ACTOR" != "ShutenOishi"', '"$ACTOR" != "github-actions[bot]"'),
        ('"$TRIGGERING_ACTOR" != "ShutenOishi"', '"$TRIGGERING_ACTOR" != "github-actions[bot]"'),
        ('"$RUN_ATTEMPT" != "1"', '"$RUN_ATTEMPT" != "2"'),
        ('"$CONFIRM_UPDATE" != "UPDATE"', '"$CONFIRM_UPDATE" != "PUBLISH"'),
        ('"$EXPECTED_MAIN_SHA" != "$HEAD_SHA"', '"$EXPECTED_MAIN_SHA" == "$HEAD_SHA"'),
        ('if [[ -n "$CONFIRM_UPDATE" || -n "$EXPECTED_MAIN_SHA" ]]', 'if [[ -z "$CONFIRM_UPDATE" ]]'),
        ("      issues: read", "      issues: write"),
        ("      dry_run: true", "      dry_run: false"),
        ("needs.watch_candidate.result == 'success'", "needs.watch_candidate.result == 'failure'"),
        ("if: ${{ needs.authorize.outputs.mode == 'read-only' }}", "if: ${{ needs.authorize.outputs.mode == 'candidate' }}"),
        ("uses: pgextwin/build/.github/workflows/candidate-update.yml@16b886b9d06d6f389b369b87ce0c155767697ca0",
         "uses: pgextwin/build/.github/workflows/candidate-update.yml@main"),
    )
    for index, (old, new) in enumerate(mutants, 1):
        if old not in text:
            raise AssertionError("Missing mutation fixture " + str(index))
        try:
            verify(text.replace(old, new, 1))
        except ValueError:
            pass
        else:
            raise AssertionError("Unauthorized mutation " + str(index))
    print(f"PASS: on-demand update B1 safety plus {len(mutants)} denied hostile mutations")


if __name__ == "__main__":
    main()
