#!/usr/bin/env python3
"""B1: offline adversarial contract for nonpublishing request-only update watch."""
from pathlib import Path
import re

PATH = Path('.github/workflows/update-watch.yml')
PIN = '16b886b9d06d6f389b369b87ce0c155767697ca0'


def verify(s):
    for marker in (
        'on:\n  workflow_dispatch:', 'default: true', 'permissions:\n  contents: read',
        'cancel-in-progress: false',
        'EVENT_NAME: ${{ github.event_name }}', 'REPO: ${{ github.repository }}',
        'REF_NAME: ${{ github.ref }}', 'HEAD_SHA: ${{ github.sha }}',
        'ACTOR: ${{ github.actor }}', 'TRIGGERING_ACTOR: ${{ github.triggering_actor }}',
        'RUN_ATTEMPT: ${{ github.run_attempt }}', 'DRY_RUN: ${{ inputs.dry_run }}',
        'CONFIRM_UPDATE: ${{ inputs.confirm_update }}',
        'EXPECTED_MAIN_SHA: ${{ inputs.expected_main_sha }}',
        '"$EVENT_NAME" != "workflow_dispatch"',
        '"$REPO" != "pgextwin/plpgsql_check"',
        '"$REF_NAME" != "refs/heads/main"', '"$RUN_ATTEMPT" != "1"',
        '"$ACTOR" != "ShutenOishi"', '"$TRIGGERING_ACTOR" != "ShutenOishi"',
        '"$CONFIRM_UPDATE" != "UPDATE"',
        '"$EXPECTED_MAIN_SHA" =~ ^[0-9a-f]{40}$',
        '"$EXPECTED_MAIN_SHA" != "$HEAD_SHA"',
        'if [[ -n "$CONFIRM_UPDATE" || -n "$EXPECTED_MAIN_SHA" ]]',
        'echo \'mode=read-only\' >> "$GITHUB_OUTPUT"',
        'echo \'mode=candidate\' >> "$GITHUB_OUTPUT"',
        "if: ${{ needs.authorize.outputs.mode == 'read-only' }}",
        "if: ${{ needs.authorize.outputs.mode == 'candidate' }}",
        "if: ${{ needs.authorize.outputs.mode == 'candidate' && needs.watch_candidate.result == 'success' }}",
    ):
        if marker not in s:
            raise ValueError('Missing guarded input/condition: ' + marker[:65])
    if any(token in s for token in (
        '\n  schedule:', '\n  push:', '\n  pull_request:', '\n  repository_dispatch:',
        '\n  workflow_call:', 'gh release ', 'confirm_release=PUBLISH',
        'build-extension-attested.yml',
    )):
        raise ValueError('Unapproved automatic/publication trigger')
    if not re.search(r'(?m)^  authorize:$', s):
        raise ValueError('Authorization required')
    sections = {
        'watch_readonly': s.split('  watch_readonly:\n', 1)[1].split('  watch_candidate:\n', 1)[0],
        'watch_candidate': s.split('  watch_candidate:\n', 1)[1].split('  candidate:\n', 1)[0],
        'candidate': s.split('  candidate:\n', 1)[1],
    }
    ro = sections['watch_readonly']
    if not re.search(r'(?m)^    permissions:\n      contents: read$', ro):
        raise ValueError('Read-only job token not read-only')
    if ro.count('persist-credentials: false') != 2 or 'persist-credentials: true' in ro:
        raise ValueError('Read-only checkout persisted credentials')
    if any(token in ro for token in ('issues: write', 'contents: write',
                                     'upload-artifact', 'candidate-update.yml',
                                     'reconcile-update-issue', 'gh workflow run ')):
        raise ValueError('Read-only job attempted mutation')
    for marker in (f'ref: {PIN}', f'--watcher-sha {PIN}',
                   'scripts/fleet-control.py', '--action watch',
                   'scripts/check-upstream-update.py',
                   'scripts/write-update-watch-summary.py'):
        if marker not in ro:
            raise ValueError('Missing pinned read-only source or command: ' + marker)
    if not re.search(r'(?m)^    permissions:\n      contents: read\n      issues: write$', sections['watch_candidate']):
        raise ValueError('Candidate watch permissions drifted')
    if f'uses: pgextwin/build/.github/workflows/check-extension-updates.yml@{PIN}' not in sections['watch_candidate'] or 'dry_run: false' not in sections['watch_candidate']:
        raise ValueError('Missing pinned candidate-only watch')
    if not re.search(r'(?m)^    permissions:\n      contents: write\n      pull-requests: write\n      actions: write$', sections['candidate']):
        raise ValueError('Candidate permission boundary changed')
    if f'uses: pgextwin/build/.github/workflows/candidate-update.yml@{PIN}' not in sections['candidate'] or 'dry_run: false' not in sections['candidate']:
        raise ValueError('Missing pinned candidate-only proposer')
    if s.count('dry_run: false') != 2 or s.count('dry_run: true') != 0:
        raise ValueError('Unexpected candidate operation path')


def main():
    src = PATH.read_text(encoding='utf-8')
    verify(src)
    mutants = (
        ('on:\n  workflow_dispatch:', 'on:\n  schedule:'),
        ('default: true', 'default: false'),
        ('"$REF_NAME" != "refs/heads/main"', '"$REF_NAME" != "refs/heads/feature"'),
        ('"$ACTOR" != "ShutenOishi"', '"$ACTOR" != "github-actions[bot]"'),
        ('"$TRIGGERING_ACTOR" != "ShutenOishi"', '"$TRIGGERING_ACTOR" != "github-actions[bot]"'),
        ('"$RUN_ATTEMPT" != "1"', '"$RUN_ATTEMPT" != "2"'),
        ('"$CONFIRM_UPDATE" != "UPDATE"', '"$CONFIRM_UPDATE" != "ANY"'),
        ('"$EXPECTED_MAIN_SHA" != "$HEAD_SHA"', '"$EXPECTED_MAIN_SHA" == "$HEAD_SHA"'),
        ('    permissions:\n      contents: read\n    steps:\n      - name: Checkout pilot configuration', '    permissions:\n      contents: write\n    steps:\n      - name: Checkout pilot configuration'),
        ('persist-credentials: false', 'persist-credentials: true'),
        (f'ref: {PIN}', 'ref: main'),
        ('--action watch', '--action candidate'),
        ("needs.watch_candidate.result == 'success'", "needs.watch_candidate.result == 'failure'"),
        (f'uses: pgextwin/build/.github/workflows/candidate-update.yml@{PIN}',
         'uses: pgextwin/build/.github/workflows/candidate-update.yml@main'),
    )
    for i, (before, after) in enumerate(mutants, 1):
        if before not in src:
            raise AssertionError('Missing hostile fixture: ' + str(i))
        try:
            verify(src.replace(before, after, 1))
        except ValueError:
            continue
        raise AssertionError('Unsafe change accepted: ' + str(i))
    print(f'PASS: B1 on-demand read-only isolation; {len(mutants)} hostile workflow mutants denied')


if __name__ == '__main__':
    main()
