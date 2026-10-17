# Issue #75: nonpublishing, docs-only GitHub event probe

This file is deliberately **not** a Release authorization, workflow trigger, or candidate.
It exists solely to observe real GitHub PR author, merger, squash commit, and protected-main
push/Actions actor metadata when the normal Chat GitHub connector creates and merges a PR.

- Pilot repository: `pgextwin/plpgsql_check`
- Pre-probe main SHA: `5df0d0e7e90719390c0c864d50dd6d56a51ec561`
- Work item: https://github.com/pgextwin/build/issues/75
- The PR must be a single-file, squash-only merge after exact-head protected CI success.
- Validate `merged_by.login`, PR `user.login`, commit parents and changed files from
  live GitHub API, and `actor`, `triggering_actor`, `event`, `head_sha`,
  `run_attempt` from the real **push** Actions run.
- A GitHub Actions run actor is not by itself a proof of the caller's Chat intent.
  Do not confuse a docs-only merged PR with the hypothetical authorization schema.
- Keep `config/release-promotion.json` as `manual-dispatch` and
  `.github/workflows/promote.yml` unchanged.
- No new workflow, publisher, authorization file, Release tag, or privileged token.
- If any required event is absent, record **BLOCKED**, not a simulated success.

**No action in this file can publish a Release.**
