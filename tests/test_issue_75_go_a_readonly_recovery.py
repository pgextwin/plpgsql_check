#!/usr/bin/env python3
"""Offline adversarial fixtures for historical GO A read-only recovery."""
from __future__ import annotations
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue_75_go_a_canary_verify as policy
import issue_75_go_a_readonly_recover as recovery


def fixture():
    required = sorted(policy.REQUIRED)
    jobs = [
        {"id": 117326505482, "name": "Fail-closed dispatch, main, lifecycle and one-shot guard",
         "conclusion": "success"},
        {"id": 117326544666, "name": "Immutable reusable signer / matrix resolver",
         "conclusion": "success"}
    ] + [
        {"id": 117326592770 + k, "name": f"Signer / PostgreSQL {m} / Windows x64",
         "conclusion": "success"} for k, m in enumerate(policy.MAJORS)
    ] + [
        {"id": recovery.FAILED_VERIFY_JOB,
         "name": "Independent read-only real X.509 and ZIP/SPDX proof", "conclusion": "failure"}
    ]
    prefix = f"actions/runs/{recovery.RUN}"
    data = {
        "branches/main": {
            "protected": True,
            "protection": {"required_status_checks": {
                "enforcement_level": "everyone",
                "checks": [{"context": c, "app_id": 15368} for c in required]}}
        },
        f"commits/{recovery.SHA}/check-runs?per_page=100": {
            "total_count": len(required),
            "check_runs": [{"name": c, "app": {"id": 15368},
                            "status": "completed", "conclusion": "success"} for c in required]
        },
        prefix: {
            "id": recovery.RUN, "run_attempt": 1,
            "head_sha": recovery.SHA, "head_branch": "main",
            "path": policy.WORKFLOW, "event": "workflow_dispatch",
            "repository": {"id": policy.REPO_ID},
            "actor": {"login": "ShutenOishi"},
            "triggering_actor": {"login": "ShutenOishi"},
            "status": "completed", "conclusion": "failure"
        },
        "actions/workflows/issue-75-pre-g4-signed-canary.yml/runs"
        "?event=workflow_dispatch&per_page=100": {
            "total_count": 1, "workflow_runs": [
                {"id": recovery.RUN, "run_attempt": 1}]},
        f"contents/.github/workflows/issue-75-pre-g4-signed-canary.yml?ref={recovery.SHA}": {
            "type": "file", "sha": recovery.WORKFLOW_BLOB},
        f"contents/scripts/issue_75_go_a_canary_verify.py?ref={recovery.SHA}": {
            "type": "file", "sha": recovery.ORIGINAL_VERIFIER_BLOB},
        prefix + "/jobs?per_page=100": {"total_count": len(jobs), "jobs": jobs}
    }
    return data


def artifacts_fixture():
    rows = []
    for major, (ident, size, digest, _) in recovery.ARTIFACTS.items():
        rows.append({"id": ident, "name": f"plpgsql_check-pg{major}-windows-x64",
                     "size_in_bytes": size, "digest": "sha256:" + digest, "expired": False})
    return {"total_count": 5, "artifacts": rows}


class HistoricalRecoveryTests(unittest.TestCase):
    def test_historical_run_remains_failure_with_eight_required_checks(self):
        data = fixture()
        with patch.object(policy, "api", side_effect=data.__getitem__) as ap:
            recovery.read_only_context()
        self.assertGreaterEqual(ap.call_count, 5)
        self.assertEqual(recovery.RUN, 39008743613)
        self.assertEqual(recovery.ATTEMPT, 1)

    def test_fail_closed_mutations_of_original_run_and_checks(self):
        changes = [
            (f"actions/runs/{recovery.RUN}", "run_attempt", 2),
            (f"actions/runs/{recovery.RUN}", "head_sha", "0" * 40),
            (f"actions/runs/{recovery.RUN}", "conclusion", "success"),
            (f"actions/runs/{recovery.RUN}", "event", "push"),
            ("actions/workflows/issue-75-pre-g4-signed-canary.yml/runs"
             "?event=workflow_dispatch&per_page=100", "total_count", 2),
            (f"contents/.github/workflows/issue-75-pre-g4-signed-canary.yml?ref={recovery.SHA}",
             "sha", "0" * 40),
        ]
        for endpoint, key, value in changes:
            with self.subTest(endpoint=endpoint, key=key, value=str(value)):
                data = fixture()
                data[endpoint][key] = value
                with patch.object(policy, "api", side_effect=data.__getitem__):
                    with self.assertRaises(policy.Deny):
                        recovery.read_only_context()
        data = fixture()
        data[f"actions/runs/{recovery.RUN}/jobs?per_page=100"]["jobs"][-1]["conclusion"] = "success"
        with patch.object(policy, "api", side_effect=data.__getitem__):
            with self.assertRaises(policy.Deny):
                recovery.read_only_context()
        data = fixture()
        data[f"commits/{recovery.SHA}/check-runs?per_page=100"]["check_runs"][0]["app"]["id"] = 999
        with patch.object(policy, "api", side_effect=data.__getitem__):
            with self.assertRaises(policy.Deny):
                recovery.read_only_context()

    def test_frozen_artifact_inventory_and_mutations(self):
        data = artifacts_fixture()
        with patch.object(policy, "api", return_value=data):
            recovery.immutable_artifact_inventory()
        for mutation in ("id", "size_in_bytes", "digest", "expired"):
            changed = copy.deepcopy(data)
            changed["artifacts"][0][mutation] = {
                "id": 999999, "size_in_bytes": 0,
                "digest": "sha256:" + "0" * 64, "expired": True
            }[mutation]
            with self.subTest(mutation=mutation), patch.object(policy, "api", return_value=changed):
                with self.assertRaises(policy.Deny):
                    recovery.immutable_artifact_inventory()

    def test_no_auto_acceptance_or_write_side_workflow(self):
        source = (Path(__file__).resolve().parents[1] /
                  "scripts/issue_75_go_a_readonly_recover.py").read_text(encoding="utf-8")
        self.assertIn('"originalRunConclusion": "failure"', source)
        self.assertIn('"canaryWorkflowSuccess": False', source)
        self.assertIn('"formalP1RowsAdded": 0', source)
        self.assertIn('"publication": "DENY"', source)
        self.assertIn('"newSignaturesGenerated": 0', source)
        self.assertNotIn('gh workflow run', source)
        self.assertNotIn('gh run rerun', source)
        self.assertNotIn('gh release create', source)
        self.assertNotIn('actions/attest@', source)


if __name__ == "__main__":
    unittest.main()
