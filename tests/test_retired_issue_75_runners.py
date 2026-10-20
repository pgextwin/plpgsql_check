#!/usr/bin/env python3
"""Do not reactivate retired one-shot Issue 75 execution paths."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
WF = ROOT / ".github" / "workflows"


class RetiredIssue75Runners(unittest.TestCase):
    def test_no_one_shot_smoke_or_g2_live_probe(self):
        for name in ("issue-75-windows-runner-smoke.yml", "issue-75-g2-readonly.yml"):
            with self.subTest(name=name):
                self.assertFalse((WF / name).exists())

    def test_live_build_and_historical_evidence_remain(self):
        for name in ("windows.yml", "promote.yml", "test-step19-hooks.yml",
                     ):
            with self.subTest(name=name):
                self.assertTrue((WF / name).is_file())
        self.assertTrue((ROOT / "scripts/issue_75_go_a_readonly_recover.py").is_file())
        self.assertTrue((ROOT / "tests/test_issue_75_go_a_readonly_recovery.py").is_file())

    def test_completed_readonly_app_proofs_are_archived_only(self):
        # Preserve original 2026-10-13 proof code/hostile tests, without
        # keeping path-triggered one-off Actions or minting new audit tokens.
        for name in ("classic-protection-audit.yml",
                     "phase-d-live-deny-probe.yml"):
            with self.subTest(name=name):
                self.assertFalse((WF / name).exists())
                self.assertTrue((ROOT / "tests/fixtures/historical-workflows" / name).is_file())
        syntax = (WF / "test-step19-hooks.yml").read_text(encoding="utf-8")
        for name in ("test_classic_protection_audit_workflow.py",
                     "test_phase_d_live_deny_workflow.py"):
            self.assertTrue((ROOT / "tests" / name).is_file())
            self.assertIn(name, syntax)
        for name in ("windows.yml", "promote.yml", "update-watch.yml",
                     "test-step19-hooks.yml"):
            self.assertTrue((WF / name).is_file())
        promote = (WF / "promote.yml").read_text(encoding="utf-8")
        self.assertIn("Type PUBLISH", promote)
        self.assertIn("promote-verified-release.yml@", promote)
        self.assertNotIn("pull_request_target:", syntax)

    def test_historical_release_oneoffs_are_never_live(self):
        # All three complete/failed one-shot paths are historical, not the
        # canonical current signed Release flow or a publication approval.
        for name in ("pg14-backfill.yml",
                     "issue-75-pre-g4-signed-canary.yml",
                     "historical-release-bilingual.yml"):
            with self.subTest(name=name):
                self.assertFalse((WF / name).exists())
                self.assertTrue((ROOT / "tests/fixtures/historical-workflows" / name).is_file())
        self.assertTrue((ROOT / "scripts/pg14-backfill-preflight.py").is_file())
        self.assertTrue((ROOT / "scripts/issue_75_go_a_canary_verify.py").is_file())
        self.assertTrue((ROOT / "scripts/bilingual_release_migration.py").is_file())
        self.assertTrue((ROOT / "config/historical-release-bilingual.json").is_file())
        self.assertTrue((ROOT / "tests/test_promotion_workflow.py").is_file())
        self.assertTrue((ROOT / "tests/test_pg14_backfill.py").is_file())
        live = (WF / "test-step19-hooks.yml").read_text(encoding="utf-8")
        windows = (WF / "windows.yml").read_text(encoding="utf-8")
        promotion = (WF / "promote.yml").read_text(encoding="utf-8")
        self.assertIn("tests/test_promotion_workflow.py", live)
        self.assertIn("tests/test_pg14_backfill.py", windows)
        self.assertIn("name: Windows required summary", windows)
        self.assertIn("pgextwin/build/.github/workflows/promote-verified-release.yml@", promotion)
        self.assertIn("Type PUBLISH", promotion)
        self.assertNotIn("release-extension.yml@", promotion)

    def test_unreachable_historical_pr45_job_not_in_active_ci(self):
        text = (WF / "test-step19-hooks.yml").read_text(encoding="utf-8")
        self.assertNotIn("original_go_a_readonly_recovery:", text)
        self.assertNotIn("github.event.pull_request.number == 45", text)
        self.assertIn("  syntax:", text)
        self.assertIn("tests/test_promotion_workflow.py", text)


if __name__ == "__main__":
    unittest.main()
