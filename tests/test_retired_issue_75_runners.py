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
                     "issue-75-pre-g4-signed-canary.yml",
                     "classic-protection-audit.yml",
                     "phase-d-live-deny-probe.yml"):
            with self.subTest(name=name):
                self.assertTrue((WF / name).is_file())
        self.assertTrue((ROOT / "scripts/issue_75_go_a_readonly_recover.py").is_file())
        self.assertTrue((ROOT / "tests/test_issue_75_go_a_readonly_recovery.py").is_file())

    def test_unreachable_historical_pr45_job_not_in_active_ci(self):
        text = (WF / "test-step19-hooks.yml").read_text(encoding="utf-8")
        self.assertNotIn("original_go_a_readonly_recovery:", text)
        self.assertNotIn("github.event.pull_request.number == 45", text)
        self.assertIn("  syntax:", text)
        self.assertIn("tests/test_promotion_workflow.py", text)


if __name__ == "__main__":
    unittest.main()
