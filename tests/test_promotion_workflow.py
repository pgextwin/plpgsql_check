#!/usr/bin/env python3
"""Step 21 publication workflow safety invariants (no network or credentials)."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROMOTION = (ROOT / ".github/workflows/promote.yml").read_text(encoding="utf-8")
WINDOWS = (ROOT / ".github/workflows/windows.yml").read_text(encoding="utf-8")

class PromotionWorkflow(unittest.TestCase):
    def test_checkout_has_complete_main_ancestry(self):
        # A reviewed candidate and separate approval are merged BEFORE main promotion;
        # default shallow checkout would always fail the ancestry checks.
        authorize = PROMOTION.split("  authorize:",1)[1].split("  release_build:",1)[0]
        self.assertIn("fetch-depth: 0", authorize)
        self.assertIn("persist-credentials: false", authorize)
        self.assertIn("promotion-gate.py", authorize)

    def test_manual_dispatch_and_scoped_publication(self):
        self.assertIn("workflow_dispatch:", PROMOTION)
        self.assertIn("github.ref == 'refs/heads/main'", PROMOTION)
        self.assertIn("release-promotion.json", PROMOTION)
        self.assertIn("needs: [authorize, release_build]", PROMOTION)
        self.assertIn("cancel-in-progress: false", PROMOTION)
        self.assertIn("promotion-recovery", PROMOTION)
        self.assertIn("publish-release.py", PROMOTION)
        self.assertNotIn("pull_request_target", PROMOTION)
        self.assertNotIn("--clobber", PROMOTION)
        self.assertNotIn("gh release delete", PROMOTION)

    def test_no_unapproved_release_branch_path(self):
        self.assertNotIn('      - "release/**"', WINDOWS)
        self.assertNotIn("  release:", WINDOWS)
        self.assertNotIn("  release_build:", WINDOWS)
        self.assertIn("candidate_report:", WINDOWS)
        self.assertIn("build-extension.yml@", WINDOWS)

    def test_immutable_reusable_workflows(self):
        uses = re.findall(r"(?m)^\s+uses:\s+([^\s#]+)", PROMOTION)
        self.assertGreaterEqual(len(uses),5)
        self.assertTrue(all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", item) for item in uses), uses)

if __name__ == "__main__":
    unittest.main()
