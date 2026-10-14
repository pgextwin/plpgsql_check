#!/usr/bin/env python3
"""Step 21 publication and Issue #75 GO A safety invariants (offline only)."""
from pathlib import Path
import importlib.util
import re
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PROMOTION = (ROOT / ".github/workflows/promote.yml").read_text(encoding="utf-8")
WINDOWS = (ROOT / ".github/workflows/windows.yml").read_text(encoding="utf-8")
CANARY = (ROOT / ".github/workflows/issue-75-pre-g4-signed-canary.yml").read_text(encoding="utf-8")
spec = importlib.util.spec_from_file_location(
    "go_a_policy", ROOT / "scripts/issue_75_go_a_canary_verify.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class PromotionWorkflow(unittest.TestCase):
    def test_checkout_has_complete_main_ancestry(self):
        authorize = PROMOTION.split("  authorize:", 1)[1].split("  release_build:", 1)[0]
        self.assertIn("fetch-depth: 0", authorize)
        self.assertIn("persist-credentials: false", authorize)
        self.assertIn("fleet-promotion-gate.py", authorize)

    def test_manual_dispatch_and_scoped_publication(self):
        self.assertIn("workflow_dispatch:", PROMOTION)
        self.assertIn("github.ref == 'refs/heads/main'", PROMOTION)
        self.assertIn("release-promotion.json", PROMOTION)
        self.assertIn("needs: [authorize, release_build]", PROMOTION)
        self.assertIn("cancel-in-progress: false", PROMOTION)
        self.assertIn("promotion-recovery", PROMOTION)
        self.assertIn("--lifecycle .pgextwin-build/metadata/postgresql.json", PROMOTION)
        self.assertIn("455f0ccc667697f600700a6e64bcfd6c57b6a977", PROMOTION)
        self.assertNotIn("environment: formal-release", PROMOTION)
        self.assertIn("confirm_release:", PROMOTION)
        self.assertIn('--confirm-release "$CONFIRM_RELEASE"', PROMOTION)
        self.assertIn("Type PUBLISH", PROMOTION)
        self.assertNotIn("approval_pr:", PROMOTION)
        self.assertNotIn("--approval-pr", PROMOTION)
        self.assertNotIn("human-reviewed", PROMOTION)
        self.assertIn("fleet-publish-release.py", PROMOTION)
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
        uses = re.findall(r"(?m)^\s*(?:-\s*)?uses:\s+([^\s#]+)", PROMOTION)
        self.assertGreaterEqual(len(uses), 5)
        self.assertTrue(all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", item) for item in uses), uses)


class GoAOfflinePolicy(unittest.TestCase):
    def test_only_dispatch_and_guarded_main_single_attempt(self):
        self.assertRegex(CANARY, r"(?m)^on:\n  workflow_dispatch:")
        self.assertNotRegex(CANARY, r"(?m)^  (push|pull_request|pull_request_target|workflow_run|schedule|release):")
        self.assertIn("github.ref == 'refs/heads/main'", CANARY)
        self.assertIn("github.run_attempt == 1", CANARY)
        self.assertIn("expected_main_sha:", CANARY)
        self.assertIn("cancel-in-progress: false", CANARY)

    def test_pinned_signer_and_no_privileged_write_or_secrets(self):
        self.assertIn("build-extension-attested.yml@" + policy.PIN, CANARY)
        for forbidden in ("contents: write", "secrets: inherit", "private-key:",
                          "gh release ", "gh workflow run ", "create-ref",
                          "publisher", "pull_request_target", "runs-on: self-hosted"):
            self.assertNotIn(forbidden, CANARY.lower() if forbidden == "publisher" else CANARY)
        refs = re.findall(r"(?m)^\s*(?:-\s*)?uses:\s+([^\s#]+)", CANARY)
        self.assertGreaterEqual(len(refs), 5)
        self.assertTrue(all(re.fullmatch(r"[^@]+@[a-f0-9]{40}", ref) for ref in refs))
        self.assertIn("id-token: write", CANARY)
        self.assertIn("attestations: read", CANARY)
        self.assertIn("persist-credentials: false", CANARY)

    def test_cert_wrong_attempt_source_builder_subject_issuer_denied(self):
        sha = "a" * 40
        digest = "b" * 64
        run = 12345
        inv = f"https://github.com/{policy.REPO}/actions/runs/{run}/attempts/1"
        cert = {"issuer": policy.ISSUER,
                "sourceRepositoryURI": f"https://github.com/{policy.REPO}",
                "sourceRepositoryRef": "refs/heads/main",
                "sourceRepositoryDigest": sha,
                "sourceRepositoryIdentifier": str(policy.REPO_ID),
                "githubWorkflowTrigger": "workflow_dispatch",
                "githubWorkflowSHA": sha,
                "runnerEnvironment": "github-hosted",
                "buildSignerDigest": policy.PIN,
                "buildSignerURI": "https://github.com/" + policy.SIGNER + "@refs/heads/main",
                "runInvocationURI": inv,
                "subjectAlternativeName": {"type": "URI", "value": "example"}}
        statement = {"_type": "https://in-toto.io/Statement/v1",
                     "predicateType": policy.SPDX,
                     "subject": [{"name": "test.zip", "digest": {"sha256": digest}}],
                     "predicate": {"spdxVersion": "SPDX-2.3"}}
        result = [{"verificationResult": {
            "statement": statement,
            "signature": {"certificate": cert},
            "verifiedTimestamps": [{"type": "Tlog"}]}}]
        # These are policy-only fixtures, NEVER cryptographic evidence.
        policy.verified_statement(result, policy.SPDX, "test.zip", digest, sha, run, 1,
                                  {"spdxVersion": "SPDX-2.3"})
        for field, wrong in (("issuer", "https://wrong.example"),
                             ("sourceRepositoryDigest", "c" * 40),
                             ("buildSignerDigest", "d" * 40),
                             ("runInvocationURI", inv.replace("/attempts/1", "/attempts/2")),
                             ("runnerEnvironment", "self-hosted")):
            with self.subTest(field=field), patch.dict(cert, {field: wrong}):
                with self.assertRaises(policy.Deny):
                    policy.verified_statement(result, policy.SPDX, "test.zip", digest, sha,
                                              run, 1, {"spdxVersion": "SPDX-2.3"})
        with self.assertRaises(policy.Deny):
            policy.verified_statement(result, policy.SPDX, "test.zip", "0" * 64, sha,
                                      run, 1, {"spdxVersion": "SPDX-2.3"})
        with self.assertRaises(policy.Deny):
            policy.verified_statement(result, policy.SPDX, "test.zip", digest, sha,
                                      run, 1, {"spdxVersion": "SPDX-2.3", "name": "tampered"})
        with self.assertRaises(policy.Deny):
            policy.verified_statement([], policy.SPDX, "test.zip", digest, sha,
                                      run, 1, {"spdxVersion": "SPDX-2.3"})

    def test_no_duplicate_json_keys_or_write_commands(self):
        with self.assertRaises(policy.Deny):
            policy.parse('{"a":1,"a":2}')
        with self.assertRaises(policy.Deny):
            policy.gh("api", "--method", "POST", "repos/pgextwin/plpgsql_check/releases")


if __name__ == "__main__":
    unittest.main()
