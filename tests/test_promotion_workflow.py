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
    def test_existing_manual_dispatch_policy_is_preserved(self):
        self.assertIn("workflow_dispatch:", PROMOTION)
        self.assertIn("confirm_release:", PROMOTION)
        self.assertIn("Type PUBLISH", PROMOTION)
        self.assertIn("github.ref == 'refs/heads/main'", PROMOTION)
        self.assertIn("cancel-in-progress: false", PROMOTION)
        for key in ("candidate_pr", "candidate_run_id", "decision_run_id",
                    "release_tag", "confirm_release"):
            self.assertIn(key + ": ${{ inputs." + key + " }}", PROMOTION)
        self.assertNotIn("pull_request_target", PROMOTION)
        self.assertNotIn("gh release ", PROMOTION)
        self.assertNotIn("secrets: inherit", PROMOTION)
        self.assertNotIn("environment: formal-release", PROMOTION)

    def test_exact_pinned_shared_promotion_not_inline_privileged_copy(self):
        self.assertIn(
            "pgextwin/build/.github/workflows/promote-verified-release.yml@"
            "5425225ea858f8c0165421902c3e66c6c9205f60", PROMOTION)
        self.assertNotIn("fleet-promotion-gate.py", PROMOTION)
        self.assertNotIn("fleet-publish-release.py", PROMOTION)
        self.assertNotIn("release_build:", PROMOTION)
        self.assertNotIn("--clobber", PROMOTION)
        self.assertIn("catalog_app_private_key:", PROMOTION)
        # The central pinned workflow has its own required static hostile tests.
        uses = re.findall(r"(?m)^\s*(?:-\s*)?uses:\s+([^\s#]+)", PROMOTION)
        self.assertEqual(len(uses), 1)
        self.assertTrue(all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", x) for x in uses))

    def test_no_unapproved_release_branch_path(self):
        self.assertNotIn('      - "release/**"', WINDOWS)
        self.assertNotIn("  release:", WINDOWS)
        self.assertNotIn("  release_build:", WINDOWS)
        self.assertIn("candidate_report:", WINDOWS)
        self.assertIn("build-extension.yml@", WINDOWS)


class GoAOfflinePolicy(unittest.TestCase):
    def test_required_syntax_check_reaches_protected_main(self):
        # Main required status must be produced on the exact postmerge main SHA.
        syntax = (ROOT / ".github/workflows/test-step19-hooks.yml").read_text(encoding="utf-8")
        self.assertIn(
            "on:\\n  pull_request:\\n  push:\\n    branches:\\n      - main\\n  workflow_dispatch:".replace("\\n", "\n"),
            syntax)
        self.assertIn("  syntax:\n    runs-on: ubuntu-latest", syntax)
        self.assertIn("permissions:\n  contents: read", syntax)
        self.assertNotIn("contents: write", syntax)
        self.assertNotIn("attestations: write", syntax)
        self.assertNotIn("gh release ", syntax)

    def test_central_main_pin_is_current_and_stale_head_is_denied(self):
        # A central revision cannot be silently authorized by a moved pointer.
        self.assertEqual(policy.CENTRAL_MAIN_PIN,
                         "dfa87e91aa0a65ceaec04cdfc67a3053f87baf75")
        stale = '{"protected":true,"commit":{"sha":"c6b7af192635c304b16edc8c7b9c1396b2cd025e"}}'
        with patch.object(policy, "gh", return_value=stale):
            with self.assertRaisesRegex(policy.Deny,
                                        "central protected main moved since GO A authorization"):
                policy.policy_readonly()

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
                "subjectAlternativeName": "https://github.com/" + policy.SIGNER + "@refs/heads/main"}
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
                             ("runnerEnvironment", "self-hosted"),
                             ("subjectAlternativeName", "https://attacker.example/workflow"),
                             ("subjectAlternativeName", ""),
                             ("subjectAlternativeName", {"type": "URI", "value": "example"}),
                             ("subjectAlternativeName", None)):
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
        # SAN must bind the *same* signer URI verified in the certificate.
        with patch.dict(cert, {"buildSignerURI":
                              "https://github.com/" + policy.SIGNER + "@attacker-ref"}):
            with self.assertRaises(policy.Deny):
                policy.verified_statement(result, policy.SPDX, "test.zip", digest, sha,
                                          run, 1, {"spdxVersion": "SPDX-2.3"})

    def test_no_duplicate_json_keys_or_write_commands(self):
        with self.assertRaises(policy.Deny):
            policy.parse('{"a":1,"a":2}')
        with self.assertRaises(policy.Deny):
            policy.gh("api", "--method", "POST", "repos/pgextwin/plpgsql_check/releases")


if __name__ == "__main__":
    unittest.main()
