#!/usr/bin/env python3
"""Fail-closed source-specific export-audit binding tests (offline; no release)."""
from __future__ import annotations
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "config/extension.json"
AUDIT = ROOT / "config/export-audit.json"
REVIEWED_AUDITS = ROOT / "config/export-audits"
BUILD = ROOT / "windows/ci/build.ps1"
SHA40 = re.compile(r"^[0-9a-f]{40}$")


def validate(manifest: dict, audit: dict) -> None:
    assert type(manifest) is dict and type(audit) is dict
    source = manifest["upstream"]
    assert source["repository"] == "okbob/plpgsql_check"
    assert type(source["commit"]) is str and SHA40.fullmatch(source["commit"])
    assert type(audit["upstreamCommit"]) is str
    assert audit["upstreamCommit"] == source["commit"], (
        "Unreviewed upstream change must not reuse a previous export audit"
    )
    assert audit["schemaVersion"] == 1 and audit["sqlExtensionVersion"] == "2.10"
    assert audit["moduleMagicExport"] == "Pg_magic_func"
    assert audit["moduleInitializerExport"] == "_PG_init"
    symbols = audit["requiredSqlSymbols"]
    assert type(symbols) is list and len(symbols) == 23
    assert len(set(symbols)) == 23
    assert all(type(s) is str and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", s)
               for s in symbols)


def load_reviewed_audit(manifest: dict) -> dict:
    """Never treat a mutable tag or a different source SHA as reviewed."""
    legacy = json.loads(AUDIT.read_text(encoding="utf-8"))
    source_sha = manifest["upstream"]["commit"]
    if legacy["upstreamCommit"] == source_sha:
        return legacy
    if type(source_sha) is not str or not SHA40.fullmatch(source_sha):
        return legacy  # validate() must reject it
    source_file = REVIEWED_AUDITS / (source_sha + ".json")
    if not source_file.is_file():
        return legacy  # unknown sources must fail the exact source audit
    reviewed = json.loads(source_file.read_text(encoding="utf-8"))
    assert reviewed["upstreamCommit"] == source_sha, (
        "Reviewed SHA-named audit file has mismatched source identity"
    )
    return reviewed


class SourceSpecificExportAuditTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.audit = load_reviewed_audit(self.manifest)

    def test_real_manifest_exact_source_sha_matches_reviewed_export_audit(self):
        validate(self.manifest, self.audit)

    def test_all_reviewed_successor_audits_are_immutably_source_bound(self):
        import copy
        approved_files = sorted(REVIEWED_AUDITS.glob("*.json"))
        self.assertTrue(approved_files, "No independent reviewed source records")
        for source_file in approved_files:
            sha = source_file.stem
            with self.subTest(sha=sha):
                self.assertRegex(sha, SHA40)
                reviewed = json.loads(source_file.read_text(encoding="utf-8"))
                self.assertEqual(reviewed["upstreamCommit"], sha)
                candidate = copy.deepcopy(self.manifest)
                candidate["upstream"]["commit"] = sha
                validate(candidate, load_reviewed_audit(candidate))
                self.assertEqual(load_reviewed_audit(candidate), reviewed)
                wrong = copy.deepcopy(reviewed)
                wrong["upstreamCommit"] = "e" * 40
                with self.assertRaises(AssertionError):
                    validate(candidate, wrong)

    def test_unknown_source_never_inherits_audit_without_review(self):
        import copy
        candidate = copy.deepcopy(self.manifest)
        candidate["upstream"]["commit"] = "f" * 40
        with self.assertRaises(AssertionError):
            validate(candidate, load_reviewed_audit(candidate))

    def test_stale_moved_or_forged_source_identity_is_denied(self):
        import copy
        for change in (
            lambda m, a: m["upstream"].update(commit="f" * 40),
            lambda m, a: a.update(upstreamCommit="e" * 40),
            lambda m, a: a.update(upstreamCommit="HEAD"),
            lambda m, a: a.update(schemaVersion=2),
            lambda m, a: a.update(moduleMagicExport=""),
            lambda m, a: a["requiredSqlSymbols"].pop(),
            lambda m, a: a["requiredSqlSymbols"].append(a["requiredSqlSymbols"][0]),
            lambda m, a: m["upstream"].update(repository="untrusted/fork"),
        ):
            m, a = copy.deepcopy(self.manifest), copy.deepcopy(self.audit)
            change(m, a)
            with self.subTest(change=repr(change)), self.assertRaises(
                (AssertionError, KeyError, TypeError)
            ):
                validate(m, a)

    def test_release_main_must_not_bypass_source_specific_export_audit(self):
        script = BUILD.read_text(encoding="utf-8")
        self.assertIn("A new formal release requires a source-specific independent export audit.", script)
        self.assertRegex(
            script,
            r"if\s*\(-not\s+\$isCandidate\s+-and\s+\$audit\.upstreamCommit\s+-cne\s+\$expectedSha\)",
        )
        self.assertIn("throw 'A new formal release requires a source-specific independent export audit.'", script)
        self.assertIn("Verified $($exports.Count) DLL exports", script)
        self.assertIn("if ($approved.Count -ne 23)", script)
        self.assertIn("config\\export-audits", script)
        self.assertIn("($expectedSha + '.json')", script)
        self.assertIn("if ($reviewedAudit.upstreamCommit -cne $expectedSha)", script)
        self.assertNotIn("$audit.upstreamCommit = $expectedSha", script)


if __name__ == "__main__":
    unittest.main()
