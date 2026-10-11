#!/usr/bin/env python3
"""Offline one-time PG14 backfill denial matrix; no API or Release mutation."""
import importlib.util
from datetime import date
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "pg14_backfill", Path(__file__).resolve().parents[1] / "scripts" / "pg14-backfill-preflight.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

SHA = "a" * 40
MAJORS = list(gate.MAJORS)

def fixtures():
    env = {"GITHUB_REPOSITORY": gate.REPO,
           "GITHUB_REF": "refs/heads/" + gate.BRANCH,
           "GITHUB_EVENT_NAME": "push", "GITHUB_SHA": SHA}
    manifest = {"name": "plpgsql_check",
                "upstream": {"repository": "okbob/plpgsql_check",
                             "ref": "v2.10.13", "version": "2.10.13",
                             "commit": gate.UPSTREAM},
                "postgresql": {"majors": MAJORS[:]}}
    lifecycle = {"schemaVersion": 1, "postgresql": [
        {"major": m, "eol": "2026-11-12" if m == 14 else "2099-11-12"}
        for m in MAJORS]}
    return env, manifest, lifecycle

class BackfillSecurity(unittest.TestCase):
    def test_exact_trusted_identity(self):
        env, manifest, lifecycle = fixtures()
        self.assertEqual(SHA, gate.check_identity(env, manifest, lifecycle, date(2026,10,10)))

    def test_denial_matrix(self):
        mutations = [
            lambda e,m,l: e.update(GITHUB_REPOSITORY="external/repo"),
            lambda e,m,l: e.update(GITHUB_REF="refs/heads/release/v2.10.13-windows.1"),
            lambda e,m,l: e.update(GITHUB_EVENT_NAME="workflow_dispatch"),
            lambda e,m,l: e.update(GITHUB_SHA="not-sha"),
            lambda e,m,l: m["upstream"].update(commit="b"*40),
            lambda e,m,l: m["upstream"].update(version="2.10.14"),
            lambda e,m,l: m["postgresql"]["majors"].remove(14),
            lambda e,m,l: m["postgresql"]["majors"].append(19),
            lambda e,m,l: l.update(schemaVersion=2),
            lambda e,m,l: l["postgresql"][0].update(eol="2026-10-09"),
        ]
        for mutate in mutations:
            with self.subTest(mutation=str(mutate)):
                f = fixtures()
                mutate(*f)
                with self.assertRaises(gate.Denied):
                    gate.check_identity(*f, current_date=date(2026,10,10))

    def test_lifecycle_denies_day_after_eol(self):
        env, manifest, lifecycle = fixtures()
        with self.assertRaises(gate.Denied):
            gate.check_identity(env, manifest, lifecycle, date(2026,11,13))

    def test_main_mismatch_denied_before_release(self):
        env, manifest, lifecycle = fixtures()
        with patch.object(gate, "api", return_value={"commit":{"sha":"b"*40}}):
            with self.assertRaises(gate.Denied):
                gate.preflight(env, manifest, lifecycle, date(2026,10,10))

    def test_old_release_absent_denied(self):
        env, manifest, lifecycle = fixtures()
        def fake_api(path):
            if path.endswith("/branches/main"): return {"commit":{"sha":SHA}}
            return {"tag_name":"wrong","draft":False,"prerelease":False,"assets":[{}]*13}
        with patch.object(gate, "api", side_effect=fake_api):
            with self.assertRaises(gate.Denied):
                gate.preflight(env, manifest, lifecycle, date(2026,10,10))

    def test_audit_missing_all_assets_denied(self):
        import tempfile
        env, manifest, lifecycle = fixtures()
        env["GITHUB_RUN_ID"]="123"
        with tempfile.TemporaryDirectory() as tmp, patch.object(
             gate, "api", return_value={"commit":{"sha":SHA}}):
            with self.assertRaises(gate.Denied):
                gate.audit(env, manifest, lifecycle, date(2026,10,10), Path(tmp))

if __name__ == "__main__":
    unittest.main()
