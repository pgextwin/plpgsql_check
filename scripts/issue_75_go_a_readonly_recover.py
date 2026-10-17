#!/usr/bin/env python3
"""#75: cryptographically recheck the ONE original failed canary, without dispatch.

Only authenticated GitHub GET and GitHub CLI attestation VERIFY operations are
allowed.  A SUCCESS receipt for the failed workflow is deliberately impossible.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from zipfile import ZipFile
import argparse

import issue_75_go_a_canary_verify as policy

RUN = 39008743613
ATTEMPT = 1
SHA = "89bf4f9b72bb4509bbf7d5591d39084776f97979"
WORKFLOW_BLOB = "f194a9a31de1aa611b0fe9ca49db49735aa201be"
ORIGINAL_VERIFIER_BLOB = "96c73f8efef5a0200ed4b21e6800f598b4595a8b"
FAILED_VERIFY_JOB = 117328976367

# Fixed from the GitHub Run-bound artifact API and original independent-byte
# audit. Outer digests are not hashes of the *inner* Windows package ZIPs.
ARTIFACTS = {
    14: (12091919152, 184705, "9f09ece9cabac0073b3de96cf5c85fb262a22bfa2ddb53517f12d1502b2111b7",
         "7e420df9c19faf54b7ab7a68d2cd9e95b680cd8a063fc33ebfe97cddb48442ac"),
    15: (12092530751, 184773, "f974d3a31bed391a77c32c952913418f363b48aa3a561c3778cd6430e1ba91fc",
         "1858146873f537e75ce459159f550784a9ac4b66a5172852ae817f2b78762e46"),
    16: (12092097237, 185370, "de612151515ed706437fb402df73f94716a1670dff04367c648ac4e2d972989a",
         "547e508d20a3c376d063a4d1ccebdb021e13749c38058fe7255639e891be7c70"),
    17: (12092545144, 185346, "98ba50fa64d75796066ab25c25599f7b38e157dd35d5ebc6ddda8e9d76c89907",
         "9fbb4fb65caa13ab9bcbcffc60fb95b25d896d9ceb1dd9fed48faecf5d321c6b"),
    18: (12092361962, 185387, "3788f139b1fe0f25a6ff5ad46c45d1442421a09e1c40ab7cd5cb7da2de876e2d",
         "93fe2b7d5cacdfad837c414d04cb7a57a02bb939a07a76ed42dd44e8e9aad68f"),
}


def read_only_context():
    # The current main may advance after the original dispatch; never silently
    # substitute its SHA for the signed historical run.
    main = policy.api("branches/main")
    checks = main.get("protection", {}).get("required_status_checks", {})
    policy.need(main.get("protected") is True and
                checks.get("enforcement_level") == "everyone" and
                {v.get("context") for v in checks.get("checks") or []} == policy.REQUIRED and
                all(v.get("app_id") == 15368 for v in checks.get("checks") or []),
                "current branch protection required checks mismatch")
    original = policy.api(f"commits/{SHA}/check-runs?per_page=100")
    checkruns = original.get("check_runs", [])
    policy.need(original.get("total_count") == len(checkruns) and len(checkruns) < 100,
                "original required check runs incomplete")
    for required in policy.REQUIRED:
        items = [c for c in checkruns if c.get("name") == required]
        policy.need(len(items) == 1 and items[0].get("status") == "completed" and
                    items[0].get("conclusion") == "success" and
                    items[0].get("app", {}).get("id") == 15368,
                    "original main required App15368 check not successful: " + required)

    rec = policy.api(f"actions/runs/{RUN}")
    policy.need(rec.get("id") == RUN and rec.get("run_attempt") == ATTEMPT and
                rec.get("head_sha") == SHA and rec.get("head_branch") == "main" and
                rec.get("path") == policy.WORKFLOW and
                rec.get("event") == "workflow_dispatch" and
                rec.get("repository", {}).get("id") == policy.REPO_ID and
                rec.get("actor", {}).get("login") == "ShutenOishi" and
                rec.get("triggering_actor", {}).get("login") == "ShutenOishi" and
                rec.get("status") == "completed" and rec.get("conclusion") == "failure",
                "original run identity or FAILURE status changed")
    runs = policy.api("actions/workflows/issue-75-pre-g4-signed-canary.yml/runs"
                      "?event=workflow_dispatch&per_page=100")
    hits = runs.get("workflow_runs") or []
    policy.need(runs.get("total_count") == 1 and len(hits) == 1 and
                hits[0].get("id") == RUN and hits[0].get("run_attempt") == ATTEMPT,
                "second canary run/replay was detected")
    for path, sha in ((".github/workflows/issue-75-pre-g4-signed-canary.yml", WORKFLOW_BLOB),
                      ("scripts/issue_75_go_a_canary_verify.py", ORIGINAL_VERIFIER_BLOB)):
        source = policy.api(f"contents/{path}?ref={SHA}")
        policy.need(source.get("type") == "file" and source.get("sha") == sha,
                    "original Run source blob changed: " + path)

    jobs = policy.api(f"actions/runs/{RUN}/jobs?per_page=100")
    entries = jobs.get("jobs") or []
    policy.need(jobs.get("total_count") == len(entries) and len(entries) < 100,
                "original run job list incomplete")
    failures = [j for j in entries if j.get("conclusion") == "failure"]
    policy.need(len(failures) == 1 and failures[0].get("id") == FAILED_VERIFY_JOB and
                "Independent read-only real X.509" in failures[0].get("name", "") and
                all(j.get("conclusion") == "success" for j in entries
                    if j.get("id") != FAILED_VERIFY_JOB),
                "unexpected original Run job failure or changed evidence")


def immutable_artifact_inventory():
    response = policy.api(f"actions/runs/{RUN}/artifacts?per_page=100")
    rows = response.get("artifacts") or []
    policy.need(response.get("total_count") == 5 and len(rows) == 5,
                "Run-bound artifact count changed")
    for major, (artifact_id, length, outer_sha, _) in ARTIFACTS.items():
        name = f"plpgsql_check-pg{major}-windows-x64"
        matches = [a for a in rows if a.get("name") == name]
        policy.need(len(matches) == 1 and matches[0].get("id") == artifact_id and
                    matches[0].get("size_in_bytes") == length and
                    matches[0].get("digest") == "sha256:" + outer_sha and
                    matches[0].get("expired") is False,
                    "original artifact ID/digest/size/retention drift: " + name)


def trusted_builder(root: Path):
    # Do not execute potentially edited local scripts as trusted build validators.
    for args, expected in ((["rev-parse", "HEAD"], policy.PIN),
                           (["status", "--porcelain", "--untracked-files=no"], "")):
        p = subprocess.run(["git", "-C", str(root), *args],
                           capture_output=True, text=True, check=False, timeout=30)
        policy.need(p.returncode == 0 and p.stdout.strip() == expected,
                    "trusted build checkout is not exact and clean signer pin")


def fetch_original_artifact(artifact_id: int, output: Path, digest: str, length: int):
    # A GET-only download; no Actions run/dispatch or signatures are created.
    p = subprocess.run(["gh", "api", "--method", "GET",
                        f"repos/{policy.REPO}/actions/artifacts/{artifact_id}/zip"],
                       capture_output=True, timeout=180, check=False)
    policy.need(p.returncode == 0 and len(p.stdout) == length and
                hashlib.sha256(p.stdout).hexdigest() == digest,
                "original artifact archive download/digest mismatch")
    output.write_bytes(p.stdout)


def unpack_frozen(folder: Path):
    output = folder / "dist"
    output.mkdir()
    for major, (artifact_id, length, outer_sha, inner_sha) in ARTIFACTS.items():
        archive = folder / f"original-pg{major}-artifact.zip"
        fetch_original_artifact(artifact_id, archive, outer_sha, length)
        stem = f"plpgsql_check-v2.10.14-pg{major}-windows-x64"
        expected = {stem + ext for ext in (".zip", ".spdx.json",
                                            ".vulnerabilities.json")}
        with ZipFile(archive) as z:
            listing = z.infolist()
            policy.need(len(listing) == 3 and {i.filename for i in listing} == expected and
                        sum(i.file_size for i in listing) < 30 * 1024 * 1024 and
                        all(0 < i.file_size < 16 * 1024 * 1024 and
                            not i.is_dir() and (i.external_attr >> 16) & 0o170000 != 0o120000
                            for i in listing), "malformed/unsafe frozen artifact archive")
            for info in listing:
                # Strict exact basename allowlist prevents traversal and symlink extraction.
                (output / info.filename).write_bytes(z.read(info))
        policy.need(policy.digest(output / (stem + ".zip")) == inner_sha,
                    "original inner ZIP SHA256 mismatch")
    return output


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--trusted-build", type=Path, required=True,
                   help="clean local checkout of build at immutable signer PIN")
    a = p.parse_args()
    try:
        trusted_builder(a.trusted_build)
        policy.source_and_lifecycle(a.trusted_build / "metadata/postgresql.json")
        read_only_context()
        immutable_artifact_inventory()
        with tempfile.TemporaryDirectory(prefix="pgextwin-go-a-original-") as work:
            dist = unpack_frozen(Path(work))
            proof = policy.artifacts(dist, a.trusted_build, SHA, RUN, ATTEMPT,
                                     policy.parse(Path("config/extension.json").read_text(encoding="utf-8")))
        # Fresh authenticated GET after all real cryptographic verification.
        read_only_context()
        immutable_artifact_inventory()
        policy.need(proof["certificatesVerified"] == 10, "not all ten cryptographic attestations verified")
        print(json.dumps({
            "status": "PASS_READONLY_EXISTING_10_ATTESTATIONS_ONLY",
            "originalRun": RUN, "originalRunAttempt": ATTEMPT,
            "originalRunConclusion": "failure", "canaryWorkflowSuccess": False,
            "originalPackagingSha": SHA, "signerSha": policy.PIN,
            "newWorkflowDispatches": 0, "newSignaturesGenerated": 0,
            "formalP1RowsAdded": 0, "publishableReceipt": False,
            "mutationsEnabled": False, "publication": "DENY", **proof
        }, sort_keys=True))
    except (policy.Deny, ValueError, TypeError, OSError, KeyError,
            subprocess.TimeoutExpired) as exc:
        print("DENY_READONLY_ORIGINAL_GO_A: " + str(exc), file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
