#!/usr/bin/env python3
"""Fail-closed PG14 compatibility-backfill gate, independent of upstream-update promotion.

One-time, unchanged-upstream compatibility backfill only. Never fabricates a watch
candidate, approves an unreviewed source change, or changes an existing Release.
"""
import argparse
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from zipfile import ZipFile

REPO = "pgextwin/plpgsql_check"
TAG = "v2.10.13-windows.2"
BRANCH = "release/" + TAG
UPSTREAM = "61776b0af7418d3fd593cccea73178e3d93c9ee1"
MAJORS = (14, 15, 16, 17, 18)
SIGNER = "pgextwin/build/.github/workflows/build-extension-attested.yml"

class Denied(ValueError):
    pass

def demand(value, why):
    if not value:
        raise Denied(why)

def command(*args):
    p = subprocess.run(args, text=True, capture_output=True, check=False)
    demand(p.returncode == 0, "Command failed closed: " + " ".join(args[:3]) + ": " + p.stderr[:260])
    return p.stdout

def api(path):
    return json.loads(command("gh", "api", path))

def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def check_identity(env, manifest, lifecycle, current_date):
    demand(env.get("GITHUB_REPOSITORY") == REPO and
           env.get("GITHUB_REF") == "refs/heads/" + BRANCH and
           env.get("GITHUB_EVENT_NAME") == "push", "not the one-time trusted release branch")
    commit = env.get("GITHUB_SHA", "")
    demand(re.fullmatch("[0-9a-f]{40}", commit) is not None, "invalid pinned packaging commit")
    demand(manifest.get("name") == "plpgsql_check" and
           manifest.get("upstream") == {"repository": "okbob/plpgsql_check",
             "ref": "v2.10.13", "version": "2.10.13", "commit": UPSTREAM},
           "source identity changed since already audited Windows release")
    demand(manifest.get("postgresql", {}).get("majors") == list(MAJORS),
           "unexpected PostgreSQL major set")
    entries = {int(x["major"]): x for x in lifecycle["postgresql"]}
    demand(lifecycle.get("schemaVersion") == 1 and
           all(m in entries and date.fromisoformat(entries[m]["eol"]) >= current_date for m in MAJORS),
           "PG14 is EOL or PostgreSQL lifecycle metadata is unavailable")
    return commit

def preflight(env, manifest, lifecycle, current_date):
    sha = check_identity(env, manifest, lifecycle, current_date)
    main = api("repos/" + REPO + "/branches/main")
    demand(main["commit"]["sha"] == sha, "release branch differs from current reviewed main")
    old = api("repos/" + REPO + "/releases/tags/v2.10.13-windows.1")
    demand(old["tag_name"] == "v2.10.13-windows.1" and not old["draft"] and
           not old["prerelease"] and len(old["assets"]) == 13,
           "original validated PG15–18 Release is absent or changed")
    existing = subprocess.run(["gh", "api", "repos/" + REPO + "/git/ref/tags/" + TAG],
                              text=True, capture_output=True, check=False)
    demand(existing.returncode != 0 and "404" in existing.stderr, "new tag already exists or GitHub API failed")
    existing = subprocess.run(["gh", "api", "repos/" + REPO + "/releases/tags/" + TAG],
                              text=True, capture_output=True, check=False)
    demand(existing.returncode != 0 and "404" in existing.stderr, "new Release already exists or GitHub API failed")
    response = api("repos/" + REPO + "/actions/runs?head_sha=" + sha + "&per_page=40")
    passed = [r for r in response["workflow_runs"]
              if r["name"] == "Windows CI/CD" and r["event"] == "push" and
              r["head_branch"] == "main" and r["head_sha"] == sha and
              r["status"] == "completed" and r["conclusion"] == "success"]
    demand(bool(passed), "independently validated PG14–18 Windows main CI is missing")
    runs = api("repos/" + REPO + "/actions/runs/" + str(passed[0]["id"]) + "/jobs?per_page=100")
    verified = {int(m.group(1)) for j in runs["jobs"]
                if j["status"] == "completed" and j["conclusion"] == "success"
                if (m := re.search(r"PostgreSQL (1[4-8]) / Windows x64", j["name"]))}
    demand(verified == set(MAJORS), "independent Windows main CI missing PG-major success")
    return {"baselineRun": passed[0]["id"], "trustedMain": sha, "maintainedMajors": MAJORS}

def audit(env, manifest, lifecycle, current_date, folder):
    sha = check_identity(env, manifest, lifecycle, current_date)
    demand(api("repos/" + REPO + "/branches/main")["commit"]["sha"] == sha,
           "main changed during backfill; new review required")
    demand(not (folder / "SHA256SUMS.txt").exists(), "premature checksum file in attested artifacts")
    required = set()
    for m in MAJORS:
        stem = "plpgsql_check-v2.10.13-pg" + str(m) + "-windows-x64"
        names = [stem + ext for ext in (".zip", ".spdx.json", ".vulnerabilities.json")]
        required.update(names)
        z, sbom, grype = [folder / n for n in names]
        demand(all(x.is_file() for x in (z, sbom, grype)), "missing PG" + str(m) + " artifact")
        with ZipFile(z) as archive:
            demand(archive.namelist().count("PACKAGE-INFO.json") == 1,
                   "missing or duplicate ZIP machine metadata")
            pkg = json.loads(archive.read("PACKAGE-INFO.json").decode("utf-8-sig"))
        demand(pkg.get("buildMode") == "release-attested" and
               pkg["package"]["name"] == "plpgsql_check" and
               pkg["postgresql"]["major"] == m and
               pkg["upstream"]["commit"] == UPSTREAM and
               pkg["source"]["packagingRepository"] == REPO and
               pkg["source"]["packagingCommit"] == sha and
               pkg["workflowRun"]["id"] == int(env["GITHUB_RUN_ID"]) and
               pkg["workflowRun"]["event"] == "push" and
               pkg["workflowRun"]["ref"] == "refs/heads/" + BRANCH,
               "untrusted per-major ZIP source/workflow identity")
        demand(json.loads(sbom.read_text(encoding="utf-8-sig"))["spdxVersion"] == "SPDX-2.3",
               "invalid SPDX SBOM")
        demand(isinstance(json.loads(grype.read_text(encoding="utf-8-sig"))["matches"], list),
               "invalid Grype output")
        demand(re.fullmatch("[0-9a-f]{64}", sha256(z)) is not None, "invalid SHA-256")
        command("gh", "attestation", "verify", str(z), "--repo", REPO,
                "--signer-workflow", SIGNER)
        command("gh", "attestation", "verify", str(z), "--repo", REPO,
                "--signer-workflow", SIGNER,
                "--predicate-type", "https://spdx.dev/Document/v2.3")
    demand({x.name for x in folder.iterdir() if x.is_file()} == required,
           "extra or incomplete Release artifacts")
    return {"verifiedMajorCount": len(MAJORS), "assetCount": len(required),
            "provenanceAndSbomAttestations": "VERIFIED"}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--audit", type=Path)
    p.add_argument("--manifest", type=Path, default=Path("config/extension.json"))
    p.add_argument("--lifecycle", type=Path,
                   default=Path(".pgextwin-build/metadata/postgresql.json"))
    args = p.parse_args()
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        lifecycle = json.loads(args.lifecycle.read_text(encoding="utf-8"))
        result = (audit(os.environ, manifest, lifecycle, date.today(), args.audit)
                  if args.audit else preflight(os.environ, manifest, lifecycle, date.today()))
        print(json.dumps({"status": "VERIFIED", **result}))
    except (Denied, OSError, KeyError, ValueError, TypeError, IndexError, json.JSONDecodeError) as ex:
        p.exit(2, "PG14 BACKFILL DENIED (fail-closed): " + str(ex) + "\n")

if __name__ == "__main__":
    main()
