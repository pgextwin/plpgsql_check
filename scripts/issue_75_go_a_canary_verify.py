#!/usr/bin/env python3
"""GO A one-shot, nonpublishing, genuinely signed artifacts; fail closed."""
from __future__ import annotations

import argparse
import base64
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from zipfile import ZipFile, BadZipFile
from zoneinfo import ZoneInfo

REPO = "pgextwin/plpgsql_check"
REPO_ID = 1410581312
WORKFLOW = ".github/workflows/issue-75-pre-g4-signed-canary.yml"
SIGNER = "pgextwin/build/.github/workflows/build-extension-attested.yml"
PIN = "5756b3c5136a8bf4db710016cfe97555f0a71c6d"
# One-shot GO A must fail closed if protected central policy advances again.
CENTRAL_MAIN_PIN = "dfa87e91aa0a65ceaec04cdfc67a3053f87baf75"
ISSUER = "https://token.actions.githubusercontent.com"
SLSA, SPDX = "https://slsa.dev/provenance/v1", "https://spdx.dev/Document/v2.3"
MAJORS = (14, 15, 16, 17, 18)
REQUIRED = {"syntax", "windows / Resolve extension and PostgreSQL matrix",
            "Regression-test immutable Release preflight", "Windows required summary"} | {
                f"windows / PostgreSQL {m} / Windows x64" for m in (15, 16, 17, 18)}


class Deny(ValueError):
    pass


def need(ok, why):
    if not ok:
        raise Deny(why)


def unique(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value, "duplicate JSON key")
        value[key] = item
    return value


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique)


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(part)
    return h.hexdigest()


def gh(*args):
    # No shell, no write verbs; the only allowed commands are authenticated GET
    # and GitHub CLI's real cryptographic attestation verifier.
    allowed = ((len(args) == 4 and args[:3] == ("api", "--method", "GET") and
                args[3].startswith(f"repos/{REPO}/")) or
               (len(args) == 4 and args[:3] == ("api", "--method", "GET") and
                args[3] in ("repos/pgextwin/build/branches/main",
                "repos/pgextwin/build/contents/metadata/release-promotion.json?ref=main",
                "repos/pgextwin/build/contents/metadata/automation-fleet.json?ref=main")) or
               (len(args) > 4 and args[:2] == ("attestation", "verify")))
    need(allowed, "GitHub operation outside read-only allowlist")
    try:
        cmd = subprocess.run(("gh",) + args, capture_output=True, text=True,
                             timeout=180, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise Deny("GitHub verification/GET unavailable") from e
    need(cmd.returncode == 0, "authenticated GET or genuine cryptographic verify DENY")
    return cmd.stdout


def api(path):
    return parse(gh("api", "--method", "GET", f"repos/{REPO}/{path}"))


def policy_readonly():
    local = parse(Path("config/release-promotion.json").read_text(encoding="utf-8"))
    need(local.get("releasePolicy") == "manual-dispatch",
         "pilot-local publication policy changed")
    central_head = parse(gh("api", "--method", "GET",
                            "repos/pgextwin/build/branches/main"))
    need(central_head.get("protected") is True and
         central_head.get("commit", {}).get("sha") == CENTRAL_MAIN_PIN,
         "central protected main moved since GO A authorization")
    for name, expected in (("release-promotion.json", "manual-dispatch"),
                           ("automation-fleet.json", "manual-only")):
        path = "repos/pgextwin/build/contents/metadata/" + name + "?ref=main"
        payload = parse(gh("api", "--method", "GET", path))
        need(payload.get("encoding") == "base64", "unverified central policy content")
        data = parse(base64.b64decode(payload["content"]).decode("utf-8"))
        need(data.get("releasePolicy") == expected, "central policy changed")
        if name == "automation-fleet.json":
            entries = data.get("entries")
            need(isinstance(entries, list) and len(entries) == 14 and
                 all(x.get("releasePolicy") == "manual-only" for x in entries),
                 "Fleet 14/14 manual-only has changed")


def source_and_lifecycle(lifecycle):
    policy_readonly()
    manifest = parse(Path("config/extension.json").read_text(encoding="utf-8"))
    want_upstream = {"repository": "okbob/plpgsql_check", "ref": "v2.10.14",
                     "version": "2.10.14",
                     "commit": "ccdbcce9de51f01e1138c270aeb9fe4e26c6e911"}
    need(manifest.get("name") == "plpgsql_check" and
         manifest.get("upstream") == want_upstream and
         manifest.get("windows", {}).get("architecture") == "x64" and
         manifest.get("postgresql", {}).get("majors") == list(MAJORS),
         "pilot upstream, architecture or source matrix changed")
    data = parse(Path(lifecycle).read_text(encoding="utf-8"))
    today = datetime.now(ZoneInfo("Asia/Tokyo")).date()
    supported = sorted(m["major"] for m in data["postgresql"]
                       if datetime.strptime(m["eol"], "%Y-%m-%d").date() >= today)
    need(supported == list(MAJORS), "maintained PG matrix differs from GO A")
    return manifest


def context(sha, run, attempt):
    need(bool(re.fullmatch(r"[a-f0-9]{40}", sha)) and
         os.environ.get("RUN_SHA") == sha, "incorrect immutable main SHA")
    need(run > 0 and attempt == 1, "re-run / malformed invocation rejected")
    main = api("branches/main")
    checks = main.get("protection", {}).get("required_status_checks", {})
    need(main.get("protected") is True and main.get("commit", {}).get("sha") == sha and
         checks.get("enforcement_level") == "everyone" and
         {c.get("context") for c in checks.get("checks") or []} == REQUIRED and
         all(c.get("app_id") == 15368 for c in checks.get("checks") or []),
         "protected main drift or App-bound required checks changed")
    record = api(f"actions/runs/{run}")
    need(record.get("id") == run and record.get("run_attempt") == attempt and
         record.get("event") == "workflow_dispatch" and
         record.get("path") == WORKFLOW and record.get("head_sha") == sha and
         record.get("head_branch") == "main" and
         record.get("repository", {}).get("id") == REPO_ID and
         record.get("actor", {}).get("login") == "ShutenOishi" and
         record.get("triggering_actor", {}).get("login") == "ShutenOishi" and
         record.get("status") == "in_progress" and record.get("conclusion") is None,
         "untrusted actor, ref, workflow or attempt")
    one = api("actions/workflows/issue-75-pre-g4-signed-canary.yml/runs"
              "?event=workflow_dispatch&per_page=100")
    hits = one.get("workflow_runs")
    need(one.get("total_count") == 1 and isinstance(hits, list) and
         len(hits) == 1 and hits[0].get("id") == run,
         "second dispatch / previous run / replay DENY")


def verified_statement(out, kind, name, checksum, sha, run, attempt, sbom):
    need(isinstance(out, list) and len(out) == 1, "missing/ambiguous attestation")
    evidence = out[0]["verificationResult"]
    statement = evidence["statement"]
    need(statement.get("_type") == "https://in-toto.io/Statement/v1" and
         statement.get("predicateType") == kind and
         statement.get("subject") == [{"name": name, "digest": {"sha256": checksum}}],
         "signed statement predicate or ZIP SHA256 mismatch")
    cert = evidence["signature"]["certificate"]
    signer_uri = "https://github.com/" + SIGNER + "@"
    invocation = f"https://github.com/{REPO}/actions/runs/{run}/attempts/{attempt}"
    need(cert.get("issuer") == ISSUER and
         cert.get("sourceRepositoryURI") == f"https://github.com/{REPO}" and
         cert.get("sourceRepositoryRef") == "refs/heads/main" and
         cert.get("sourceRepositoryDigest") == sha and
         str(cert.get("sourceRepositoryIdentifier")) == str(REPO_ID) and
         cert.get("githubWorkflowTrigger") == "workflow_dispatch" and
         cert.get("githubWorkflowSHA") == sha and
         cert.get("runnerEnvironment") == "github-hosted" and
         cert.get("buildSignerDigest") == PIN and
         isinstance(cert.get("buildSignerURI"), str) and
         cert["buildSignerURI"].startswith(signer_uri) and
         cert.get("runInvocationURI") == invocation and
         cert.get("subjectAlternativeName", {}).get("type") == "URI" and
         evidence.get("verifiedTimestamps"), "verified X.509 OIDC/signer/run identity DENY")
    pred = statement.get("predicate") or {}
    if kind == SPDX:
        need(pred == sbom and pred.get("spdxVersion") == "SPDX-2.3",
             "signed SBOM not semantically identical to public SPDX")
    else:
        need(isinstance(pred.get("buildDefinition"), dict) and
             isinstance(pred.get("runDetails"), dict) and
             pred["runDetails"].get("metadata", {}).get("invocationId") == invocation,
             "SLSA v1 provenance runInvocationURI mismatch")


def artifacts(folder, trusted, sha, run, attempt, manifest):
    stems = {m: f"plpgsql_check-v{manifest['upstream']['version']}-pg{m}-windows-x64"
             for m in MAJORS}
    suffixes = (".zip", ".spdx.json", ".vulnerabilities.json")
    expected = {stem + suffix for stem in stems.values() for suffix in suffixes}
    need({p.name for p in folder.iterdir() if p.is_file()} == expected and
         not any(p.is_dir() for p in folder.iterdir()), "missing/extra ZIP SPDX Grype")
    inventory = api(f"actions/runs/{run}/artifacts?per_page=100")
    files = inventory.get("artifacts") or []
    need(inventory.get("total_count") == 5 and len(files) == 5 and
         {a.get("name") for a in files} ==
         {f"plpgsql_check-pg{m}-windows-x64" for m in MAJORS} and
         all(a.get("expired") is False and a.get("size_in_bytes", 0) > 0 for a in files),
         "signed canary artifact set missing/expired")
    storage = sum(a["size_in_bytes"] for a in files)
    need(storage <= 250 * 1024 * 1024, "artifact storage exceeded conservative cap")
    job_response = api(f"actions/runs/{run}/jobs?per_page=100")
    jobs = job_response.get("jobs") or []
    need(len(jobs) < 100 and job_response.get("total_count", len(jobs)) == len(jobs),
         "incomplete job pagination")
    for major in MAJORS:
        pgjobs = [j for j in jobs
                  if f"PostgreSQL {major} / Windows x64" in j.get("name", "")]
        need(len(pgjobs) == 1 and pgjobs[0].get("conclusion") == "success",
             f"PG{major} signer job failed")
    summaries = {}
    count = 0
    for major, stem in stems.items():
        z, s, g = (folder / (stem + ext) for ext in suffixes)
        need(min(p.stat().st_size for p in (z, s, g)) > 0, "empty package asset")
        try:
            with ZipFile(z) as archive:
                package_info = [x for x in archive.infolist()
                                if x.filename == "PACKAGE-INFO.json"]
                need(len(package_info) == 1 and package_info[0].file_size <= 262144,
                     "missing/oversized PACKAGE-INFO")
                pkg = parse(archive.read(package_info[0]).decode("utf-8-sig"))
        except (BadZipFile, UnicodeError, KeyError) as e:
            raise Deny("invalid Windows ZIP metadata") from e
        need(pkg.get("buildMode") == "release-attested" and
             pkg.get("package") == {"name": "plpgsql_check", "platform": "windows",
                                    "architecture": "x64"} and
             pkg.get("postgresql", {}).get("major") == major and
             pkg.get("upstream") == manifest["upstream"] and
             pkg.get("source") == {"packagingRepository": REPO,
                                   "packagingCommit": sha} and
             pkg.get("buildInfrastructure") == {"repository": "pgextwin/build",
                 "commit": PIN, "workflow": ".github/workflows/build-extension-attested.yml"} and
             all(pkg.get("workflowRun", {}).get(k) == val for k, val in
                 {"id": run, "attempt": attempt, "event": "workflow_dispatch",
                  "ref": "refs/heads/main"}.items()),
             "PACKAGE-INFO source/build/run/PG tuple mismatch")
        for script, flags in (
            ("validate-sbom.py", ["--sbom", str(s), "--zip", str(z),
                                  "--expected-extension", "plpgsql_check",
                                  "--expected-version", manifest["upstream"]["version"]]),
            ("validate-vulnerability-report.py",
             ["--report", str(g), "--sbom", str(s), "--zip", str(z),
              "--expected-extension", "plpgsql_check",
              "--postgresql-major", str(major)])):
            checked = subprocess.run([sys.executable, str(trusted / "scripts" / script),
                                      *flags], capture_output=True, text=True, timeout=90)
            need(checked.returncode == 0, "immutable SBOM/Grype validation DENY")
        checksum = digest(z)
        sbom = parse(s.read_text(encoding="utf-8-sig"))
        for predicate in (SLSA, SPDX):
            verified = parse(gh("attestation", "verify", str(z), "--repo", REPO,
                                "--signer-workflow", SIGNER, "--signer-digest", PIN,
                                "--source-digest", sha, "--source-ref", "refs/heads/main",
                                "--cert-oidc-issuer", ISSUER, "--deny-self-hosted-runners",
                                "--predicate-type", predicate, "--format", "json"))
            verified_statement(verified, predicate, z.name, checksum, sha, run, attempt, sbom)
            count += 1
        summaries[str(major)] = {"zipSha256": checksum, "spdxSha256": digest(s),
                                 "grypeSha256": digest(g)}
    need(count == 10, "not 10 fresh genuine X.509 attestations")
    return {"certificatesVerified": count, "artifactsSha256": summaries,
            "artifactStorageBytes": storage}


def main():
    arg = argparse.ArgumentParser()
    arg.add_argument("phase", choices=("preflight", "verify"))
    arg.add_argument("--expected-sha", required=True)
    arg.add_argument("--run-id", type=int, required=True)
    arg.add_argument("--attempt", type=int, required=True)
    arg.add_argument("--lifecycle", required=True)
    arg.add_argument("--dist")
    arg.add_argument("--trusted-build")
    a = arg.parse_args()
    try:
        manifest = source_and_lifecycle(a.lifecycle)
        context(a.expected_sha, a.run_id, a.attempt)
        if a.phase == "verify":
            need(bool(a.dist and a.trusted_build), "missing verifier inputs")
            proof = artifacts(Path(a.dist), Path(a.trusted_build),
                              a.expected_sha, a.run_id, a.attempt, manifest)
            context(a.expected_sha, a.run_id, a.attempt)  # independent JIT second GET
            status = "PASS_GO_A_NONRELEASE_SIGNED_CANARY_ONLY"
        else:
            proof = {"maintainedPG": list(MAJORS)}
            status = "PASS_GO_A_PREFLIGHT_ONLY"
        record = {"status": status, "runId": a.run_id, "runAttempt": a.attempt,
                  "packagingSha": a.expected_sha, "builderSha": PIN,
                  "publishableReceipt": False, "mutationsEnabled": False,
                  "publication": "DENY", **proof}
        output = json.dumps(record, sort_keys=True)
        print(output)
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
                handle.write("### GO A non-Release evidence\n\n```json\n" + output + "\n```\n")
    except (Deny, ValueError, TypeError, OSError, subprocess.TimeoutExpired) as error:
        print("DENY_GO_A: " + str(error), file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
