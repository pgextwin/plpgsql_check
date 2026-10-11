#!/usr/bin/env python3
"""Offline regression tests for release-absence gate; never calls real GitHub."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-release-absence.sh"

def invoke(repo, ref, http_status):
    with tempfile.TemporaryDirectory() as temp:
        fake = Path(temp) / "curl"
        fake.write_text(
            "#!/usr/bin/env bash\n"
            "set -e\n"
            "out=''\n"
            "while [ $# -gt 0 ]; do\n"
            "  if [ \"$1\" = '--output' ]; then shift; out=\"$1\"; fi\n"
            "  shift\n"
            "done\n"
            ": > \"$out\"\n"
            "printf '%s' \"$FAKE_HTTP_STATUS\"\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        env = dict(os.environ)
        env.update({
            "PATH": temp + os.pathsep + os.environ["PATH"],
            "GH_TOKEN": "fixture-only-token",
            "GITHUB_REPOSITORY": repo,
            "GITHUB_REF": ref,
            "FAKE_HTTP_STATUS": str(http_status),
        })
        return subprocess.run(["bash", str(SCRIPT)], cwd=ROOT, env=env, capture_output=True, text=True)

def main():
    configured = json.loads((ROOT / "config" / "extension.json").read_text(encoding="utf-8"))["upstream"]["version"]
    valid = f"refs/heads/release/v{configured}-windows.2"
    other = "0.0.1" if configured == "0.0.0" else "0.0.0"
    mismatched = f"refs/heads/release/v{other}-windows.2"
    assert invoke("nottrusted/ext", valid, 404).returncode != 0
    assert invoke("pgextwin/plpgsql_check", "refs/heads/feature/new", 404).returncode != 0
    assert invoke("pgextwin/plpgsql_check", mismatched, 404).returncode != 0
    assert invoke("pgextwin/plpgsql_check", valid, 200).returncode != 0
    assert invoke("pgextwin/plpgsql_check", valid, 503).returncode != 0
    assert invoke("pgextwin/plpgsql_check", valid, 404).returncode == 0
    assert invoke("pgextwin/plpgsql_check", valid.replace("-windows.2", "-windows.0"), 404).returncode != 0
    print("Step 19 release gate fixture tests passed")

if __name__ == "__main__":
    main()
