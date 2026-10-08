#!/usr/bin/env bash
# Fail closed when a release or tag exists, including before a workflow rerun.
set -euo pipefail

expected_ref="refs/heads/release/v2.10.13-windows.1"
if [[ "${GITHUB_REF:-}" != "$expected_ref" ]]; then
  echo "::error::Unexpected release branch; only $expected_ref is permitted by this Step 17 gate."
  exit 1
fi
if [[ "${GITHUB_REPOSITORY:-}" != "pgextwin/plpgsql_check" ]]; then
  echo "::error::Unexpected caller repository."
  exit 1
fi
if [[ -z "${GH_TOKEN:-}" ]]; then
  echo "::error::GitHub token not available for the release gate."
  exit 1
fi

tag="v2.10.13-windows.1"
for path in "releases/tags/$tag" "git/ref/tags/$tag"; do
  response_path="$(mktemp)"
  status="$(curl --silent --show-error --location --retry 2 \
    --header "Accept: application/vnd.github+json" \
    --header "Authorization: Bearer $GH_TOKEN" \
    --header "X-GitHub-Api-Version: 2022-11-28" \
    --output "$response_path" \
    --write-out "%{http_code}" \
    "https://api.github.com/repos/$GITHUB_REPOSITORY/$path")" || {
      rm -f "$response_path"
      echo "::error::GitHub API failed while checking $path."
      exit 1
    }
  rm -f "$response_path"
  case "$status" in
    404) echo "Confirmed absent: $path" ;;
    200) echo "::error::Existing release or tag found at $path; refuse to overwrite."; exit 1 ;;
    *) echo "::error::Unexpected GitHub API HTTP $status for $path; publication blocked."; exit 1 ;;
  esac
done
echo "Release and tag are both unused; publication may proceed after attested matrix."
