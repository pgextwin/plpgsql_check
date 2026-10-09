#!/usr/bin/env bash
# Fail closed for new immutable publication, including reruns and competing builds.
set -euo pipefail
if [[ "${GITHUB_REPOSITORY:-}" != "pgextwin/plpgsql_check" ||
      "${GITHUB_REF:-}" != refs/heads/release/* ]]; then
  echo "::error::Only pgextwin/plpgsql_check release/* refs may publish."
  exit 1
fi
tag="${GITHUB_REF#refs/heads/release/}"
if [[ ! "$tag" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)-windows\.([1-9][0-9]*)$ ]]; then
  echo "::error::Invalid release tag naming policy."
  exit 1
fi
version="${BASH_REMATCH[1]}"
configured="$(python -c 'import json; print(json.load(open("config/extension.json",encoding="utf-8"))["upstream"]["version"])')" || exit 1
if [[ "$version" != "$configured" ]]; then
  echo "::error::Release name and configured upstream version disagree."
  exit 1
fi
if [[ -z "${GH_TOKEN:-}" ]]; then
  echo "::error::Token unavailable for mandatory release absence gate."
  exit 1
fi
for path in "releases/tags/$tag" "git/ref/tags/$tag"; do
  tmp="$(mktemp)"
  status="$(curl --silent --show-error --location --retry 2 \
    --header "Accept: application/vnd.github+json" \
    --header "Authorization: Bearer $GH_TOKEN" \
    --header "X-GitHub-Api-Version: 2022-11-28" \
    --output "$tmp" --write-out "%{http_code}" \
    "https://api.github.com/repos/$GITHUB_REPOSITORY/$path")" || {
      rm -f "$tmp"; echo "::error::GitHub API failure; publication blocked."; exit 1;
    }
  rm -f "$tmp"
  case "$status" in
    404) echo "Confirmed absent: $path" ;;
    200) echo "::error::Existing tag or release $path; publication blocked."; exit 1 ;;
    *) echo "::error::Unexpected API HTTP $status; publication blocked."; exit 1 ;;
  esac
done
echo "Preflight passed for $tag; final publication must use create-only semantics."
