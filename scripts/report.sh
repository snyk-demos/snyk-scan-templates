#!/usr/bin/env bash
# Write the scan report to the run summary and, optionally, one sticky PR
# comment that is edited in place on later pushes.
#
# Env: TITLE FILE EXIT_CODE MARKER PR_COMMENT GH_TOKEN GH_REPO
#      ERROR_MESSAGE ERROR_HINT (from classify.py)
set -euo pipefail

: "${TITLE:=Snyk}"
: "${FILE:=}"
: "${EXIT_CODE:=}"
: "${MARKER:=snyk}"
: "${PR_COMMENT:=false}"
: "${GH_REPO:=${GITHUB_REPOSITORY:-}}"
: "${ERROR_MESSAGE:=}"
: "${ERROR_HINT:=}"

# GITHUB_SHA on a pull_request event is the synthetic merge commit, so blob
# links built from it 404. Use the PR head instead.
RENDER_REF=""
if [ "${GITHUB_EVENT_NAME:-}" = "pull_request" ] && [ -s "${GITHUB_EVENT_PATH:-}" ]; then
  RENDER_REF=$(jq -r '.pull_request.head.sha // empty' "$GITHUB_EVENT_PATH")
fi
RENDER_REF="${RENDER_REF:-${GITHUB_SHA:-}}"

rm -f report.md
RENDER_TITLE="$TITLE" RENDER_FILE="$FILE" RENDER_JSON="${FILE%.sarif}.json" \
  RENDER_EXIT="$EXIT_CODE" RENDER_OUT=report.md RENDER_REF="$RENDER_REF" \
  python3 "$(dirname "$0")/render.py"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -f report.md ]; then
  cat report.md >> "$GITHUB_STEP_SUMMARY"
fi

[ "$PR_COMMENT" = "true" ] || exit 0
[ -f report.md ] || exit 0

# On pull_request events the ref name is "N/merge", useless for a head lookup,
# so read the PR number from the event payload instead.
pr=""
if [ "${GITHUB_EVENT_NAME:-}" = "pull_request" ] && [ -s "${GITHUB_EVENT_PATH:-}" ]; then
  pr=$(jq -r '.pull_request.number // empty' "$GITHUB_EVENT_PATH")
elif [ -n "${GITHUB_REF_NAME:-}" ]; then
  pr=$(gh pr list --head "$GITHUB_REF_NAME" --state open --json number \
         --jq '.[0].number // empty' 2>/dev/null || true)
fi
if [ -z "$pr" ]; then
  echo "::notice::No open PR for this ref. Run summary only."
  exit 0
fi

MARK="<!-- ${MARKER} -->"

# GitHub caps a comment body at 65536 chars. Decode leniently so a truncated
# multi-byte character cannot produce invalid UTF-8.
BUDGET=$(( 65536 - ${#MARK} - 200 ))
{
  echo "$MARK"
  BUDGET="$BUDGET" python3 - <<'PY'
import os
limit = int(os.environ["BUDGET"])
raw = open("report.md", "rb").read()
text = raw.decode("utf-8", "ignore")
if len(text) > limit:
    text = text[:limit] + "\n\n_Report truncated; see the run summary for the full output._\n"
print(text, end="")
PY
} > comment.md

# --paginate so the comment is still found on a PR with over 100 comments.
# Do not pipe to `head -n1`: the early close SIGPIPEs gh, which under pipefail
# and set -e kills the step. The marker goes through jq --arg so a quote in
# comment-marker cannot corrupt the filter.
id=$(gh api --paginate --jq '.[]' "repos/${GH_REPO}/issues/${pr}/comments" 2>/dev/null \
       | jq -s -r --arg m "$MARK" \
           'map(select((.body // "") | startswith($m))) | .[0].id // empty' \
     || true)

if [ -n "$id" ]; then
  gh api -X PATCH "repos/${GH_REPO}/issues/comments/${id}" -F body=@comment.md > /dev/null
else
  gh api "repos/${GH_REPO}/issues/${pr}/comments" -F body=@comment.md > /dev/null
fi
