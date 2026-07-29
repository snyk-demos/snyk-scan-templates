#!/usr/bin/env bash
# Resolve the value passed to Snyk's --target-reference.
#
# "auto" resolves to the BASE branch, so a PR test and a merge-queue test
# inherit the ignores and policies of the monitored default-branch target.
# github.ref_name is wrong for both: it is "N/merge" on a pull_request and
# "gh-readonly-queue/<base>/pr-N-<sha>" on a merge_group, and neither matches
# anything that was ever monitored.
#
# Any other value passes through unchanged; empty stays empty, which means the
# flag is not sent at all.
#
# Env: TARGET_REFERENCE, BASE_REF (github.base_ref),
#      MG_BASE_REF (github.event.merge_group.base_ref), GITHUB_REF_NAME
set -euo pipefail

value="${TARGET_REFERENCE:-}"

if [ "$value" = "auto" ]; then
  mg="${MG_BASE_REF:-}"
  value="${BASE_REF:-}"                     # pull_request
  [ -n "$value" ] || value="${mg#refs/heads/}"        # merge_group
  [ -n "$value" ] || value="${GITHUB_REF_NAME:-}"     # push, workflow_dispatch
  if [ -z "$value" ]; then
    echo "::error::target-reference: auto could not resolve a branch for event '${GITHUB_EVENT_NAME:-unknown}'. Set target-reference explicitly."
    exit 1
  fi
  echo "target-reference resolved to '${value}' for ${GITHUB_EVENT_NAME:-unknown}."
fi

echo "value=${value}" >> "$GITHUB_OUTPUT"
