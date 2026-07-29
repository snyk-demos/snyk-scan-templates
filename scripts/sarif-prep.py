#!/usr/bin/env python3
"""Prepare a Snyk SARIF file for github/codeql-action/upload-sarif.

Code scanning rejects a file with two runs in the same category, and
`snyk test --all-projects` emits one run per manifest with no
automationDetails. This gives each run a distinct automationDetails.id
(category + project). The CodeQL Action only fills automationDetails when
absent, so the id set here wins over its `category:` input; ids carry the same
trailing slash the Action uses, so prepared and unprepared files land in the
same category.
  https://github.blog/changelog/2025-07-21-code-scanning-will-stop-combining-multiple-sarif-runs-uploaded-in-the-same-sarif-file/

Also enforces the upload limits up front so the failure is legible:
20 runs/file, 25000 results/run, 10 MB gzipped.
  https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/troubleshoot-sarif-uploads/results-exceed-limit

Env: SARIF_FILE (may be absent: Snyk Code writes none when clean),
     SARIF_CATEGORY (the comment-marker input).
Writes ok=true|false to $GITHUB_OUTPUT; exits non-zero on a limit breach so
the check fails closed rather than skipping the upload.
"""
import gzip
import json
import os
import re
import sys

MAX_RUNS = 20
MAX_RESULTS_PER_RUN = 25_000
MAX_GZIP_BYTES = 10 * 1024 * 1024


def out(key, value):
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"{key}={value}\n")


def slug(text, fallback):
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", str(text or "")).strip("-")
    return s[:80] or fallback


def run_label(run, index):
    """A stable, human-legible discriminator for one run."""
    props = run.get("properties") or {}
    for key in ("projectName", "projectPath", "targetFile", "displayTargetFile"):
        if props.get(key):
            return slug(props[key], f"run{index}")
    # Snyk Open Source SARIF names the manifest on the tool driver.
    driver = ((run.get("tool") or {}).get("driver") or {})
    for key in ("projectName", "semanticVersion"):
        if driver.get(key):
            return slug(driver[key], f"run{index}")
    arts = run.get("artifacts") or []
    if arts:
        uri = ((arts[0] or {}).get("location") or {}).get("uri")
        if uri:
            return slug(uri, f"run{index}")
    return f"run{index}"


def main():
    path = os.environ.get("SARIF_FILE", "")
    category = os.environ.get("SARIF_CATEGORY", "snyk").rstrip("/")

    if not path or not os.path.exists(path) or os.path.getsize(path) == 0:
        # Snyk Code writes no file when clean. Not an error, but nothing
        # supersedes previously uploaded alerts, so they stay open.
        print("::notice::No SARIF produced; nothing to upload.")
        out("ok", "false")
        return 0

    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"::error::SARIF at {path} is not readable JSON: {exc}")
        out("ok", "false")
        return 1

    runs = doc.get("runs")
    if not isinstance(runs, list) or not runs:
        print("::notice::SARIF contains no runs; nothing to upload.")
        out("ok", "false")
        return 0

    if len(runs) > MAX_RUNS:
        print(
            f"::error::SARIF contains {len(runs)} runs; code scanning accepts "
            f"at most {MAX_RUNS} per file. Split the scan (drop --all-projects "
            f"for a matrix of working-directory jobs, or narrow it with "
            f"--detection-depth / --exclude) so each upload stays under the "
            f"limit. Failing rather than skipping the upload, because a "
            f"skipped upload would leave this check green with no results."
        )
        out("ok", "false")
        return 1

    single = len(runs) == 1
    seen = set()
    for i, run in enumerate(runs):
        ident = f"{category}/" if single else f"{category}/{run_label(run, i)}/"
        while ident in seen:
            ident = f"{category}/{run_label(run, i)}-{i}/"
        seen.add(ident)
        run.setdefault("automationDetails", {})["id"] = ident

        results = run.get("results")
        if isinstance(results, list) and len(results) > MAX_RESULTS_PER_RUN:
            print(
                f"::error::Run {i} has {len(results)} results; the hard limit "
                f"is {MAX_RESULTS_PER_RUN}. Raise severity-threshold or narrow "
                f"the scanned path."
            )
            out("ok", "false")
            return 1

    payload = json.dumps(doc, separators=(",", ":")).encode("utf-8")
    zipped = len(gzip.compress(payload))
    if zipped > MAX_GZIP_BYTES:
        print(
            f"::error::SARIF is {zipped} bytes gzipped, over the 10 MB upload "
            f"limit. Raise severity-threshold or narrow the scanned path."
        )
        out("ok", "false")
        return 1

    with open(path, "wb") as fh:
        fh.write(payload)

    total = sum(len(r.get("results") or []) for r in runs)
    print(
        f"SARIF ready: {len(runs)} run(s), {total} result(s), "
        f"{zipped} bytes gzipped. Categories: {', '.join(sorted(seen))}"
    )
    out("ok", "true")
    return 0


if __name__ == "__main__":
    sys.exit(main())
