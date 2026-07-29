#!/usr/bin/env python3
"""Turn a Snyk CLI log plus exit code into an actionable diagnosis.

Env in: CLASSIFY_LOG (CLI stdout+stderr), CLASSIFY_EXIT, CLASSIFY_SCAN (label).
Out to $GITHUB_OUTPUT: reason (a PATTERNS name, or clean | findings |
nothing-to-scan | quota | unknown), message, hint, quota.
"""
import os
import re
import uuid

# Most specific and most actionable causes first.
PATTERNS = [
    ("misconfig",
     [r"^bash: line \d+: .*command not found",
      r"\bsnyk: (command )?not found\b",
      r"No such file or directory.*[/ ]snyk\b"],
     "The scan step itself is broken, not the scan.",
     "The shell failed before or instead of running Snyk (typically a broken "
     "line continuation or a missing binary). Fix the step script; the target "
     "was never actually scanned, so treat any 'clean' result as void."),

    ("bad-flag",
     [r"Unsupported (option|flag)", r"Unknown (option|argument|flag)",
      r"not a recognised option", r"Invalid value for", r"Unknown command"],
     "The Snyk CLI rejected an option.",
     "Usually an extra-args flag that this subcommand does not accept. "
     "Options valid for `snyk test` are not automatically valid for "
     "`snyk code test`, `snyk iac test` or `snyk container test`. Check the "
     "per-command option list in the Snyk CLI docs."),

    # Must precede "parse": SNYK-CLI-0012 covers both a real parse failure
    # and "no valid IaC files".
    ("unsupported",
     [r"SNYK-CODE-0006", r"Project not supported",
      r"unable to find supported files",
      r"Could not find any valid IaC files",
      r"Could not detect supported target files"],
     "Snyk found no supported files at the scanned path.",
     "Check working-directory points at real source code and that the "
     "language is supported by this scan type. A wrong or literal path "
     "argument (e.g. a stray backslash) also produces this."),

    ("auth",
     [r"SNYK-0005", r"Authentication error", r"401 Unauthorized",
      r"Not authorised", r"authentication credentials not recognized",
      r"snyk auth", r"Missing (API|auth) token"],
     "Snyk rejected the credentials (401).",
     "Check the SNYK_TOKEN secret exists, is not expired, and belongs to an "
     "account with access to this org. Re-create it as a service account token."),

    ("forbidden",
     [r"403 Forbidden", r"SNYK-0003", r"lacks? permission",
      r"not authorized to (access|perform)", r"\bForbidden\b"],
     "Snyk returned 403 Forbidden.",
     "The token authenticated but lacks permission for this org or product, "
     "or the org has hit a plan limit. On a Code scan with monitor enabled "
     "this is usually the token's role missing 'View Project Ignores', which "
     "Snyk requires for `snyk code test --report`. On a scan that sets "
     "project attributes (--project-tags on monitor, container monitor or "
     "iac test) it is the role missing permission to edit project attributes."),

    ("rate-limit",
     [r"\b429\b", r"Too Many Requests", r"rate limit(ed| exceeded)?"],
     "Snyk throttled the request (429).",
     "Too many concurrent scans against one org. Reduce matrix parallelism or "
     "add a concurrency group, then re-run."),

    ("parse",
     [r"SNYK-CLI-0012", r"Failed to parse (JSON|YAML) file",
      r"invalid JSON", r"failed to load and parse"],
     "The scan hit files it could not parse.",
     "Almost always non-IaC JSON/YAML swept in from vendored directories "
     "such as node_modules. Run this scan in a job that does NOT install "
     "dependencies, or scope it with detection-depth or an explicit path. "
     "Snyk IaC has no --exclude flag."),

    ("out-of-sync",
     [r"out of sync", r"strict-out-of-sync",
      r"Dependency snapshot is missing", r"lockfile.*out.of.date"],
     "The lockfile is out of sync with the manifest.",
     "Snyk refuses out-of-sync lockfiles by default. Regenerate the lockfile "
     "and commit it, or pass extra-args: --strict-out-of-sync=false, which "
     "scans a manifest Snyk knows is stale."),

    ("missing-deps",
     [r"Required packages missing", r"Missing node_modules folder",
      r"could not detect a supported.*after installing",
      r"Please run .?(npm|yarn|pnpm) install"],
     "Snyk ran but the dependencies were not resolved on disk.",
     "`snyk test` scans RESOLVED dependencies. Let install-command run (do not "
     "set it to \"skip\"), add the ecosystem's setup action before this step, "
     "or for pip pass extra-args: --skip-unresolved=true to accept a partial "
     "tree knowingly."),

    ("partial-scan",
     [r"Failed to get dependencies for",
      r"Could not (test|monitor) .* project",
      r"invalid string length"],
     "Some projects in this scan failed and were dropped.",
     "Without --fail-fast, `snyk test --all-projects` skips projects it could "
     "not scan and still reports success for the rest, so a green check can "
     "hide an unscanned component. This action adds --fail-fast automatically "
     "for multi-project scans; fix the failing project or exclude it "
     "explicitly with --exclude."),

    ("registry",
     [r"denied: requested access to the resource is denied",
      r"unauthorized: authentication required",
      r"pull access denied", r"no basic auth credentials"],
     "The container registry refused the pull.",
     "Log in to the registry before the scan (docker/login-action), or pass "
     "--username/--password via extra-args. Scan a locally built tag if the "
     "image was never pushed."),

    ("image",
     [r"image .* not found", r"unable to find image",
      r"Error response from daemon", r"Failed to scan image",
      r"manifest unknown", r"docker: .*not found"],
     "The image could not be read.",
     "Build or pull the image in a prior step and pass the exact tag to the "
     "image input. For a multi-arch image add --platform via extra-args."),

    ("tls",
     [r"unable to verify the first certificate", r"self.signed certificate",
      r"UNABLE_TO_GET_ISSUER_CERT", r"CERT_HAS_EXPIRED",
      r"DEPTH_ZERO_SELF_SIGNED_CERT"],
     "TLS verification to the Snyk API failed.",
     "Usually a corporate MITM proxy. Point NODE_EXTRA_CA_CERTS at the proxy "
     "CA bundle on the runner, and see Snyk's proxy configuration docs."),

    ("network",
     [r"ENOTFOUND", r"ECONNRESET", r"ECONNREFUSED", r"ETIMEDOUT",
      r"EAI_AGAIN", r"socket hang up", r"getaddrinfo",
      r"connect ETIMEDOUT", r"Client network socket disconnected"],
     "Network failure reaching the Snyk API.",
     "Usually transient; re-run the job. If it persists, check runner egress "
     "and any proxy or firewall rules for *.snyk.io."),

    ("server",
     [r"\b50[0-9]\b\s*(Internal Server Error|Bad Gateway|Service Unavailable|Gateway Time-?out)",
      r"Internal Server Error", r"Bad Gateway", r"Service Unavailable"],
     "Snyk API returned a server error.",
     "Transient on Snyk's side. Re-run, and check https://status.snyk.io."),
]

QUOTA = [r"reached your monthly limit", r"monthly limit of \d+ (private )?tests",
         r"\btest limit\b", r"upgrade your plan", r"out of tests"]


def find(text, patterns):
    return any(re.search(p, text, re.IGNORECASE | re.MULTILINE) for p in patterns)


def emit(pairs):
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        for key, value in pairs:
            value = str(value)
            if "\n" in value or "\r" in value:
                # Delimiter form: a raw newline would start a new output.
                delim = f"ghadelim_{uuid.uuid4().hex}"
                fh.write(f"{key}<<{delim}\n{value}\n{delim}\n")
            else:
                fh.write(f"{key}={value}\n")


def main():
    log = ""
    path = os.environ.get("CLASSIFY_LOG", "")
    if path and os.path.exists(path):
        try:
            with open(path, errors="replace") as f:
                log = f.read()
        except OSError:
            log = ""

    code = os.environ.get("CLASSIFY_EXIT", "")
    scan = os.environ.get("CLASSIFY_SCAN", "Scan")

    quota = find(log, QUOTA)
    reason, message, hint = "unknown", "", ""

    if code == "0":
        reason, message = "clean", f"{scan}: no findings at the threshold."
    elif code == "1":
        reason, message = "findings", f"{scan}: findings at the threshold."
    elif code == "3":
        reason, message = ("nothing-to-scan",
                           f"{scan}: no supported files found, nothing to scan.")
    else:
        for name, pats, msg, tip in PATTERNS:
            if find(log, pats):
                reason, message, hint = name, f"{scan}: {msg}", tip
                break
        else:
            if quota:
                reason = "quota"
                message = f"{scan}: the Snyk org has hit its test limit."
                hint = ("Scans are being refused until the limit resets or the "
                        "plan is upgraded. See https://snyk.io/plans.")
            elif code == "":
                # No exit code means the CLI never completed. Never clean.
                message = (f"{scan}: the scan step produced no exit code, so "
                           "the CLI did not run to completion.")
                hint = ("Open the scan step log. A cancelled job, an install "
                        "failure or a runner timeout all land here. Results "
                        "are void, not clean.")
            else:
                message = (f"{scan}: the Snyk CLI failed (exit {code}) "
                           "with no recognised error signature.")
                hint = ("Open the scan step log for the raw CLI output. Re-run "
                        "with extra-args: \"-d\" for debug output, but only on "
                        "a private repo: debug output is verbose and has not "
                        "been audited for secret redaction.")

    # Quota can fire on a passing scan; it is why the NEXT one fails.
    if quota and reason != "quota":
        print(f"::warning::{scan}: the Snyk org has reached its test limit. "
              "Scans will start failing until it resets or the plan is upgraded.")

    emit([("reason", reason), ("message", message), ("hint", hint),
          ("quota", "true" if quota else "false")])


if __name__ == "__main__":
    main()
