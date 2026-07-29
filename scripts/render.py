#!/usr/bin/env python3
"""Render scan results as Markdown for the run summary and PR comment.

Sources, preferred first:
  RENDER_JSON  Snyk JSON (SCA/container). Carries fix data SARIF lacks.
               --all-projects makes this an array, one element per project.
  RENDER_FILE  SARIF. Only source for Code scans, fallback for SCA. One run
               per project on multi-project scans; all are read.

Other env: RENDER_TITLE, RENDER_EXIT, RENDER_OUT (default report.md),
           RENDER_REF (PR head SHA; GITHUB_SHA is a merge commit on PRs),
           ERROR_MESSAGE / ERROR_HINT (from classify.py),
           GITHUB_SERVER_URL / GITHUB_REPOSITORY.
"""
import json
import os
import re

CLEAN = "> \u2705 **Clean.** No findings at this threshold."
SEV_ORDER = ["critical", "high", "medium", "low"]
ICON = {"critical": "\U0001F6A8", "high": "\U0001F534",
        "medium": "\U0001F7E0", "low": "\U0001F7E1"}
NAME = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
# SARIF's default level when absent is "warning", not "note", so an
# unlabelled result must not become low.
LEVEL = {"error": "high", "warning": "medium", "note": "low", "none": "low"}
ROW_LIMIT = 25          # rows shown per severity section
VULN_DB = "https://security.snyk.io/vuln/"


def esc(text):
    """Keep cell text from breaking the Markdown table."""
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def scorecard(counts, fixable=None, unit="findings"):
    """Summary table: one row per severity present, plus a total.

    Gains a Fixable column when fixability is known (dependency scans).
    """
    if fixable is not None:
        rows = [f"| Severity | {unit.capitalize()} | Fixable |",
                "|:---|---:|---:|"]
    else:
        rows = [f"| Severity | {unit.capitalize()} |", "|:---|---:|"]

    total = 0
    total_fix = 0
    for s in SEV_ORDER:
        n = counts.get(s, 0)
        if not n:
            continue
        total += n
        row = f"| {ICON[s]} **{NAME[s]}** | {n} |"
        if fixable is not None:
            f = fixable.get(s, 0)
            total_fix += f
            row = f"| {ICON[s]} **{NAME[s]}** | {n} | {f} |"
        rows.append(row)

    tail = f"| **Total** | **{total}** |"
    if fixable is not None:
        tail = f"| **Total** | **{total}** | **{total_fix}** |"
    rows.append(tail)
    return rows + [""]


def section(sev, count, rows, note=None):
    """One collapsed severity block. Closed by default, count in the label."""
    out = ["<details>",
           f"<summary>&nbsp;{ICON[sev]}&nbsp; <b>{NAME[sev]}</b> "
           f"&nbsp;&mdash;&nbsp; {count} </summary>", ""] + rows
    if note:
        out += ["", note]
    return out + ["", "</details>", ""]


# ---------------------------------------------------------------- SCA (JSON)

def sca_projects(doc):
    """Normalise Snyk Open Source JSON into a list of project objects.

    Single-project scans write one object; --all-projects writes an array.
    """
    if isinstance(doc, list):
        return [d for d in doc if isinstance(d, dict) and "vulnerabilities" in d]
    if isinstance(doc, dict):
        if "vulnerabilities" in doc:
            return [doc]
        inner = doc.get("projects")
        if isinstance(inner, list):
            return [d for d in inner
                    if isinstance(d, dict) and "vulnerabilities" in d]
    return []


def render_sca_json(projects):
    """Dedupe, score, then group by severity.

    Snyk JSON repeats a vulnerability once per dependency path, so dedupe
    first or every count in the report is inflated.
    """
    vulns = []
    names = []
    for p in projects:
        label = p.get("displayTargetFile") or p.get("targetFile") or p.get("projectName")
        if label:
            names.append(str(label))
        for v in p.get("vulnerabilities") or []:
            v = dict(v)
            v["_project"] = label or ""
            vulns.append(v)

    header = []
    if len(projects) > 1:
        shown = ", ".join(f"`{esc(n)}`" for n in names[:8])
        more = f" _+{len(names) - 8} more_" if len(names) > 8 else ""
        header = [f"**{len(projects)} projects scanned:** {shown}{more}", ""]

    if not vulns:
        return header + [CLEAN]

    seen = {}
    for v in vulns:
        seen.setdefault(
            (v.get("id"), v.get("packageName"), v.get("version"), v.get("_project")), v)
    vulns = list(seen.values())

    def sev_of(v):
        return str(v.get("severity", "low")).lower()

    def direct_target(v):
        # upgradePath[0] is the project; [1] is the direct dep to bump.
        up = v.get("upgradePath") or []
        return next((str(p) for p in up[1:2] if p), "")

    def is_fixable(v):
        return bool(v.get("isUpgradable") or v.get("fixedIn") or v.get("isPatchable"))

    def fix_for(v):
        target = direct_target(v)
        if v.get("isUpgradable") and target:
            return f"upgrade `{esc(target)}`"
        fixed = v.get("fixedIn") or []
        if fixed:
            return f"fixed in `{esc(', '.join(map(str, fixed[:3])))}`"
        if v.get("isPatchable"):
            return "`snyk patch` available"
        return "_no fix yet_"

    def is_direct(v):
        # from[] is [project, direct-dep, ...]; length 2 means direct.
        return len(v.get("from") or []) <= 2

    counts, fixable, pkgs, buckets = {}, {}, set(), {}
    for v in vulns:
        s = sev_of(v)
        counts[s] = counts.get(s, 0) + 1
        if is_fixable(v):
            fixable[s] = fixable.get(s, 0) + 1
        pkgs.add(f"{v.get('packageName', '?')}@{v.get('version', '?')}")
        buckets.setdefault(s, []).append(v)

    noun = "vulnerability" if len(vulns) == 1 else "vulnerabilities"
    out = header + [f"**{len(vulns)} {noun}** across **{len(pkgs)} packages**", ""]
    out += scorecard(counts, fixable, unit="vulns")

    upgrades = {}
    for v in vulns:
        target = direct_target(v)
        if v.get("isUpgradable") and target:
            upgrades.setdefault(target, set()).add(v.get("id"))

    if upgrades:
        def ver_key(target):
            ver = target.rsplit("@", 1)[-1]
            return tuple(int(x) if x.isdigit() else 0
                         for x in re.split(r"[.+-]", ver)[:4])

        by_pkg = {}
        for target, ids in upgrades.items():
            d = by_pkg.setdefault(target.rsplit("@", 1)[0],
                                  {"targets": [], "ids": set()})
            d["targets"].append(target)
            d["ids"] |= ids
        # The highest suggested version subsumes the lower ones.
        merged = [(max(d["targets"], key=ver_key), d["ids"])
                  for d in by_pkg.values()]
        ranked = sorted(merged, key=lambda kv: -len(kv[1]))
        cleared = len(set().union(*(ids for _, ids in ranked)))

        out += ["> [!TIP]",
                f"> **Fix first.** {len(ranked)} direct "
                f"upgrade{'' if len(ranked) == 1 else 's'} "
                f"clear{' ' if len(ranked) != 1 else 's '}"
                f"{cleared} of the {len(vulns)} {noun}.", "",
                "| Upgrade to | Clears |", "|:---|---:|"]
        for target, ids in ranked[:10]:
            out.append(f"| `{esc(target)}` | **{len(ids)}** |")
        if len(ranked) > 10:
            out.append(f"| _+{len(ranked) - 10} more_ | |")
        out.append("")

    multi = len(projects) > 1
    for s in SEV_ORDER:
        group = buckets.get(s)
        if not group:
            continue
        group.sort(key=lambda v: (str(v.get("_project", "")),
                                  str(v.get("packageName", ""))))
        if multi:
            rows = ["| Project | Package | | Vulnerability | Fix |",
                    "|:---|:---|:---|:---|:---|"]
        else:
            rows = ["| Package | | Vulnerability | Fix |", "|:---|:---|:---|:---|"]
        for v in group[:ROW_LIMIT]:
            pkg = f"{v.get('packageName', '?')}@{v.get('version', '?')}"
            title = esc(v.get("title") or v.get("id") or "Vulnerability")
            link = f"{VULN_DB}{v.get('id', '')}"
            kind = "direct" if is_direct(v) else "transitive"
            cells = f"`{esc(pkg)}` | {kind} | [{title}]({link}) | {fix_for(v)}"
            if multi:
                rows.append(f"| `{esc(v.get('_project', ''))}` | {cells} |")
            else:
                rows.append(f"| {cells} |")
        note = None
        if len(group) > ROW_LIMIT:
            note = (f"_+{len(group) - ROW_LIMIT} more at this severity; the "
                    "full list is in the Snyk UI and the run log._")
        out += section(s, len(group), rows, note)

    unfixable = [v for v in vulns if not is_fixable(v)]
    if unfixable:
        names_nf = sorted({f"`{esc(v.get('packageName', '?'))}`" for v in unfixable})
        out += ["> [!WARNING]",
                f"> **No fix available** for {', '.join(names_nf[:15])}."
                " Replace the package, or accept the risk explicitly with a"
                " Snyk ignore policy so it stops costing triage time.", ""]
    return out


# ------------------------------------------------------------------- SARIF

def severity(result, rules):
    for src in (result.get("properties") or {},
                (rules.get(result.get("ruleId")) or {}).get("properties") or {}):
        s = str(src.get("severity", "")).lower()
        if s in NAME:
            return s
    # Snyk Code leaves properties.severity empty and puts the numeric
    # security-severity on the rule instead.
    rule_props = (rules.get(result.get("ruleId")) or {}).get("properties") or {}
    raw = rule_props.get("security-severity")
    if raw is not None:
        try:
            score = float(raw)
        except (TypeError, ValueError):
            score = None
        if score is not None:
            if score >= 9.0:
                return "critical"
            if score >= 7.0:
                return "high"
            if score >= 4.0:
                return "medium"
            return "low"
    return LEVEL.get(result.get("level", "warning"), "medium")


def cwe_of(rule):
    props = (rule or {}).get("properties") or {}
    for c in props.get("cwe") or []:
        return str(c)
    for t in props.get("tags") or []:
        if re.fullmatch(r"(?i)cwe-\d+", str(t)):
            return str(t).upper()
    return ""


def blob_link(uri, line):
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    ref = os.environ.get("RENDER_REF") or os.environ.get("GITHUB_SHA", "")
    label = esc(f"{uri}:{line}")
    if repo and ref and isinstance(line, int):
        return f"[`{label}`]({server}/{repo}/blob/{ref}/{uri}#L{line})"
    return f"`{label}`"


def render_sarif(doc):
    """Read every run: multi-manifest scans write one run per project."""
    runs = doc.get("runs") or []
    results = []
    rules = {}
    for run in runs:
        raw = ((run.get("tool") or {}).get("driver") or {}).get("rules", []) or []
        for r in raw:
            rules.setdefault(r.get("id"), r)
        results.extend(run.get("results") or [])
    if not results:
        return [CLEAN]

    buckets = {}
    for r in results:
        buckets.setdefault(severity(r, rules), []).append(r)
    counts = {s: len(v) for s, v in buckets.items()}

    files = {((r.get("locations") or [{}])[0].get("physicalLocation") or {})
             .get("artifactLocation", {}).get("uri", "?") for r in results}
    noun = "finding" if len(results) == 1 else "findings"
    out = [f"**{len(results)} {noun}** across **{len(files)} files**", ""]
    if len(runs) > 1:
        out[0] += f" in **{len(runs)} projects**"
    out += scorecard(counts)

    for s in SEV_ORDER:
        group = buckets.get(s)
        if not group:
            continue
        rows = ["| Issue | CWE | Location |", "|:---|:---|:---|"]
        for r in group[:ROW_LIMIT]:
            rid = r.get("ruleId") or "?"
            rule = rules.get(rid) or {}
            title = esc((rule.get("shortDescription") or {}).get("text") or rid)
            # SNYK-* ids link to the vuln DB; Code rules use helpUri.
            help_uri = rule.get("helpUri") or ""
            if re.match(r"^SNYK-", rid):
                help_uri = help_uri or f"{VULN_DB}{rid}"
            issue = f"[{title}]({help_uri})" if help_uri else title
            loc = (r.get("locations") or [{}])[0].get("physicalLocation") or {}
            uri = (loc.get("artifactLocation") or {}).get("uri", "?")
            line = (loc.get("region") or {}).get("startLine", "?")
            rows.append(f"| {issue} | {cwe_of(rule) or '&nbsp;'} "
                        f"| {blob_link(uri, line)} |")
        note = None
        if len(group) > ROW_LIMIT:
            note = (f"_+{len(group) - ROW_LIMIT} more at this severity; see "
                    "the Security tab for the full list._")
        out += section(s, len(group), rows, note)
    return out


# -------------------------------------------------------------------- main

def load(path):
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def footer():
    """A dim one-liner: what was scanned and where the rest lives."""
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    ref = os.environ.get("RENDER_REF") or os.environ.get("GITHUB_SHA", "")
    bits = []
    if ref:
        bits.append(f"scanned <code>{esc(ref[:7])}</code>")
    if repo:
        bits.append(f"<a href='{server}/{repo}/security/code-scanning'>"
                    "all alerts in the Security tab</a>")
    if not bits:
        return []
    return ["<sub>" + " &nbsp;\u00b7&nbsp; ".join(bits) + "</sub>", ""]


def main():
    title = os.environ.get("RENDER_TITLE", "")
    code = os.environ.get("RENDER_EXIT")
    body, status = [], "\u2705"

    if code == "3":
        status = "\u2139\uFE0F"
        body = ["> [!NOTE]", "> **Nothing to scan** in this repo at this path."]
    elif code not in ("0", "1"):
        # A failed scan has no results; show the diagnosis, not an empty table.
        status = "\u274C"
        msg = os.environ.get("ERROR_MESSAGE", "").strip() or "The scan failed."
        hint = os.environ.get("ERROR_HINT", "").strip()
        body = ["> [!CAUTION]", f"> **{msg}**", ">",
                "> Results are incomplete: this is **not** a clean scan."]
        if hint:
            body += [">", f"> **Fix:** {hint}"]
    else:
        projects = sca_projects(load(os.environ.get("RENDER_JSON")))
        sarif = load(os.environ.get("RENDER_FILE"))
        if projects:
            body = render_sca_json(projects)
        elif isinstance(sarif, dict):
            body = render_sarif(sarif)
        elif code == "0":
            # Snyk writes no output file on a completely clean SAST scan.
            body = [CLEAN]
        else:
            status = "\u26A0\uFE0F"
            body = ["> [!WARNING]",
                    "> **No readable results.** Check the scan step log."]
        if code == "1" and body and body[-1] != CLEAN and CLEAN not in body:
            status = "\U0001F534"

    lines = [f"### {status} &nbsp;{title}", ""] if title else []
    lines += body
    if lines and lines[-1] != "":
        lines.append("")          # a blockquote runs on without this
    lines += footer()

    with open(os.environ.get("RENDER_OUT", "report.md"), "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n\n")


if __name__ == "__main__":
    main()
