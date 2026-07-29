# Example workflows

Copy one into `.github/workflows/` and replace `YOUR-ORG`. All are standalone;
the single-scan files compose freely.

| File | Scans | Use when |
|:---|:---|:---|
| `snyk-sca.yml` | Open source deps | One scan at a time, or a staged rollout |
| `snyk-code.yml` | SAST | " |
| `snyk-iac.yml` | Terraform, CFN, K8s, ARM | " |
| `snyk-scans.yml` | SAST, SCA & IaC | One workflow with the 3 main scans |
| `snyk-scans-monorepo.yml` | SAST, SCA & IaC per component | Components need their own projects or owners |

Separate files give four independent checks and four concurrency groups, so a
slow container build doesn't hold up SAST feedback. The combined file gives you
one thing to maintain. Either is fine.

## Gating

Everything defaults to **report only**: findings go to the PR comment and the
Security tab, and the build breaks only when the scan itself breaks. Two ways
to block a merge:

- `fail-on-findings: "true"` blocks on **all** findings at `severity-threshold`,
  backlog included. Fine on a clean repo or a hard compliance line.
- Leave it `"false"` and make **Code scanning results** a required check in
  branch protection. That blocks only on findings the PR **introduces**, which
  is what most teams want on a codebase with history. Needs one push run on the
  default branch first, or there's no baseline to diff against.

Pick one. Both at once means a single problem fails two checks.

`severity-threshold` is the dial, not the mode. Usual rollout: report only →
critical → high → add the required check.

A scan that **couldn't complete** always fails, in every mode. Bad token, quota
exhausted, a manifest that won't resolve. The gate only treats exit 0, 1 and 3
as known-good, so incomplete results never read as clean.

## Things that bite

- **Skipped jobs pass required checks** and upload no SARIF, so no code
  scanning check appears for that PR at all. Fork PRs get no secrets and
  therefore skip. Sort that out before making the check required.
- **`merge_group`** must be in `on:` if the code scanning check is required and
  the repo uses a merge queue, or the merge fails on a check that never reports.
- **Pin `snyk-cli-version`.** On `latest` a CLI release can change what your
  gate does with no commit in your repo.
- **`monitor` on default-branch pushes only,** or every PR branch forks a new
  Snyk project.
- **`comment-marker` must be unique** per action call in a repo. It's both the
  code scanning category and the sticky PR comment marker.
