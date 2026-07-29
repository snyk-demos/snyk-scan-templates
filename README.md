# Snyk Scan Templates

Four composite GitHub Actions wrapping the Snyk CLI. Each installs a checksum-verified CLI, scans, classifies failures, writes a run summary and a sticky PR comment, uploads SARIF to GitHub code scanning, and gates the check.

| Action | Command | Scans | Publishes via |
|---|---|---|---|
| `sca` | `snyk test` | Open source dependencies | `snyk monitor` step |
| `code` | `snyk code test` | First-party code (SAST) | `--report` on the test |
| `iac` | `snyk iac test` | Terraform, CFN, K8s, ARM | `--report` on the test |
| `container` | `snyk container test` | A built image | `snyk container monitor` step |

**Gate:** exit 0 and 3 pass. Exit 1 passes unless `fail-on-findings`. Everything else, including an unset exit code, fails.

## Setup

1. Add a Snyk service account token as the `SNYK_TOKEN` secret.
2. Copy an example into `.github/workflows/` and replace `YOUR-ORG`.
3. Permissions: `contents: read`, `pull-requests: write`, `security-events: write`, `actions: read`.
4. To block merges: branch protection → require the **`Code scanning results`** check.

| Example | Use when |
|---|---|
| `snyk-scans.yml` | Repo not imported into Snyk. Publishes on default-branch pushes. |
| `snyk-scans-cli-only.yml` | Repo already imported via the SCM integration. CI gating only. |
| `snyk-scans-monorepo.yml` | Per-component matrix. Needed above ~20 manifests (see SARIF limits). |

Do not publish from CI and import via SCM. That duplicates projects, splits ignore state, and doubles test consumption.

## Inputs

### All four actions

| Input | Default | Notes |
|---|---|---|
| `snyk-token` | required | |
| `snyk-org` | `""` | Slug or UUID. Only if the token spans orgs. |
| `severity-threshold` | `high` | `low\|medium\|high\|critical`. Snyk Code has no `critical`; it is lowered to `high` with a warning. |
| `fail-on-findings` | `"false"` | `"true"` fails on findings. Redundant if code scanning is your required check. |
| `upload-sarif` | `"true"` | Private repos need GitHub Code Security. |
| `pr-comment` | `"true"` | One sticky comment per scan, keyed on `comment-marker`. |
| `working-directory` | `.` | For `container`, output files and Dockerfile lookup only; the image is scanned by name. |
| `monitor` | `"false"` | Publish to the Snyk UI. Default-branch pushes only, or every PR branch becomes a project. |
| `target-reference` | `""` | Branch or tag. Never a commit SHA. |
| `project-tags` | `""` | `key=value,...`. Needs a role that can edit project attributes. |
| `extra-args` | `""` | Appended **unquoted**. Never put a secret here. |
| `comment-marker` | `snyk-<scan>` | Also the code scanning category. Must be unique per scan and per matrix leg. |
| `snyk-cli-version` | `latest` | **Pin it.** On `latest` a CLI release changes your gate with no commit. |
| `verify-cli-gpg` | `"false"` | `"true"` verifies the signed `sha256sums.txt.asc` as well as the digest. |
| `github-token` | `${{ github.token }}` | |
| `remote-repo-url` | `""` | `sca`, `code`, `iac` only. Defaults to this repo's URL. Change on one, change on all three. |

### Per action

| Action | Input | Default | Notes |
|---|---|---|---|
| `sca` | `install-command` | `auto` | `skip` disables. Anything else runs verbatim in bash. |
| `sca` | `project-name` | `""` | Auto-detects the manifest filename. **Set explicitly when `working-directory` is not `.`** or components collide. Ignored for multi-manifest scans. |
| `sca` | `monitor-required` | `"true"` | `"false"` downgrades a failed publish to a warning. |
| `code` | `project-name` | `Code Scan` | Required by the CLI with `--report`. Keep it stable or each run forks a project. |
| `iac` | `detection-depth` | `""` | The only scoping control; `snyk iac test` has no `--exclude`. |
| `container` | `image` | required | Build it first. |
| `container` | `dockerfile` | `Dockerfile` | Base image upgrade advice. Missing file warns. |
| `container` | `exclude-app-vulns` | `"true"` | OS packages only. See the coverage gap below. |
| `container` | `project-name` | `Container Image` | Set per image; the CLI gives no other handle. |
| `container` | `monitor-required` | `"false"` | Publish retried up to 3 times; exit 3 is not retried. |

**Outputs:** `exit-code` (0 clean, 1 findings, 2 error, 3 nothing to scan), `results-file` (`snyk-<scan>.sarif`, relative to `working-directory`).

## Snyk UI grouping

Model is Org → Target → Project. Current CLI support:

| Command | `--remote-repo-url` | `--target-name` | `--target-reference` | `--project-tags` | `--project-name` |
|---|---|---|---|---|---|
| `snyk test` | yes | no | yes (not with `--unmanaged`) | no | yes |
| `snyk monitor` | yes | no | yes | yes | yes |
| `snyk code test --report` | yes | yes | yes | yes | **required** |
| `snyk iac test --report` | yes | yes (**supersedes** `--remote-repo-url`) | yes | yes | none |
| `snyk container monitor` | **no** | **no** | yes | yes | yes |

- `sca`, `code` and `iac` pass an identical `--remote-repo-url` and omit `--target-name`, so they land as close to one target as the CLI allows. One shared target is not documented or guaranteed; use `project-tags` for a reliable cross-product view.
- `container` cannot join: `container monitor` takes no `--remote-repo-url`. Two targets is the floor for one repo plus one image.
- Targets key on the literal URL string. `.../repo`, `.../repo.git`, `.../repo/` and a case variant are different targets. Pass the flag explicitly everywhere.
- Projects cannot be renamed or re-parented. Delete strays before changing names.
- Ignores do not cross projects. A CVE ignored on SCA still shows on container.

## Blocking merges

- The check fails only on **error / critical / high** security severity. Scanning at `medium` and expecting it to block will not work; use `fail-on-findings: "true"` or change the repo's failure severities.
- An alert appears on a PR only if its lines are in the diff, compared against the default-branch baseline.
- **No upload means no check.** Fork PRs (no secrets, job skipped) and clean Snyk Code scans (no SARIF written) produce no `Code scanning results` check at all. A skipped job separately counts as successful for required checks, so job status and check status can disagree.
- Merge queues require the `merge_group` trigger or the entry never reports and the merge fails. All examples declare it.
- `snyk-scans.yml` pushes only on `main`/`master`. Other branches are scanned via their PR only.
- `cancel-in-progress` applies to PRs only. A cancelled run uploads no SARIF and leaves the previous comment; `monitor`/`--report` are push-only, so no Snyk project is left half-written.

## Failure reasons

`classify.py` maps the CLI log and exit code to a cause, surfaced in the annotation, summary and comment.

| Reason | Fix |
|---|---|
| `misconfig` | The step broke before Snyk ran. Any "clean" result is void. |
| `bad-flag` | An `extra-args` flag this subcommand does not accept. `snyk test` options are not valid on `code`/`iac`/`container test`. |
| `unsupported` | Check `working-directory` and language support for this scan type. |
| `auth` | 401. Recreate `SNYK_TOKEN` as a service account token with org access. |
| `forbidden` | 403. For `code` + `monitor`, usually the role missing **View Project Ignores**. Also fires when a project-attribute option is set without permission to edit attributes. |
| `rate-limit` | 429. Reduce matrix parallelism. |
| `parse` | Malformed JSON/YAML, usually `node_modules`. Do not install deps in the IaC job. |
| `out-of-sync` | Regenerate the lockfile, or `--strict-out-of-sync=false`. |
| `missing-deps` | Let `install-command` run, or add the ecosystem's setup action. |
| `partial-scan` | Projects were dropped from a multi-project scan. Fix or `--exclude` them. |
| `registry` / `image` | Use `docker/login-action`, or scan a locally built tag. |
| `tls` | MITM proxy. Set `NODE_EXTRA_CA_CERTS`. |
| `network` / `server` | Transient. Re-run. |
| `quota` | Org out of tests. Warned even on passing scans. |
| `unknown`, empty exit code | The CLI did not finish. Void, not clean. |

## Considerations

**Secrets.** `extra-args` is traced into the run log. `container` fails the job on `--username`/`--password`; all four warn on `-d`. Snyk does not document debug output as redacted, so treat it as leaking on public repos. No step echoes either token.

**Multi-project scans.** Without `--fail-fast`, Snyk drops projects it could not scan and still exits 0, so `sca` adds it automatically for `--all-projects`/`--yarn-workspaces`/`--all-sub-projects`. `--all-projects` also writes one SARIF run per manifest; `sarif-prep.py` gives each a distinct category and **fails** above 20 runs rather than skipping the upload. Past ~20 manifests, use the matrix example.

**SARIF limits.** 20 runs per file, 25,000 results per run (top 5,000 shown), 10 MB gzipped. Enforced before upload. Uploads use `github/codeql-action/upload-sarif@v4` by major tag, as GitHub recommends; everything else is SHA-pinned.

**Dependency install (`sca`, `auto`).** First-match chain: Node → Python → Ruby → PHP → .NET → JVM → Go → Elixir → Swift. Installs only where Snyk documents a build as required; committed lockfiles (including Poetry) are a no-op. Yarn Berry uses `--immutable` with scripts disabled. `pip`, Poetry lock, Pipenv, `mvn install`, `dotnet restore` and `mix deps.get` execute third-party code on the runner; fork PRs are excluded but **same-repo branches are not**. Missing toolchains are a hard error, not a warning. `uv` and Paket are not auto-handled. C/C++ needs `--unmanaged`, which is incompatible with `--target-reference`.

**Snyk Code.** `--report` needs **View Project Ignores** and CLI v1.1297.0+. No `--all-projects`; one path per run. No output file on a clean scan, so previous alerts stay open.

**IaC.** Never install deps in the IaC job. No `--exclude`. `--report` cannot combine with `--rules` (the action fails fast). No `--project-name`. Whether `--sarif-file-output` is honoured with `--report` is undocumented; the action does not assume a file exists.

**Container.** `exclude-app-vulns` is not deduplication. `sca` scans repo manifests, app-vulns scans what is installed in the image; anything a `RUN` line, vendored jar or base image adds is covered by **neither**. Set `"false"` if your images install what the manifests do not. `container monitor` exit codes are 0, 2, 3 only.

**Supply chain.** The `.sha256` is integrity, not provenance. `verify-cli-gpg: "true"` checks the signed sums against fingerprint `467717A30B2B4658415975629691DA64D0025194`.

**Environment.** GitHub-hosted runners: `gh`, `jq`, `python3`, `docker` and language toolchains on PATH. The installer covers glibc and musl Linux, macOS and Windows on x64/arm64, probing the loader directly because `RUNNER_OS` cannot distinguish musl.
