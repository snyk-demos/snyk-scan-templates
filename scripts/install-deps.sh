#!/usr/bin/env bash
# Resolve dependencies before `snyk test`, which scans RESOLVED dependencies.
# Build/no-build per ecosystem follows Snyk's matrix:
# https://docs.snyk.io/developer-tools/snyk-cli/snyk-cli/scan-and-maintain-projects-using-the-cli/snyk-cli-for-open-source/open-source-projects-that-must-be-built-before-testing-with-the-snyk-cli
#
# INSTALL_COMMAND: "auto" (default) detect and install | "skip"/"none" do
# nothing | anything else runs verbatim in bash. Never build that value from
# untrusted input such as PR titles, branch names or issue bodies.
#
# SUPPLY CHAIN: the pip, Poetry, Pipenv, Maven, dotnet and mix branches execute
# third-party code on the runner. Fork PRs are excluded by the example
# workflows; same-repo branches are not. Use install-command: "skip" plus your
# own hardened step if that matters.
set -euo pipefail

cmd="${INSTALL_COMMAND:-auto}"

case "$cmd" in
  skip|none)
    echo "Dependency install skipped (install-command: $cmd)."
    exit 0 ;;
  auto)
    ;;
  *)
    echo "Running custom install command from the workflow."
    bash -ec "$cmd"
    exit 0 ;;
esac

# require <tool> <ecosystem hint>
# Hard failure, not a warning: without the toolchain the scan tests an
# incomplete dependency tree and reports "clean".
require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "::error::Detected $2 but '$1' is not on the runner. Snyk needs this" \
         "project built before testing, so the scan would be incomplete. Add a" \
         "setup step (actions/setup-java, setup-python, setup-dotnet, ...)" \
         "before this action, or set the install-command input."
    exit 1
  fi
}

yarn_major() {
  yarn --version 2>/dev/null | cut -d. -f1
}

# ---- JavaScript / TypeScript (npm, Yarn, pnpm) ------------------------------
if   [ -f package-lock.json ]; then
  echo "Detected npm (package-lock.json)."
  npm ci --ignore-scripts || npm install --ignore-scripts
elif [ -f yarn.lock ]; then
  echo "Detected Yarn (yarn.lock)."
  corepack enable
  # Yarn Berry (2+) rejects --frozen-lockfile and has no --ignore-scripts;
  # the equivalents are --immutable and YARN_ENABLE_SCRIPTS=0.
  if [ "$(yarn_major)" -ge 2 ] 2>/dev/null; then
    echo "Yarn Berry detected; using --immutable with build scripts disabled."
    YARN_ENABLE_SCRIPTS=0 yarn install --immutable
  else
    yarn install --frozen-lockfile --ignore-scripts
  fi
elif [ -f pnpm-lock.yaml ]; then
  echo "Detected pnpm (pnpm-lock.yaml)."
  corepack enable
  pnpm install --frozen-lockfile --ignore-scripts
elif [ -f package.json ]; then
  echo "Detected Node without a lockfile (package.json)."
  npm install --ignore-scripts

# ---- Python -----------------------------------------------------------------
# Order matters: poetry.lock and Pipfile before the generic pyproject.toml
# branch, or a Poetry project hits `pip install -e .` and fails on poetry-core.
elif [ -f poetry.lock ]; then
  # Installing here would run third-party code for no scanning benefit.
  echo "Poetry: poetry.lock present; Snyk reads it directly, no install needed."
elif [ -f pyproject.toml ] && grep -q '\[tool\.poetry' pyproject.toml; then
  echo "Poetry without a lockfile; generating poetry.lock."
  if ! command -v poetry >/dev/null 2>&1; then
    require pipx "Poetry (pyproject.toml)"
    pipx install poetry
  fi
  poetry lock
elif [ -f Pipfile.lock ]; then
  echo "Detected Pipenv with a lockfile."
  if ! command -v pipenv >/dev/null 2>&1; then
    require pipx "Pipenv (Pipfile.lock)"
    pipx install pipenv
  fi
  pipenv install --deploy
elif [ -f Pipfile ]; then
  echo "Detected Pipenv without a lockfile."
  if ! command -v pipenv >/dev/null 2>&1; then
    require pipx "Pipenv (Pipfile)"
    pipx install pipenv
  fi
  pipenv lock && pipenv install --deploy
elif [ -f requirements.txt ]; then
  echo "Detected pip (requirements.txt). Install is required so the full" \
       "dependency tree, nested dependencies included, can be tested." \
       "Use extra-args: --skip-unresolved=true to test only what resolves" \
       "without building."
  require pip "pip (requirements.txt)"
  pip install -r requirements.txt
elif [ -f uv.lock ]; then
  # uv is in neither Snyk's build matrix nor its option help. Do not guess.
  echo "::warning::Found uv.lock. uv is not listed in Snyk's CLI build matrix." \
       "Export a requirements.txt (uv export --format requirements-txt) in a" \
       "prior step, or set install-command explicitly."
elif [ -f setup.py ] || [ -f pyproject.toml ]; then
  echo "Detected a Python package (setup.py/pyproject.toml)."
  require pip "Python package"
  pip install -e .

# ---- Ruby (Bundler): lockfile is read directly ------------------------------
elif [ -f Gemfile.lock ]; then
  echo "Ruby: Gemfile.lock present; Snyk reads it directly, no install needed."
elif [ -f Gemfile ]; then
  echo "Ruby: no Gemfile.lock; generating it with bundle install."
  require bundle "Ruby (Gemfile)"
  bundle install

# ---- PHP (Composer): lockfile is read directly ------------------------------
elif [ -f composer.lock ]; then
  echo "PHP: composer.lock present; Snyk reads it directly, no install needed."
elif [ -f composer.json ]; then
  echo "PHP: no composer.lock; generating it with composer install."
  require composer "PHP (composer.json)"
  composer install --no-scripts --no-interaction

# ---- .NET -------------------------------------------------------------------
elif [ -f paket.dependencies ]; then
  # "Build required: yes" with no documented CLI helper: nothing safe to run.
  echo "::error::Detected Paket (paket.dependencies). Snyk requires Paket" \
       "projects to be built before testing and this action has no safe" \
       "default for that. Set install-command explicitly."
  exit 1
elif ls ./*.sln >/dev/null 2>&1 || ls ./*.csproj >/dev/null 2>&1 \
  || ls ./*.fsproj >/dev/null 2>&1 || ls ./*.vbproj >/dev/null 2>&1 \
  || [ -f packages.config ]; then
  echo "Detected .NET; running dotnet restore to produce project.assets.json."
  require dotnet ".NET"
  dotnet restore

# ---- JVM: Maven must be built; Gradle and sbt are invoked by Snyk -----------
elif [ -f pom.xml ]; then
  echo "Detected Maven. Snyk requires the project built before testing."
  require mvn "Maven (pom.xml)"
  mvn -q -B -DskipTests install
elif [ -f build.gradle ] || [ -f build.gradle.kts ]; then
  echo "Gradle: no install needed; Snyk invokes Gradle itself during the scan." \
       "--all-sub-projects and --all-projects both require build.gradle AND" \
       "settings.gradle in the scanned directory."
elif [ -f build.sbt ]; then
  echo "sbt (Scala): no install needed; Snyk invokes sbt itself during the" \
       "scan. sbt 1.2 and older also need the sbt-dependency-graph plugin."

# ---- Go modules: manifest and lockfile are read directly --------------------
elif [ -f go.mod ]; then
  echo "Go modules: no install needed, Snyk resolves go.mod/go.sum directly."

# ---- Elixir (Hex) -----------------------------------------------------------
elif [ -f mix.exs ]; then
  # Not in Snyk's build matrix. Fetching is harmless if unsupported (exit 3)
  # and necessary if it is.
  echo "Detected Elixir (mix.exs); fetching dependencies." \
       "Note: Elixir is not listed in Snyk's CLI build matrix."
  require mix "Elixir (mix.exs)"
  mix deps.get

# ---- Swift / Objective-C ----------------------------------------------------
elif [ -f Podfile.lock ] || [ -f Package.swift ]; then
  echo "Swift/ObjC: CocoaPods and Swift Package Manager manifests are read" \
       "directly, no install needed."
elif [ -f Podfile ]; then
  echo "CocoaPods: no Podfile.lock; generating it with pod install."
  require pod "CocoaPods (Podfile)"
  pod install

else
  echo "::notice::No recognised manifest. If this repo has dependencies, set" \
       "the install-command input. C/C++ needs extra-args: --unmanaged." \
       "Otherwise Snyk reports 'nothing to scan' (exit 3), which passes the gate."
fi
