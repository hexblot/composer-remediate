#!/usr/bin/env bash
#
# Runs action/run.sh, the body of the shipped GitHub Action, against a local git remote with stubbed
# composer and gh commands. The PHP suite cannot reach this code, and the defects it has had were in
# exactly the decisions it makes: which revision the branch is built from, what goes into the commit,
# and which credential authenticates the push.
#
# Usage: tests/Action/action-test.sh

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
sandbox="$(mktemp -d)"
trap 'rm -rf "$sandbox"' EXIT
failures=0

note() { printf '  %s\n' "$1"; }
check() {
  if [ "$2" = "$3" ]; then
    printf '  ok   %s\n' "$1"
  else
    printf '  FAIL %s\n    expected: %s\n    actual:   %s\n' "$1" "$3" "$2" >&2
    failures=$((failures + 1))
  fi
}
contains() {
  if grep -qF -- "$2" "$3"; then
    printf '  ok   %s\n' "$1"
  else
    printf '  FAIL %s (not found in %s): %s\n' "$1" "$3" "$2" >&2
    failures=$((failures + 1))
  fi
}

# A remote with a base branch, and a feature branch carrying a commit that must not reach the pull request.
remote="$sandbox/remote.git"
git init -q --bare "$remote"
seed="$sandbox/seed"
git init -q -b main "$seed"
cd "$seed"
git config user.email t@t; git config user.name t
printf '{"name":"acme/app"}\n' > composer.json
printf '{"packages":[{"name":"acme/lib","version":"1.0.0"}]}\n' > composer.lock
git add -A && git commit -qm 'base'
git checkout -q -b feature
printf 'unrelated\n' > FEATURE.md
git add -A && git commit -qm 'a feature commit that must not appear in the remediation branch'
git push -q "$remote" main feature

# The workspace as a workflow leaves it: checked out on the feature branch, not on the base.
work="$sandbox/work"
git clone -q --branch feature "$remote" "$work"
cd "$work"
git config user.email t@t; git config user.name t

# Stubs. composer answers the three calls the script makes; gh answers the repository and pull request
# calls; git is wrapped so the push to an https URL is recorded and then sent to the local remote.
stub="$sandbox/stub"
mkdir -p "$stub"
cat > "$stub/composer" <<'STUB'
#!/usr/bin/env bash
case "$1 ${2:-}" in
  "remediate:pr-body "*) echo "rendered body" ;;
  *)
    if [[ " $* " == *" --apply "* ]]; then
      printf '{"packages":[{"name":"acme/lib","version":"1.1.0"}]}\n' > composer.lock
      echo '{"exit_code":0,"warnings":[],"summary":{"packages":0,"advisories":0},"findings":[]}'
      exit 0
    fi
    echo '{"exit_code":1,"warnings":[],"summary":{"packages":1,"advisories":1},"findings":[{"package":"acme/lib","version":"1.0.0","advisories":[{"id":"PKSA-1"}],"remediation":{"status":"verified","command":"composer update acme/lib"}}]}'
    exit 1
    ;;
esac
STUB
cat > "$stub/gh" <<'STUB'
#!/usr/bin/env bash
case "$1 ${2:-}" in
  "repo view") echo main ;;
  "pr list") echo "" ;;
  "pr create") echo "https://github.test/acme/app/pull/1" ;;
  "pr edit") ;;
esac
STUB
cat > "$stub/git" <<'STUB'
#!/usr/bin/env bash
# Records a push to an https URL, then performs it against the local remote instead.
# Every call that talks to the remote is recorded, whatever comes before the subcommand.
case " $* " in
  *" push "*|*" fetch "*) printf '%s\n' "$*" >> "$PUSH_LOG" ;;
esac
# Records the URL the action sets on the remote, then points it at the local one instead, so the rest
# of the run is real git against a real repository.
args=()
for arg in "$@"; do
  if [[ "$arg" == https://* ]]; then
    printf '%s\n' "$arg" >> "$PUSH_LOG"
    arg="$LOCAL_REMOTE"
  fi
  args+=("$arg")
done
exec /usr/bin/env -u PATH "$REAL_GIT" "${args[@]}"
STUB
chmod +x "$stub/composer" "$stub/gh" "$stub/git"

export REAL_GIT="$(command -v git)"
export LOCAL_REMOTE="$remote"
export PUSH_LOG="$sandbox/push.log"
: > "$PUSH_LOG"
export PATH="$stub:$PATH"
export GITHUB_OUTPUT="$sandbox/output.txt"
: > "$GITHUB_OUTPUT"
export GH_TOKEN='test-token-value'
export REMEDIATE_ARGS='--no-dev'
export BRANCH='remediate/advisories'
export BASE='main'
export COMMIT_MESSAGE='Apply verified Composer security fixes'
export PR_TITLE='Security: apply verified Composer fixes'
export PR_LABELS=''
export PR_DRAFT='false'
export WITH_INSTALL='false'
export REPOSITORY='acme/app'

echo "A run started on a feature branch, with an unrelated file already staged:"
printf 'staged by an earlier step\n' > STRAY.txt
git add STRAY.txt

bash "$root/action/run.sh" > "$sandbox/run.out" 2> "$sandbox/run.err" || {
  echo "  the action script failed:" >&2
  cat "$sandbox/run.err" >&2
  exit 1
}

check "it reports that a pull request was opened" "$(grep -c 'opened=true' "$GITHUB_OUTPUT")" "1"

pushed="$("$REAL_GIT" --git-dir="$remote" log --format=%s "refs/heads/$BRANCH")"
check "the branch carries one commit on top of the base" "$(printf '%s\n' "$pushed" | wc -l | tr -d ' ')" "2"
check "the remediation commit is the top of the branch" "$(printf '%s\n' "$pushed" | head -1)" "$COMMIT_MESSAGE"
if printf '%s\n' "$pushed" | grep -q 'feature commit'; then
  echo "  FAIL the branch was built from the checkout, not from the base" >&2
  failures=$((failures + 1))
else
  echo "  ok   the branch was built from the base, not from the checked-out feature branch"
fi

files="$("$REAL_GIT" --git-dir="$remote" show --name-only --format= "refs/heads/$BRANCH" | sort | tr '\n' ' ')"
check "the commit carries the file the fix changed" "$(printf '%s' "$files" | xargs)" "composer.lock"
if printf '%s' "$files" | grep -q 'STRAY'; then
  echo "  FAIL an unrelated staged file was committed into the security pull request" >&2
  failures=$((failures + 1))
else
  echo "  ok   the file an earlier step had staged was left out"
fi

contains "the remote was given the token it was told to use" "x-access-token:test-token-value@github.com/acme/app" "$PUSH_LOG"
contains "the push kept its lease" "--force-with-lease" "$PUSH_LOG"
# actions/checkout leaves an Authorization header in http.<server>/.extraheader. Credentials in the URL
# do not displace it, so the server would answer the checkout's identity and a supplied token would have
# no effect. What this harness can check is that every call talking to the remote resets that header;
# which credential a server actually receives needs a real HTTP server, and is not covered here.
contains "the calls that talk to the remote reset the checkout's authorization header" "http.https://github.com/.extraheader=" "$PUSH_LOG"

echo
echo "A second run, with the branch already on the remote:"
cd "$work"
"$REAL_GIT" checkout -q feature
printf '{"packages":[{"name":"acme/lib","version":"1.0.0"}]}\n' > composer.lock
"$REAL_GIT" checkout -q -- . 2>/dev/null || true
: > "$GITHUB_OUTPUT"
bash "$root/action/run.sh" > "$sandbox/run2.out" 2> "$sandbox/run2.err" || {
  echo "  the second run failed, which is the failure a scheduled job hides:" >&2
  tail -5 "$sandbox/run2.err" >&2
  failures=$((failures + 1))
}
check "the second run also opened or updated a pull request" "$(grep -c 'opened=true' "$GITHUB_OUTPUT")" "1"

echo
if [ "$failures" -eq 0 ]; then
  echo "action: all checks passed"
else
  echo "action: $failures check(s) failed" >&2
  exit 1
fi
