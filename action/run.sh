#!/usr/bin/env bash
#
# The body of the composer-remediate GitHub Action. A file rather than a string inside action.yml so
# that tests/Action/action-test.sh can run this exact script against a local git remote with stubbed
# composer and gh commands: the branch, index and authentication decisions here are not reachable from
# the PHP suite, and two defects in them survived a green suite once already.
#
# Every input arrives through the environment; nothing is interpolated into this file.

set -euo pipefail
echo "opened=false" >> "$GITHUB_OUTPUT"

work="$(mktemp -d)"
git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"

# The token authenticates every git operation here, not only the API calls: the checkout's own
# credentials may be absent, or be a different identity from the one the pull request should come from.
# It goes on the remote rather than on the push, so that fetches are authenticated too and so that
# --force-with-lease still has a remote-tracking ref to lease against, which a push straight to a URL
# does not.
#
# Credentials in the URL are not enough on their own. actions/checkout leaves an Authorization header
# configured in http.<server>/.extraheader, git sends it, and the server answers the checkout's identity
# rather than this token, so a checkout credential that cannot push would keep failing however good the
# token is. Every call that talks to the remote resets that header for the duration of the call: an empty
# value clears the list, and nothing of the workflow's own configuration is changed.
server="${GITHUB_SERVER_URL:-https://github.com}"
server="${server%/}"
git_remote=(-c "http.${server}/.extraheader=")
host="${server#https://}"
git remote set-url origin "https://x-access-token:${GH_TOKEN}@${host}/${REPOSITORY}.git"

# The base is established before anything is planned. A fix is planned against the code it will
# be applied to, and the branch this run produces has to contain that and nothing else; planning
# on whatever ref happened to be checked out would carry unrelated commits into the pull request.
base="${BASE:-$(gh repo view "$REPOSITORY" --json defaultBranchRef --jq .defaultBranchRef.name)}"
git "${git_remote[@]}" fetch -q origin "+refs/heads/$base:refs/remotes/origin/$base"
git checkout -q --detach "refs/remotes/origin/$base"
# shellcheck disable=SC2086  # REMEDIATE_ARGS is a deliberate argument list
set +e
composer remediate --format=json $REMEDIATE_ARGS > "$work/before.json"
before=$?
set -e
echo "exit-code-before=$before" >> "$GITHUB_OUTPUT"
if [ "$before" -ge 3 ]; then
  echo "::error::composer remediate could not complete (exit $before); nothing was applied."
  jq -r '.warnings[]?' "$work/before.json" 2>/dev/null || true
  exit "$before"
fi
if [ "$(jq -r '[.findings[] | select(.remediation.status == "verified")] | length' "$work/before.json")" = "0" ]; then
  echo "Nothing to apply: no finding has a verified fix."
  exit 0
fi

# The checkout only fetched the ref that triggered this run, so on every run after the first
# there is no remote-tracking ref for the remediation branch and --force-with-lease would refuse
# with stale info. Fetching it explicitly gives the lease something to compare against; when the
# branch does not exist yet the fetch fails, there is nothing to lease, and the push creates it.
git "${git_remote[@]}" fetch -q origin "+refs/heads/$BRANCH:refs/remotes/origin/$BRANCH" || true
# Built from the base, which is where the planning above happened, not continued from the branch:
# a commit pushed to this branch by hand is replaced by the next run.
git checkout -q -B "$BRANCH"

apply=(--apply --format=json)
if [ "$WITH_INSTALL" != "true" ]; then apply+=(--apply-no-install); fi
set +e
# shellcheck disable=SC2086
composer remediate "${apply[@]}" $REMEDIATE_ARGS > "$work/after.json"
after=$?
set -e
echo "exit-code-after=$after" >> "$GITHUB_OUTPUT"
if [ "$after" -ge 3 ]; then
  echo "::error::the apply did not complete (exit $after)."
  exit "$after"
fi

if git diff --quiet -- composer.json composer.lock; then
  echo "The apply changed neither composer.json nor composer.lock; nothing to open."
  exit 0
fi

jq -r '.warnings[]? | select(startswith("Applied: ")) | sub("^Applied: "; "") | sub("\\. The composer\\.json.*$"; "")' "$work/after.json" \
  | tr '&' '\n' | sed 's/^ *//; s/ *$//' | grep -v '^$' > "$work/commands.txt" || true
composer remediate:pr-body "$work/before.json" "$work/after.json" --commands="$work/commands.txt" > "$work/body.md"

# Only the two files this run changed, whatever an earlier step of the workflow left in the index:
# a security pull request carries the fix and nothing that came along with it.
git reset -q
git commit -q -m "$COMMIT_MESSAGE" -- composer.json composer.lock
git "${git_remote[@]}" push -q --force-with-lease origin "$BRANCH"

url="$(gh pr list --head "$BRANCH" --base "$base" --state open --json url --jq '.[0].url // empty')"
if [ -n "$url" ]; then
  gh pr edit "$url" --title "$PR_TITLE" --body-file "$work/body.md"
else
  create=(--head "$BRANCH" --base "$base" --title "$PR_TITLE" --body-file "$work/body.md")
  if [ "$PR_DRAFT" = "true" ]; then create+=(--draft); fi
  if [ -n "$PR_LABELS" ]; then create+=(--label "$PR_LABELS"); fi
  url="$(gh pr create "${create[@]}")"
fi
echo "opened=true" >> "$GITHUB_OUTPUT"
echo "pull-request=$url" >> "$GITHUB_OUTPUT"
echo "Pull request: $url"
