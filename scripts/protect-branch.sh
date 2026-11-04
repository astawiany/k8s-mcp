#!/usr/bin/env bash
# Apply branch protection on main, the "release" GitHub Environment and the v* tag ruleset.
# Usage: scripts/protect-branch.sh [--dry-run] --repo owner/name [--branch main] [--approvals N]
#          [--enforce-admins] [--no-protect-tags]
#   --repo           required, always (dry run included); there is no default and nothing runs implicitly
#   --dry-run        print the exact gh api calls and execute nothing (no gh needed)
#   --approvals N    approving PR reviews required on the branch, 0-6 (default 0: GitHub never lets an
#                    author approve their own PR, so a solo owner would be locked out with 1). With 1 or
#                    more, code-owner review is required too. See .github/README.md.
#   --enforce-admins apply the rules to admins as well (default off, so the owner is never locked out)
#   --no-protect-tags skip the tag ruleset "release-tags" (prints a warning). By default it is created
#                    (or updated): only repository admins may create, move or delete v* tags, because a
#                    pushed v* tag runs the workflows of the tagged commit.
# Required status checks are the job ids of .github/workflows/validate.yml, except the jobs in
# OPTIONAL_JOBS (they download vulnerability databases at run time and must not block merges).
# The "release" Environment has the repository owner as required reviewer and only accepts
# deployments from v* tags. The reviewer is added as type User (the owner's id): for an
# organization-owned repository add a team reviewer by hand in Settings > Environments > release. After applying, everything is read back and the script exits 1 when the
# release tag policy, the ruleset or the branch protection is missing.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dry=0
repo=""
branch=main
approvals=0
enforce_admins=false
protect_tags=1
OPTIONAL_JOBS="security"

need() { [ "$1" -ge 2 ] || { echo "protect-branch: $2 needs a value" >&2; exit 2; }; }
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) dry=1; shift ;;
    --repo) need $# --repo; repo="$2"; shift 2 ;;
    --branch) need $# --branch; branch="$2"; shift 2 ;;
    --approvals) need $# --approvals; approvals="$2"; shift 2 ;;
    --enforce-admins) enforce_admins=true; shift ;;
    --no-protect-tags) protect_tags=0; shift ;;
    *) echo "protect-branch: unknown argument '$1'" >&2; exit 2 ;;
  esac
done

[ -n "$repo" ] || { echo "protect-branch: --repo owner/name is required" >&2; exit 2; }
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "protect-branch: --repo must look like owner/name" >&2; exit 2; }
[[ "$approvals" =~ ^[0-6]$ ]] || { echo "protect-branch: --approvals must be a number from 0 to 6 (got '$approvals')" >&2; exit 2; }
if [ "$approvals" -ge 1 ]; then code_owners=true; else code_owners=false; fi
owner="${repo%%/*}"

# Required checks: top-level job ids of validate.yml minus OPTIONAL_JOBS.
checks=()
while IFS= read -r j; do
  case " $OPTIONAL_JOBS " in *" $j "*) continue ;; esac
  checks+=("$j")
done < <(awk '/^jobs:/ {in_jobs=1; next} in_jobs && /^[^ #]/ {in_jobs=0} in_jobs && /^  [A-Za-z0-9_-]+:/ {sub(/^  /, ""); sub(/:.*/, ""); print}' \
  "$ROOT/.github/workflows/validate.yml")
[ "${#checks[@]}" -gt 0 ] || { echo "protect-branch: no jobs found in validate.yml" >&2; exit 2; }
checks_json="["
for c in "${checks[@]}"; do checks_json="$checks_json\"$c\", "; done
checks_json="${checks_json%, }]"

if [ "$dry" -eq 1 ]; then
  owner_id="\"<id of $owner: gh api users/$owner --jq .id>\""
else
  command -v gh > /dev/null 2>&1 || { echo "protect-branch: gh not found on PATH" >&2; exit 2; }
  owner_id="$(gh api "users/$owner" --jq .id)"
fi

protection="$(cat << JSON
{
  "required_status_checks": { "strict": true, "contexts": $checks_json },
  "enforce_admins": $enforce_admins,
  "required_pull_request_reviews": { "required_approving_review_count": $approvals, "require_code_owner_reviews": $code_owners, "dismiss_stale_reviews": true },
  "restrictions": null
}
JSON
)"

# RepositoryRole 5 is the built-in admin role: only admins can create, move or delete v* tags.
ruleset='{
  "name": "release-tags",
  "target": "tag",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/tags/v*"], "exclude": [] } },
  "rules": [ { "type": "creation" }, { "type": "update" }, { "type": "deletion" } ],
  "bypass_actors": [ { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" } ]
}'

# Read-only lookups that make re-runs idempotent (before the first run they find nothing).
tag_policy_id=""
ruleset_id=""
if [ "$dry" -eq 0 ]; then
  tag_policy_id="$(gh api "repos/$repo/environments/release/deployment-branch-policies" \
    --jq '.branch_policies[] | select(.type == "tag" and .name == "v*") | .id' 2> /dev/null || true)"
  if [ "$protect_tags" -eq 1 ]; then
    if ! ruleset_id="$(gh api "repos/$repo/rulesets" --jq '.[] | select(.name == "release-tags") | .id' 2>&1)"; then
      echo "protect-branch: rulesets are not available for $repo (gh said: $ruleset_id)." >&2
      echo "protect-branch: rulesets need a public repository or a paid plan, and admin rights. Nothing was changed." >&2
      echo "protect-branch: re-run with --no-protect-tags to skip the tag ruleset (v* tags are then unprotected)." >&2
      exit 1
    fi
  fi
fi

call() { # <json body> <gh api args...>: print the call in dry-run, execute it otherwise
  local body="$1"; shift
  if [ "$dry" -eq 1 ]; then
    echo "gh api $* --input - <<'JSON'"
    echo "$body"
    echo "JSON"
  else
    echo "$body" | gh api "$@" --input - > /dev/null
  fi
}

if [ "$dry" -eq 1 ]; then echo "# dry run: nothing is executed"; echo "# required status checks: ${checks[*]}"; fi
call "$protection" --method PUT "repos/$repo/branches/$branch/protection"

call "{ \"reviewers\": [ { \"type\": \"User\", \"id\": $owner_id } ], \"deployment_branch_policy\": { \"protected_branches\": false, \"custom_branch_policies\": true } }" \
  --method PUT "repos/$repo/environments/release"
if [ -z "$tag_policy_id" ]; then
  call '{ "name": "v*", "type": "tag" }' --method POST "repos/$repo/environments/release/deployment-branch-policies"
fi

if [ "$protect_tags" -eq 0 ]; then
  echo "protect-branch: WARNING: --no-protect-tags: anyone with write access can push a v* tag and trigger a release" >&2
else
  if [ "$dry" -eq 1 ]; then
    echo "# release-tags: POST creates it; a re-run updates the existing ruleset with PUT repos/$repo/rulesets/<id>"
  fi
  if [ -n "$ruleset_id" ]; then
    call "$ruleset" --method PUT "repos/$repo/rulesets/$ruleset_id"
  else
    call "$ruleset" --method POST "repos/$repo/rulesets"
  fi
fi

# Read back what was applied and fail loudly when something is missing. A first run once left the
# release Environment with "selected tags" turned on but no tag policy, which blocks every release
# without any error. GitHub may need a moment after creating the Environment, so retry the policy
# (re-posting it once) before failing.
if [ "$dry" -eq 0 ]; then
  verify_failed=0
  policy_ok() {
    gh api "repos/$repo/environments/release/deployment-branch-policies" \
      --jq '[.branch_policies[] | select(.type == "tag" and .name == "v*")] | length' 2> /dev/null
  }
  n=0
  attempt=0
  while [ "$attempt" -lt 4 ]; do
    n="$(policy_ok || echo 0)"
    [ "$n" = "1" ] && break
    attempt=$((attempt + 1))
    sleep "${PROTECT_VERIFY_SLEEP:-3}"
    if [ "$attempt" -eq 2 ]; then
      echo '{ "name": "v*", "type": "tag" }' |
        gh api --method POST "repos/$repo/environments/release/deployment-branch-policies" --input - > /dev/null 2>&1 || true
    fi
  done
  if [ "$n" != "1" ]; then
    echo "protect-branch: FAILED to verify: environment 'release' has no v* tag policy; releases would be rejected" >&2
    verify_failed=1
  fi
  if [ "$protect_tags" -eq 1 ]; then
    state="$(gh api "repos/$repo/rulesets" --jq '[.[] | select(.name == "release-tags" and .enforcement == "active" and .target == "tag")] | length' 2> /dev/null || echo 0)"
    if [ "$state" != "1" ]; then
      echo "protect-branch: FAILED to verify: no active tag ruleset 'release-tags'; v* tags would be unprotected" >&2
      verify_failed=1
    fi
  fi
  want_state="true $(printf '%s\n' "${checks[@]}" | sort | paste -sd, -)"
  if ! got_state="$(gh api "repos/$repo/branches/$branch/protection" \
    --jq '"\(.required_status_checks.strict) \(.required_status_checks.contexts | sort | join(","))"' 2> /dev/null)"; then
    echo "protect-branch: FAILED to verify: no branch protection on $branch" >&2
    verify_failed=1
  elif [ "$got_state" != "$want_state" ]; then
    echo "protect-branch: FAILED to verify: required checks are '$got_state' (strict, contexts), want '$want_state'" >&2
    verify_failed=1
  fi
  [ "$verify_failed" -eq 0 ] || exit 1
  echo "protect-branch: verified: branch protection, release tag policy$([ "$protect_tags" -eq 1 ] && echo ", tag ruleset")" >&2
fi
