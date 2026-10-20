#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

script=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/verify-dco.sh
scratch_root=$(cd "${TMPDIR:-/tmp}" && pwd -P)
fixture=$(mktemp -d "$scratch_root/scoplen-dco.XXXXXXXX")
cleanup() {
  if [[ "$fixture" == "$scratch_root"/scoplen-dco.* && -d "$fixture" ]]; then
    rm -rf -- "$fixture"
  fi
}
trap cleanup EXIT

git init -q "$fixture"
cd "$fixture"
git symbolic-ref HEAD refs/heads/main
export GIT_AUTHOR_NAME='DCO fixture' GIT_AUTHOR_EMAIL='dco@example.com'
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
signed() {
  git -c commit.gpgsign=false commit -q -s --allow-empty -m "$1"
}
unsigned() {
  git -c commit.gpgsign=false commit -q --allow-empty -m "$1"
}
expect_rejected() {
  local description=$1
  if bash "$script" >/dev/null 2>&1; then
    printf '%s was accepted\n' "$description" >&2
    exit 1
  fi
}
expect_unsigned() {
  local description=$1 commit=$2 result
  if result=$(bash "$script" 2>&1); then
    printf '%s accepted unsigned commit %s\n' "$description" "$commit" >&2
    exit 1
  fi
  if [[ "$result" != *"$commit"* ]]; then
    printf '%s rejected for the wrong reason: %s\n' "$description" "$result" >&2
    exit 1
  fi
}

unsigned 'legacy imported history'
signed 'signed import snapshot'
export DCO_IMPORT_BASELINE
DCO_IMPORT_BASELINE=$(git rev-parse HEAD)
export HEAD_SHA="$DCO_IMPORT_BASELINE"
export EVENT_NAME=push BEFORE_SHA=0000000000000000000000000000000000000000
export DEFAULT_BRANCH=main PUSH_REF=refs/heads/main
bash "$script"

unsigned 'published unsigned historical merge'
historical=$(git rev-parse HEAD)
HEAD_SHA=$historical
expect_unsigned 'initial default-branch push' "$historical"
git update-ref refs/remotes/origin/main "$historical"

git switch -q -c signed-topic
signed 'signed branch contribution'
signed_tip=$(git rev-parse HEAD)
HEAD_SHA=$signed_tip PUSH_REF=refs/heads/signed-topic
bash "$script"
EVENT_NAME=pull_request BASE_SHA=$historical bash "$script"

unsigned 'unsigned intermediate contribution'
unsigned_intermediate=$(git rev-parse HEAD)
signed 'signed branch tip'
HEAD_SHA=$(git rev-parse HEAD)
expect_unsigned 'new branch' "$unsigned_intermediate"
EVENT_NAME=pull_request BASE_SHA=$historical expect_unsigned 'pull request' "$unsigned_intermediate"
BEFORE_SHA=$signed_tip expect_unsigned 'later push' "$unsigned_intermediate"
EVENT_NAME=pull_request BASE_SHA=$unsigned_intermediate bash "$script"
BEFORE_SHA=$unsigned_intermediate bash "$script"

git switch -q main
signed 'default branch advanced after topic forked'
advanced_main=$(git rev-parse HEAD)
git update-ref refs/remotes/origin/main "$advanced_main"
git switch -q -c lagging-topic "$historical"
signed 'signed contribution from older main'
HEAD_SHA=$(git rev-parse HEAD)
BEFORE_SHA=0000000000000000000000000000000000000000
[[ $(git merge-base refs/remotes/origin/main "$HEAD_SHA") == "$historical" ]]
bash "$script"
EVENT_NAME=pull_request BASE_SHA=$advanced_main bash "$script"

git switch -q -c unsigned-side "$historical"
unsigned 'unsigned side contribution'
unsigned_side=$(git rev-parse HEAD)
git switch -q -c merge-topic "$historical"
signed 'signed merge topic'
git -c commit.gpgsign=false merge -q --no-ff --no-edit --signoff unsigned-side
HEAD_SHA=$(git rev-parse HEAD)
PUSH_REF=refs/heads/merge-topic
merge_signoff=$(git show -s --format='%(trailers:key=Signed-off-by,valueonly)' "$HEAD_SHA")
if [[ "$merge_signoff" != 'DCO fixture <dco@example.com>' ]]; then
  printf 'merge fixture was not signed off: %s\n' "$HEAD_SHA" >&2
  exit 1
fi
expect_unsigned 'signed merge with unsigned side' "$unsigned_side"

git update-ref -d refs/remotes/origin/main
expect_rejected 'new branch without fetched default branch'
git update-ref refs/remotes/origin/main "$advanced_main"
BEFORE_SHA=1111111111111111111111111111111111111111
expect_rejected 'invalid later-push base'

printf 'DCO event-range regression checks passed\n'
