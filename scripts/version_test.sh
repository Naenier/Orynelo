#!/bin/sh

set -eu

unset CDPATH
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
project_root=$(cd -- "$script_dir/.." && pwd)
version_script="$script_dir/version.sh"
test_root=$(mktemp -d)

cleanup() {
	rm -rf -- "$test_root"
}
trap cleanup EXIT HUP INT TERM

assert_equal() {
	expected=$1
	actual=$2
	label=$3
	if [ "$actual" != "$expected" ]; then
		printf '%s\n' "$label: got '$actual', want '$expected'" >&2
		exit 1
	fi
}

cd "$test_root"
git init -q
git config user.name "OpsDoctor Version Test"
git config user.email "version-test@localhost"
printf '%s\n' "initial" > tracked.txt
git add tracked.txt
git commit -qm "chore: initialize"
sha=$(git rev-parse --short=7 HEAD)

local_version=$("$version_script")
assert_equal "0.1.0-dev+g${sha}" "$local_version" "local build"
assert_equal "0.1.0" "$("$version_script" --base)" "initial base version"

printf '%s\n' "dirty" >> tracked.txt
dirty_version=$("$version_script")
assert_equal "0.1.0-dev+g${sha}.dirty" "$dirty_version" "dirty local build"
git restore tracked.txt

printf '%s\n' "untracked" > untracked.txt
untracked_version=$("$version_script")
assert_equal "0.1.0-dev+g${sha}.dirty" "$untracked_version" "untracked local build"
rm -- untracked.txt

branch_version=$(
	GITHUB_ACTIONS=true GITHUB_EVENT_NAME=push GITHUB_RUN_NUMBER=143 \
		"$version_script"
)
assert_equal "0.1.0-dev.143+g${sha}" "$branch_version" "branch build"

pr_version=$(
	GITHUB_ACTIONS=true GITHUB_EVENT_NAME=pull_request GITHUB_RUN_NUMBER=143 \
		PR_NUMBER=17 "$version_script"
)
assert_equal "0.1.0-pr.17.143+g${sha}" "$pr_version" "pull request build"

ref_pr_version=$(
	GITHUB_ACTIONS=true GITHUB_EVENT_NAME=pull_request GITHUB_RUN_NUMBER=144 \
		GITHUB_REF=refs/pull/18/merge PR_NUMBER='' "$version_script"
)
assert_equal "0.1.0-pr.18.144+g${sha}" "$ref_pr_version" "pull request ref build"

if GITHUB_ACTIONS=true GITHUB_EVENT_NAME=pull_request GITHUB_RUN_NUMBER=143 \
	PR_NUMBER=not-a-number "$version_script" >/dev/null 2>&1; then
	printf '%s\n' "invalid pull request number was accepted" >&2
	exit 1
fi

if GITHUB_ACTIONS=true GITHUB_EVENT_NAME=push GITHUB_RUN_NUMBER=not-a-number \
	"$version_script" >/dev/null 2>&1; then
	printf '%s\n' "invalid GitHub run number was accepted" >&2
	exit 1
fi

oci_version=$(
	GITHUB_ACTIONS=true GITHUB_EVENT_NAME=pull_request GITHUB_RUN_NUMBER=143 \
		PR_NUMBER=17 "$version_script" --oci
)
assert_equal "0.1.0-pr-17-143-g${sha}" "$oci_version" "OCI build"

git tag v0.2.1
release_version=$(GITHUB_ACTIONS=true GITHUB_EVENT_NAME=push "$version_script")
assert_equal "0.2.1" "$release_version" "exact release"
assert_equal "0.2.1" "$("$version_script" --base)" "tagged base version"

printf '%s\n' "next" >> tracked.txt
git add tracked.txt
git commit -qm "feat: next"
next_sha=$(git rev-parse --short=7 HEAD)
next_version=$("$version_script")
assert_equal "0.2.1-dev+g${next_sha}" "$next_version" "post-release local build"

snapshot_command=$(
	make --no-print-directory --dry-run -C "$project_root" snapshot \
		VERSION="$next_version" GORELEASER=goreleaser
)
assert_equal \
	"OPSDOCTOR_VERSION=\"$next_version\" goreleaser release --snapshot --clean" \
	"$snapshot_command" \
	"GoReleaser snapshot version handoff"

printf '%s\n' "version tests passed"
