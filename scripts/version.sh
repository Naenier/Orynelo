#!/bin/sh

set -eu

base_version_default="0.1.0"
output_kind="semver"

usage() {
	cat <<'USAGE'
Usage: scripts/version.sh [--oci|--base]

Print the build version without modifying tracked files.
  --oci   print an OCI-compatible image tag
  --base  print only the most recent release version, or 0.1.0
USAGE
}

require_unsigned_integer() {
	name=$1
	value=$2
	case "$value" in
	""|*[!0-9]*)
		printf '%s\n' "$name must be an unsigned integer" >&2
		exit 1
		;;
	esac
}

case "${1:-}" in
	"")
		;;
	--oci|--docker)
		output_kind="oci"
		;;
	--base)
		output_kind="base"
		;;
	-h|--help)
		usage
		exit 0
		;;
	*)
		usage >&2
		exit 2
		;;
esac

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	printf '%s\n' "version.sh must run inside a Git working tree" >&2
	exit 1
fi

exact_tag="$(
	git tag --points-at HEAD --sort=-version:refname 2>/dev/null |
		awk '/^v[0-9]+\.[0-9]+\.[0-9]+$/ { print; exit }'
)"

latest_tag="$(
	git tag --merged HEAD --sort=-version:refname 2>/dev/null |
		awk '/^v[0-9]+\.[0-9]+\.[0-9]+$/ { print; exit }'
)"

if [ -n "$latest_tag" ]; then
	base_version=${latest_tag#v}
else
	base_version=$base_version_default
fi

if [ "$output_kind" = "base" ]; then
	printf '%s\n' "$base_version"
	exit 0
fi

short_sha=$(git rev-parse --short=7 HEAD)

if [ -n "$exact_tag" ]; then
	calculated=${exact_tag#v}
elif [ "${GITHUB_EVENT_NAME:-}" = "pull_request" ] ||
	[ "${GITHUB_EVENT_NAME:-}" = "pull_request_target" ] ||
	[ -n "${PR_NUMBER:-}" ]; then
	pr_number=${PR_NUMBER:-}
	if [ -z "$pr_number" ]; then
		case "${GITHUB_REF:-}" in
		refs/pull/*/*)
			pr_number=$(printf '%s' "$GITHUB_REF" | cut -d/ -f3)
			;;
		esac
	fi
	if [ -z "$pr_number" ]; then
		printf '%s\n' "unable to determine pull request number" >&2
		exit 1
	fi
	run_number=${GITHUB_RUN_NUMBER:-0}
	require_unsigned_integer "pull request number" "$pr_number"
	require_unsigned_integer "GitHub run number" "$run_number"
	calculated="${base_version}-pr.${pr_number}.${run_number}+g${short_sha}"
elif [ "${GITHUB_ACTIONS:-}" = "true" ] || [ "${GITHUB_EVENT_NAME:-}" = "push" ]; then
	run_number=${GITHUB_RUN_NUMBER:-0}
	require_unsigned_integer "GitHub run number" "$run_number"
	calculated="${base_version}-dev.${run_number}+g${short_sha}"
else
	calculated="${base_version}-dev+g${short_sha}"
	if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
		calculated="${calculated}.dirty"
	fi
fi

if [ "$output_kind" = "oci" ]; then
	# OCI tags permit [A-Za-z0-9_.-], but replacing SemVer separators makes
	# generated tags easier to use consistently across registries.
	suffix=${calculated#"$base_version"}
	suffix=$(printf '%s' "$suffix" | sed 's/[^A-Za-z0-9_.-]/-/g; s/[.+]/-/g')
	calculated="${base_version}${suffix}"
fi

printf '%s\n' "$calculated"
