#!/bin/sh

set -eu

if [ "$#" -ne 1 ]; then
	printf '%s\n' "Usage: scripts/checksums.sh <artifact-directory>" >&2
	exit 2
fi

artifact_dir=$1
if [ ! -d "$artifact_dir" ]; then
	printf '%s\n' "artifact directory does not exist: $artifact_dir" >&2
	exit 1
fi

output="$artifact_dir/checksums.txt"
temporary="$artifact_dir/.checksums.tmp"

(
	cd "$artifact_dir"
	find . -type f \
		! -name 'checksums.txt' \
		! -name '.checksums.tmp' \
		-print0 |
		LC_ALL=C sort -z |
		xargs -0 --no-run-if-empty sha256sum
) >"$temporary"

mv "$temporary" "$output"
