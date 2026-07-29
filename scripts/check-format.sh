#!/bin/sh

set -eu

unformatted=$(
	find . -type f -name '*.go' -not -path './vendor/*' -print |
		while IFS= read -r file; do
			gofmt -l "$file"
		done
)

if [ -n "$unformatted" ]; then
	printf '%s\n' "The following Go files need formatting:" >&2
	printf '%s\n' "$unformatted" >&2
	exit 1
fi
