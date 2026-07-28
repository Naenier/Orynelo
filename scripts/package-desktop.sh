#!/bin/sh

set -eu

usage() {
	printf '%s\n' \
		"Usage: scripts/package-desktop.sh <linux|darwin> <executable> <version> <build> <output.tar.gz>" \
		"" \
		"Package a prebuilt OpsDoctor desktop binary with Fyne metadata and icon." \
		"Set FYNE_PACKAGE_TOOL to the pinned fyne executable when it is not on PATH."
}

if [ "$#" -ne 5 ]; then
	usage >&2
	exit 2
fi

target=$1
executable=$2
version=$3
build=$4
output=$5

case "$target" in
linux|darwin)
	;;
*)
	printf '%s\n' "unsupported desktop package target: $target" >&2
	exit 2
	;;
esac

case "$build" in
""|*[!0-9]*|0)
	printf '%s\n' "application build must be a positive integer" >&2
	exit 2
	;;
esac

if [ -z "$version" ]; then
	printf '%s\n' "application version must not be empty" >&2
	exit 2
fi

case "$executable" in
/*)
	;;
*)
	executable=$PWD/$executable
	;;
esac

if [ ! -f "$executable" ]; then
	printf '%s\n' "desktop executable not found: $executable" >&2
	exit 1
fi

script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd)
project_root=$(CDPATH='' cd "$script_dir/.." && pwd)
icon="$project_root/assets/Icon.png"
fyne_package_tool=${FYNE_PACKAGE_TOOL:-fyne}

if [ ! -f "$icon" ]; then
	printf '%s\n' "desktop package icon not found: $icon" >&2
	exit 1
fi
case "$fyne_package_tool" in
*/*)
	;;
*)
	resolved_fyne_package_tool=$(command -v "$fyne_package_tool" || true)
	if [ -n "$resolved_fyne_package_tool" ]; then
		fyne_package_tool=$resolved_fyne_package_tool
	fi
	;;
esac
if [ ! -x "$fyne_package_tool" ]; then
	printf '%s\n' "Fyne package tool is not executable: $fyne_package_tool" >&2
	exit 1
fi

output_dir=$(dirname "$output")
output_name=$(basename "$output")
mkdir -p "$output_dir"
output_dir=$(CDPATH='' cd "$output_dir" && pwd)
output=$output_dir/$output_name

work_dir=$(mktemp -d)
cleanup() {
	rm -rf "$work_dir"
}
trap cleanup EXIT HUP INT TERM

stage=$work_dir/stage
mkdir -p "$stage"

(
	cd "$work_dir"
	"$fyne_package_tool" package \
		--target "$target" \
		--source-dir "$project_root/cmd/opsdoctor-desktop" \
		--executable "$executable" \
		--name OpsDoctor \
		--icon "$icon" \
		--app-id io.github.naenier.opsdoctor \
		--app-version "$version" \
		--app-build "$build" \
		--release
)

case "$target" in
linux)
	native_archive=$work_dir/OpsDoctor.tar.xz
	if [ ! -s "$native_archive" ]; then
		printf '%s\n' "Fyne did not create the expected Linux package" >&2
		exit 1
	fi
	tar -xJf "$native_archive" -C "$stage"

	packaged_binary=$stage/opsdoctor-desktop/usr/local/bin/opsdoctor-desktop
	desktop_entry=$stage/opsdoctor-desktop/usr/local/share/applications/io.github.naenier.opsdoctor.desktop
	packaged_icon=$stage/opsdoctor-desktop/usr/local/share/pixmaps/io.github.naenier.opsdoctor.png
	if [ ! -f "$desktop_entry" ] || [ ! -f "$packaged_icon" ]; then
		printf '%s\n' "Fyne Linux package is missing desktop metadata or icon" >&2
		exit 1
	fi
	;;
darwin)
	app=$work_dir/OpsDoctor.app
	if [ ! -d "$app" ]; then
		printf '%s\n' "Fyne did not create the expected macOS application bundle" >&2
		exit 1
	fi
	mv "$app" "$stage/OpsDoctor.app"
	app=$stage/OpsDoctor.app
	plist=$app/Contents/Info.plist
	plutil -replace LSApplicationCategoryType \
		-string public.app-category.utilities "$plist"
	plutil -replace LSMinimumSystemVersion -string 12.0 "$plist"
	plutil -lint "$plist"

	packaged_binary=$app/Contents/MacOS/opsdoctor-desktop
	packaged_icon=$app/Contents/Resources/icon.icns
	if [ ! -f "$packaged_icon" ]; then
		printf '%s\n' "Fyne macOS package is missing its native icon" >&2
		exit 1
	fi
	;;
esac

if ! cmp -s "$executable" "$packaged_binary"; then
	printf '%s\n' "Fyne package did not preserve the prebuilt desktop binary" >&2
	exit 1
fi

cp "$project_root/LICENSE" "$project_root/README.md" "$stage/"
tar -czf "$output" -C "$stage" .

if [ ! -s "$output" ]; then
	printf '%s\n' "desktop package archive was not created: $output" >&2
	exit 1
fi

printf '%s\n' "$output"
