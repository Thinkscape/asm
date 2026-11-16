#!/bin/sh
# Package one `asm` CLI build as a release tarball and, for Linux, as nfpm packages.
#
#   packaging/package-cli.sh <target> <binary> <version> <outdir>
#
# <target>   linux-x86_64 | linux-aarch64 | macos-universal
# <binary>   the built `asm` executable for that target
# <version>  version without the leading "v", e.g. 0.1.0
# <outdir>   receives asm-<target>.tar.gz and, for Linux targets,
#            asm-<target>.deb, .rpm, .apk and .pkg.tar.zst (needs nfpm on PATH)
#
# Run from the repository root. Asset names carry no version so that
# https://github.com/Thinkscape/asm/releases/latest/download/<asset> always works.
set -eu

[ $# -eq 4 ] || { echo "usage: $0 <target> <binary> <version> <outdir>" >&2; exit 2; }
target=$1 binary=$2 version=$3 outdir=$4

case "$target" in
    linux-x86_64) nfpm_arch=amd64 ;;
    linux-aarch64) nfpm_arch=arm64 ;;
    macos-universal) nfpm_arch= ;;
    *) echo "unknown target: $target" >&2; exit 2 ;;
esac
[ -x "$binary" ] || { echo "not an executable: $binary" >&2; exit 2; }

mkdir -p "$outdir"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT INT TERM

dir="$stage/asm-$target"
mkdir -p "$dir/skill/asm"
cp "$binary" "$dir/asm"
chmod 0755 "$dir/asm"
cp README.md LICENSE "$dir/"
cp skill/asm/SKILL.md "$dir/skill/asm/SKILL.md"
# COPYFILE_DISABLE and --no-xattrs keep macOS tar from adding AppleDouble (._*) entries and
# extended attributes (com.apple.provenance) that GNU tar warns about.
COPYFILE_DISABLE=1 tar --no-xattrs -C "$stage" -czf "$outdir/asm-$target.tar.gz" "asm-$target"
echo "created $outdir/asm-$target.tar.gz"

[ -n "$nfpm_arch" ] || exit 0

mkdir -p dist/nfpm
cp "$binary" dist/nfpm/asm
for packager in deb rpm apk archlinux; do
    case "$packager" in
        archlinux) ext=pkg.tar.zst ;;
        *) ext=$packager ;;
    esac
    ASM_VERSION=$version NFPM_ARCH=$nfpm_arch \
        nfpm package --config packaging/nfpm.yaml --packager "$packager" \
        --target "$outdir/asm-$target.$ext"
done
rm -f dist/nfpm/asm
