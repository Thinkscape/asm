#!/bin/sh
# Render the Homebrew tap files for a release.
#
#   packaging/homebrew/render.sh <version> <SHA256SUMS> <tap-dir>
#
# Writes <tap-dir>/Formula/asm.rb and, when SHA256SUMS lists the app zip,
# <tap-dir>/Casks/asm-manager.rb. <version> has no leading "v".
set -eu

[ $# -eq 3 ] || { echo "usage: $0 <version> <SHA256SUMS> <tap-dir>" >&2; exit 2; }
version=$1 sums=$2 tap=$3
here=$(cd "$(dirname "$0")" && pwd)

sum_of() {
    awk -v f="$1" '$2 == f || $2 == "*" f { print $1; exit }' "$sums"
}
require() {
    s=$(sum_of "$1")
    [ -n "$s" ] || { echo "$1 is not listed in $sums" >&2; exit 1; }
    printf '%s' "$s"
}

macos=$(require asm-macos-universal.tar.gz)
x86_64=$(require asm-linux-x86_64.tar.gz)
aarch64=$(require asm-linux-aarch64.tar.gz)

mkdir -p "$tap/Formula"
sed -e "s/@VERSION@/$version/g" \
    -e "s/@SHA256_MACOS_UNIVERSAL@/$macos/" \
    -e "s/@SHA256_LINUX_X86_64@/$x86_64/" \
    -e "s/@SHA256_LINUX_AARCH64@/$aarch64/" \
    "$here/asm.rb.tmpl" >"$tap/Formula/asm.rb"
echo "wrote $tap/Formula/asm.rb"

app=$(sum_of Agents-Secrets-Manager-macos.zip)
if [ -n "$app" ]; then
    mkdir -p "$tap/Casks"
    sed -e "s/@VERSION@/$version/g" -e "s/@SHA256_APP_ZIP@/$app/" \
        "$here/asm-manager.rb.tmpl" >"$tap/Casks/asm-manager.rb"
    echo "wrote $tap/Casks/asm-manager.rb"
else
    echo "no app zip in $sums; cask not updated" >&2
fi
