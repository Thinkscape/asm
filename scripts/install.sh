#!/bin/sh
# Install the `asm` CLI (Agents Secrets Manager) from a GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/Thinkscape/asm/main/scripts/install.sh | sh
#
# Environment:
#   ASM_VERSION  release tag to install, e.g. v0.1.0 (default: the latest release)
#   PREFIX       install prefix (default: ~/.local); the binary goes to $PREFIX/bin/asm and
#                the agent skill to $PREFIX/share/asm/skill/asm/SKILL.md
#   ASM_REPO     GitHub repository (default: Thinkscape/asm)
set -eu

repo=${ASM_REPO:-Thinkscape/asm}
version=${ASM_VERSION:-latest}
prefix=${PREFIX:-$HOME/.local}

say() { printf '%s\n' "$*" >&2; }
die() { say "asm install: $*"; exit 1; }

case "$(uname -s)" in
    Linux)
        case "$(uname -m)" in
            x86_64 | amd64) target=linux-x86_64 ;;
            aarch64 | arm64) target=linux-aarch64 ;;
            *) die "unsupported Linux architecture: $(uname -m) (x86_64 and aarch64 are available)" ;;
        esac
        ;;
    Darwin) target=macos-universal ;;
    *) die "unsupported OS: $(uname -s) (Linux and macOS are available)" ;;
esac

if [ "$version" = latest ]; then
    base="https://github.com/$repo/releases/latest/download"
else
    base="https://github.com/$repo/releases/download/$version"
fi
archive="asm-$target.tar.gz"

if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -q -O "$2" "$1"; }
else
    die "curl or wget is required"
fi

if command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum "$1" | cut -d ' ' -f 1; }
elif command -v shasum >/dev/null 2>&1; then
    sha256() { shasum -a 256 "$1" | cut -d ' ' -f 1; }
else
    die "sha256sum or shasum is required to verify the download"
fi

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t asm-install)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "downloading $base/$archive"
fetch "$base/$archive" "$tmp/$archive" || die "download failed: $base/$archive"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || die "download failed: $base/SHA256SUMS"

expected=$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp/SHA256SUMS")
[ -n "$expected" ] || die "$archive is not listed in SHA256SUMS"
actual=$(sha256 "$tmp/$archive")
[ "$expected" = "$actual" ] || die "checksum mismatch for $archive: expected $expected, got $actual"

tar -xzf "$tmp/$archive" -C "$tmp"
src="$tmp/asm-$target"
[ -f "$src/asm" ] || die "archive does not contain asm-$target/asm"

mkdir -p "$prefix/bin" "$prefix/share/asm/skill/asm"
# Install via a temp file and rename, so a running asm is never overwritten in place.
cp "$src/asm" "$prefix/bin/.asm.new"
chmod 0755 "$prefix/bin/.asm.new"
mv -f "$prefix/bin/.asm.new" "$prefix/bin/asm"
cp "$src/skill/asm/SKILL.md" "$prefix/share/asm/skill/asm/SKILL.md"

say "installed $("$prefix/bin/asm" --version) to $prefix/bin/asm"
say "agent skill: $prefix/share/asm/skill/asm/SKILL.md"
case ":$PATH:" in
    *":$prefix/bin:"*) ;;
    *) say "note: $prefix/bin is not on PATH; add it, e.g. export PATH=\"$prefix/bin:\$PATH\"" ;;
esac
say ""
say "next steps:"
say "  asm pair <manager-host>      # approve the code shown on the Mac, or pass a pairing code"
say "  asm doctor                   # every line should say ok"
say "  eval \"\$(asm proxy-env)\"      # point HTTP clients at the proxy"
