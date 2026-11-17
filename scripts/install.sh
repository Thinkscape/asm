#!/bin/sh
# Install the `asm` CLI (Agents Secrets Manager) from a GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/Thinkscape/asm/main/scripts/install.sh | sh
#
# Environment:
#   ASM_VERSION  release tag to install, e.g. v0.1.0 (default: the latest release)
#   PREFIX       install prefix (default: ~/.local); the binary goes to $PREFIX/bin/asm
#   ASM_REPO     GitHub repository (default: Thinkscape/asm)
#
# Afterwards it runs `asm skill install`, which writes the agent skill embedded in the binary to
# ~/.agents/skills/asm/SKILL.md (skipped under sudo, so root's home is not used).
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

mkdir -p "$prefix/bin"
# Install via a temp file and rename, so a running asm is never overwritten in place.
cp "$src/asm" "$prefix/bin/.asm.new"
chmod 0755 "$prefix/bin/.asm.new"
mv -f "$prefix/bin/.asm.new" "$prefix/bin/asm"

say "installed $("$prefix/bin/asm" --version) to $prefix/bin/asm"
if [ "$(id -u)" = 0 ] && [ -n "${SUDO_USER:-}" ]; then
    say "agent skill: run 'asm skill install' as $SUDO_USER (adds it to ~/.agents/skills)"
elif ! "$prefix/bin/asm" skill install >&2; then
    say "note: the agent skill was not installed; see the message above ('asm skill status' shows the state)"
fi
case ":$PATH:" in
    *":$prefix/bin:"*) ;;
    *) say "note: $prefix/bin is not on PATH; add it, e.g. export PATH=\"$prefix/bin:\$PATH\"" ;;
esac
say ""
say "next steps:"
say "  asm pair <manager-host>      # approve the code shown on the Mac, or pass a pairing code"
say "  asm doctor                   # every line should say ok"
say "  eval \"\$(asm proxy-env)\"      # point HTTP clients at the proxy"
say "  asm skill install --dir ~/.claude/skills   # also for agents reading another skill folder"
