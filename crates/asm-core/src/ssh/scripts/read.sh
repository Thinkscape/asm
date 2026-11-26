#!/bin/sh
set -u
set -f
PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH
fail() { echo "asm: $*" >&2; exit 126; }
[ "$#" -eq 1 ] || fail "usage: read PATH"
# The grammar of asm_proto::ssh::validate_read_path: absolute, at most 255 bytes,
# components of [A-Za-z0-9._@+-] that are neither empty, "." nor "..".
p=$1
[ "${#p}" -le 255 ] || fail "invalid file"
case "$p" in /*) ;; *) fail "invalid file" ;; esac
case "$p" in *[!A-Za-z0-9._@+/-]*|*//*|*/|*/./*|*/../*|*/.|*/..) fail "invalid file" ;; esac
# Only root may change the directories on the way, so nobody else can swap the file
# between these checks and the read.
d=$(dirname "$p")
while :; do
  { [ -d "$d" ] && [ ! -L "$d" ] && [ "$(stat -c %u "$d" 2>/dev/null)" = 0 ]; } \
    || fail "$p is not in a directory only root can write; asm can't read it safely"
  case "$(stat -c %A "$d" 2>/dev/null)" in
    ?????w????|????????w?) fail "$p is not in a directory only root can write; asm can't read it safely" ;;
  esac
  [ "$d" = / ] && break
  d=$(dirname "$d")
done
[ -f "$p" ] && [ ! -L "$p" ] || fail "$p is not a regular file"
# Files of kernel and other virtual filesystems may block, change as they are read, or
# act on a read. GNU stat names devtmpfs "tmpfs"; /dev holds no regular files anyway.
fs=$(stat -f -c %T "$p" 2>/dev/null) || fail "cannot check the filesystem of $p"
case "$fs" in
  proc|sysfs|devtmpfs|devpts|debugfs|tracefs|securityfs|cgroupfs|cgroup2fs|configfs|efivarfs|bpf_fs|pstorefs|fusectl)
    fail "$p is on a virtual filesystem; asm can't read it safely" ;;
esac
size=$(stat -c %s "$p" 2>/dev/null) || fail "$p is not a regular file"
timeout 10 head -c 1048576 "$p" || fail "cannot read $p"
[ "$size" -le 1048576 ] || echo "asm: showing the first 1 MiB of $size bytes" >&2
exit 0
