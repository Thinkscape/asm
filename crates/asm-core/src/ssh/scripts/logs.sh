#!/bin/sh
set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH
fail() { echo "asm: $*" >&2; exit 126; }
[ "$#" -eq 2 ] || fail "usage: logs UNIT [LINES]"
printf '%s\n' "$1" | grep -Eqx '[A-Za-z0-9][A-Za-z0-9@._-]{0,120}\.service' || fail "invalid unit"
case "$2" in ''|*[!0-9]*) fail "LINES must be a number" ;; esac
{ [ "$2" -ge 1 ] && [ "$2" -le 10000 ]; } || fail "LINES must be 1-10000"
exec journalctl --no-pager -q -o short-iso -u "$1" -n "$2"
