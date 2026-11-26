#!/bin/sh
set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH
fail() { echo "asm: $*" >&2; exit 126; }
[ "$#" -eq 1 ] || fail "usage: status UNIT"
case "$1" in *[!A-Za-z0-9@._-]*) fail "invalid unit" ;; esac
printf '%s\n' "$1" | grep -Eqx '[A-Za-z0-9][A-Za-z0-9@._-]{0,120}\.service' || fail "invalid unit"
# Not `systemctl status`: its process tree shows command lines, which may hold secrets.
exec systemctl show --no-pager -p Id -p Description -p LoadState -p ActiveState -p SubState -p UnitFileState \
  -p Result -p MainPID -p ExecMainStatus -p NRestarts -p ActiveEnterTimestamp -- "$1"
