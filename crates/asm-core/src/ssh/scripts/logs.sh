#!/bin/sh
set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH
fail() { echo "asm: $*" >&2; exit 126; }
{ [ "$#" -eq 2 ] || [ "$#" -eq 3 ]; } || fail "usage: logs UNIT [LINES] [--since WHEN]"
case "$1" in *[!A-Za-z0-9@._-]*) fail "invalid unit" ;; esac
printf '%s\n' "$1" | grep -Eqx '[A-Za-z0-9][A-Za-z0-9@._-]{0,120}\.service' || fail "invalid unit"
case "$2" in ''|*[!0-9]*) fail "LINES must be a number" ;; esac
{ [ "$2" -ge 1 ] && [ "$2" -le 10000 ]; } || fail "LINES must be 1-10000"
[ "$#" -eq 2 ] && exec journalctl --no-pager -q -o short-iso -u "$1" -n "$2"
# WHEN: 30m (relative: s, m, h, d) or 2026-11-25[T10:00[:00]][Z] (absolute, host time or UTC).
when=$3
case "$when" in *[!0-9smhdTZ:-]*) fail "WHEN must look like 30m, 2h, 1d or 2026-11-25T10:00" ;; esac
if printf '%s\n' "$when" | grep -Eqx '[0-9]{1,6}[smhd]'; then
  case "$when" in
    *s) since="-${when%s}s" ;;
    *m) since="-${when%m}min" ;;
    *h) since="-${when%h}h" ;;
    *) since="-${when%d}d" ;;
  esac
elif printf '%s\n' "$when" | grep -Eqx '[0-9]{4}-[0-9]{2}-[0-9]{2}(T[0-9]{2}:[0-9]{2}(:[0-9]{2})?)?Z?'; then
  since=$(printf '%s\n' "$when" | sed -e 's/T/ /' -e 's/Z$/ UTC/')
else
  fail "WHEN must look like 30m, 2h, 1d or 2026-11-25T10:00"
fi
exec journalctl --no-pager -q -o short-iso -u "$1" -n "$2" --since="$since"
