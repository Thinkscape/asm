#!/bin/sh
set -u
set -f
PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH
LIB=/usr/lib/asm-ssh
fail() { echo "asm: $*" >&2; exit 126; }
[ "$#" -eq 2 ] && [ "$1" = "-c" ] || fail "interactive login is not allowed; run: logs UNIT [LINES] | restart UNIT"
# The manager's cleanup login: its key line forces exactly this command.
if [ "$2" = asm-cleanup ]; then exec sudo -n "$LIB/asm-end-lease"; fi
set -- $2
[ "${1:-}" = asm-grant ] || fail "no asm grant"
case "${2:-}" in lease=*) lease=${2#lease=} ;; *) fail "no asm grant" ;; esac
case "${3:-}" in until=*) until=${3#until=} ;; *) fail "no asm grant" ;; esac
shift 3
grants="$*"
printf '%s\n' "$lease" | grep -Eqx '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' || fail "no asm grant"
case "$until" in ''|*[!0-9]*) fail "no asm grant" ;; esac
[ -n "$grants" ] || fail "no asm grant"
[ "$(date +%s)" -lt "$until" ] || fail "the SSH lease has ended"
[ -n "${SSH_ORIGINAL_COMMAND+x}" ] || fail "usage: logs UNIT [LINES] | restart UNIT"
granted() { for g in $grants; do [ "$g" = "$1" ] && return 0; done; return 1; }
unit_ok() { printf '%s\n' "$1" | grep -Eqx '[A-Za-z0-9][A-Za-z0-9@._-]{0,120}\.service'; }
set -- $SSH_ORIGINAL_COMMAND
case "${1:-}" in
  logs)
    { [ "$#" -eq 2 ] || [ "$#" -eq 3 ]; } || fail "usage: logs UNIT [LINES]"
    unit_ok "$2" || fail "invalid unit"
    granted "logs:$2" || fail "logs of $2 not granted"
    lines=${3:-200}
    case "$lines" in ''|*[!0-9]*) fail "LINES must be a number" ;; esac
    { [ "$lines" -ge 1 ] && [ "$lines" -le 10000 ]; } || fail "LINES must be 1-10000" ;;
  restart)
    [ "$#" -eq 2 ] || fail "usage: restart UNIT"
    unit_ok "$2" || fail "invalid unit"
    granted "restart:$2" || fail "restart of $2 not granted" ;;
  *) fail "unknown operation; allowed: logs, restart" ;;
esac
# Record this session before doing anything, so the lease's end can end it.
r=$(sudo -n "$LIB/asm-end-lease" register "$lease" "$until" - 2>&1) || { m=${r##*asm-end-error }; fail "${m#* }"; }
logger -p authpriv.notice -t asm-dispatch "lease=$lease op=$1 unit=$2" 2>/dev/null
if [ "$1" = logs ]; then exec sudo -n "$LIB/asm-logs" "$2" "$lines"; fi
exec sudo -n "$(command -v systemctl)" restart "$2"
