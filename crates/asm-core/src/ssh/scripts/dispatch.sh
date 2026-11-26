#!/bin/sh
set -u
set -f
PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH
LIB=/usr/lib/asm-ssh
fail() { echo "asm: $*" >&2; exit 126; }
interactive() { fail "interactive login is not allowed; run: logs UNIT [LINES] [--since WHEN] | status UNIT | restart UNIT | reload UNIT | read PATH"; }
[ "$#" -eq 2 ] && [ "$1" = "-c" ] || interactive
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
[ -n "${SSH_ORIGINAL_COMMAND+x}" ] || interactive
granted() { for g in $grants; do [ "$g" = "$1" ] && return 0; done; return 1; }
# The grammar of asm_proto::ssh::validate_unit, validate_read_path and WHEN. Each value
# is one word of the command, so it holds no space or newline.
unit_ok() { printf '%s\n' "$1" | grep -Eqx '[A-Za-z0-9][A-Za-z0-9@._-]{0,120}\.service'; }
path_ok() {
  [ "${#1}" -le 255 ] || return 1
  case "$1" in /*) ;; *) return 1 ;; esac
  case "$1" in *[!A-Za-z0-9._@+/-]*|*//*|*/|*/./*|*/../*|*/.|*/..) return 1 ;; esac
}
when_ok() {
  printf '%s\n' "$1" | grep -Eqx '[0-9]{1,6}[smhd]|[0-9]{4}-[0-9]{2}-[0-9]{2}(T[0-9]{2}:[0-9]{2}(:[0-9]{2})?)?Z?'
}
set -- $SSH_ORIGINAL_COMMAND
op=${1:-}
case "$op" in
  logs)
    usage="usage: logs UNIT [LINES] [--since WHEN]"
    { [ "$#" -ge 2 ] && [ "$#" -le 5 ]; } || fail "$usage"
    unit=$2; shift 2
    unit_ok "$unit" || fail "invalid unit"
    granted "logs:$unit" || fail "logs of $unit not granted"
    lines=; since=
    while [ "$#" -gt 0 ]; do
      if [ "$1" = --since ]; then
        { [ "$#" -ge 2 ] && [ -z "$since" ]; } || fail "$usage"
        when_ok "$2" || fail "WHEN must look like 30m, 2h, 1d or 2026-11-25T10:00"
        since=$2; shift 2
      else
        [ -z "$lines" ] || fail "$usage"
        lines=$1; shift
      fi
    done
    lines=${lines:-200}
    case "$lines" in ''|*[!0-9]*) fail "LINES must be a number" ;; esac
    { [ "$lines" -ge 1 ] && [ "$lines" -le 10000 ]; } || fail "LINES must be 1-10000" ;;
  status|restart|reload)
    [ "$#" -eq 2 ] || fail "usage: $op UNIT"
    unit=$2
    unit_ok "$unit" || fail "invalid unit"
    if [ "$op" = status ]; then
      granted "logs:$unit" || granted "restart:$unit" || granted "reload:$unit" || fail "status of $unit not granted"
    else
      granted "$op:$unit" || fail "$op of $unit not granted"
    fi ;;
  read)
    [ "$#" -eq 2 ] || fail "usage: read PATH"
    file=$2
    path_ok "$file" || fail "invalid file"
    granted "read:$file" || fail "read of $file not granted" ;;
  *) fail "unknown operation; allowed: logs, status, restart, reload, read" ;;
esac
# Record this session before doing anything, so the lease's end can end it.
r=$(sudo -n "$LIB/asm-end-lease" register "$lease" "$until" - 2>&1) || { m=${r##*asm-end-error }; fail "${m#* }"; }
if [ "$op" = read ]; then what="path=$file"; else what="unit=$unit"; fi
logger -p authpriv.notice -t asm-dispatch "lease=$lease op=$op $what" 2>/dev/null
case "$op" in
  logs) exec sudo -n "$LIB/asm-logs" "$unit" "$lines" ${since:+"$since"} ;;
  status) exec sudo -n "$LIB/asm-status" "$unit" ;;
  read) exec sudo -n "$LIB/asm-read" "$file" ;;
esac
exec sudo -n "$(command -v systemctl)" "$op" "$unit"
