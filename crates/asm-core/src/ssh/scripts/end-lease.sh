#!/bin/sh
# asm-end-lease: records the sessions of asm SSH leases, and ends them.
#   register LEASE UNTIL TTY [USER]  asm-dispatch and asm-shell run this through sudo
#                             before a lease session does anything. It records the
#                             caller's systemd-logind session, refuses an ended lease and,
#                             for a login as USER, an account that changed since enrollment.
#   (no arguments)            asm-dispatch runs this through sudo for the manager's cleanup
#                             login. Reads one line: "end LEASE VALID_BEFORE" or "check".
#   --sweep                   asm-end-lease.timer: ends sessions past their lease's end or
#                             of ended leases, and warns lease terminals 10 and 2 minutes
#                             before the end.
#   --all                     asm-remove, which holds the lock: ends every lease session.
# State lives in /run/asm-ssh (root-only, gone at reboot like the sessions it describes):
#   sessions/<id>  lease=, user=, mono= (the session's start) and tty= of one logind session
#   leases/<id>    the latest end any login of that lease presented
#   ended          "<lease> <valid before>" for each lease the manager ended
set -u
set -f
PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH
umask 077
STATE=/var/lib/asm-ssh
RUN=/run/asm-ssh
UUID='[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
fail() { echo "asm-end-error $1 $2"; exit 3; }
[ "$(id -u)" = 0 ] || fail not-root "asm-end-lease must run as root"
[ -f "$STATE/manifest" ] || fail not-enrolled "asm is not installed on this host"
mf() { sed -n "s/^$1=//p" "$STATE/manifest" | head -n 1; }
ops=$(mf ops_uid); priv=$(mf priv_uid)
MODE=${1:-stdin}
case "$MODE" in register|stdin|--sweep|--all) ;; *) fail usage "unknown mode $MODE" ;; esac
NOW=$(date +%s)
{ [ -d "$RUN" ] || install -d -m 0700 -o root -g root "$RUN"; } && mkdir -p "$RUN/sessions" "$RUN/leases" \
  || fail io "cannot create $RUN"
[ "$MODE" = --all ] || { exec 9>>"$RUN/lock" && flock -w 30 9; } || fail busy "another asm operation is running on this host"
prop() { loginctl show-session "$1" -p "$2" --value 2>/dev/null; }
# own_session: the logind session of this process; sudo keeps the caller's session.
own_session() { sed -n 's|.*/session-\([A-Za-z0-9][A-Za-z0-9]*\)\.scope$|\1|p' /proc/$$/cgroup | head -n 1; }
is_ended() { grep -q "^$1 " "$RUN/ended" 2>/dev/null; }
@@ADMIN@@

if [ "$MODE" = register ]; then
  { [ "$#" -eq 4 ] || [ "$#" -eq 5 ]; } || fail usage "asm-end-lease register LEASE UNTIL TTY [USER]"
  lease=$2; until=$3; tty=$4; as=${5:-}
  printf '%s\n' "$lease" | grep -Eqx "$UUID" || fail usage "invalid lease id"
  printf '%s\n' "$until" | grep -Eqx '[0-9]{1,12}' || fail usage "invalid end time"
  [ -n "${SUDO_UID:-}" ] && { [ "$SUDO_UID" = "$ops" ] || [ "$SUDO_UID" = "$priv" ]; } \
    || fail usage "only asm-ops and asm-priv record sessions"
  user=$(getent passwd "$SUDO_UID" | cut -d: -f1)
  s=$(own_session)
  [ -n "$s" ] && [ "$(prop "$s" Name)" = "$user" ] && [ "$(prop "$s" Service)" = sshd ] \
    || fail no-session "this login has no systemd-logind session of $user"
  # A login as another user: the account must be the one enrollment recorded (user=
  # NAME:UID:ADMIN), and it may become root only if the operator chose it knowing that.
  if [ -n "$as" ]; then
    [ "$SUDO_UID" = "$priv" ] || fail usage "only asm-priv logs in as another user"
    printf '%s\n' "$as" | grep -Eqx '[a-z_][a-z0-9_-]{0,31}' || fail usage "invalid user"
    rec=$(sed -n 's/^user=//p' "$STATE/manifest" | awk -F: -v u="$as" '$1 == u' | head -n 1)
    [ -n "$rec" ] || fail user "this host does not allow access as $as"
    uid=${rec#*:}; uid=${uid%%:*}
    [ "$(id -u "$as" 2>/dev/null)" = "$uid" ] || fail user-changed "$as is not the account asm enrolled; the operator must enroll the target again"
    if [ "${rec##*:}" != 1 ]; then
      why=$(admin_why "$as")
      [ -z "$why" ] || fail user-admin "$as can now become root ($why); the operator must enroll the target again"
    fi
  fi
  case "$tty" in
    -) ;;
    /dev/pts/[0-9]*) [ "$(stat -c %u "$tty" 2>/dev/null)" = "$SUDO_UID" ] || tty=- ;;
    *) fail usage "invalid terminal" ;;
  esac
  { [ "$until" -gt "$NOW" ] && ! is_ended "$lease"; } || fail ended "the SSH lease has ended"
  if [ -f "$RUN/sessions/$s" ]; then
    grep -qx "lease=$lease" "$RUN/sessions/$s" || fail conflict "this session belongs to another lease"
  else
    # The session's start tells it apart from a later session logind gives the same id.
    mono=$(prop "$s" TimestampMonotonic)
    printf '%s\n' "$mono" | grep -Eqx '[0-9]+' || fail logind "systemd-logind did not describe this session"
    printf 'lease=%s\nuser=%s\nmono=%s\ntty=%s\n' "$lease" "$user" "$mono" "$tty" \
      > "$RUN/sessions/.$s" && mv -f "$RUN/sessions/.$s" "$RUN/sessions/$s" || fail io "cannot record the session"
  fi
  old=$(cat "$RUN/leases/$lease" 2>/dev/null) || old=0
  if [ "$until" -gt "$old" ]; then
    printf '%s\n' "$until" > "$RUN/leases/.$lease" && mv -f "$RUN/leases/.$lease" "$RUN/leases/$lease" \
      || fail io "cannot record the lease"
  fi
  echo "asm-end-ok 0"; exit 0
fi

if [ "$MODE" = stdin ]; then
  [ "$#" -eq 0 ] || fail usage "unknown mode $1"
  s=$(own_session)
  [ -n "${SUDO_UID:-}" ] && [ "$SUDO_UID" = "$ops" ] || fail usage "only asm's cleanup login runs this"
  [ -n "$s" ] && [ ! -e "$RUN/sessions/$s" ] || fail usage "a lease session cannot end leases"
  set -- $(head -c 200 | head -n 1)
  case "${1:-}" in
    check) [ "$#" -eq 1 ] || fail usage "expected: check"; echo "asm-end-ok 0"; exit 0 ;;
    end) [ "$#" -eq 3 ] || fail usage "expected: end LEASE VALID_BEFORE" ;;
    *) fail usage "expected: end LEASE VALID_BEFORE" ;;
  esac
  LEASE=$2; VB=$3
  printf '%s\n' "$LEASE" | grep -Eqx "$UUID" || fail usage "invalid lease id"
  printf '%s\n' "$VB" | grep -Eqx '[0-9]{1,12}' || fail usage "invalid time"
  is_ended "$LEASE" || printf '%s %s\n' "$LEASE" "$VB" >> "$RUN/ended" || fail io "cannot record the lease as ended"
fi

# warn RECORD SESSION LEASE END: write one line to the session's terminal when 10 and 2
# minutes are left; the record remembers each warning it got.
warn() {
  rem=$(($4 - NOW))
  [ "$rem" -le 600 ] || return 0
  if [ "$rem" -le 120 ]; then t=2; else t=10; fi
  tty=$(sed -n 's/^tty=//p' "$1")
  case "$tty" in /dev/pts/[0-9]*) ;; *) return 0 ;; esac
  # A terminal the session closed may now belong to another login.
  o=$(stat -c %u "$tty" 2>/dev/null) && { [ "$o" = "$ops" ] || [ "$o" = "$priv" ]; } || return 0
  ! grep -qx "warned=$4:$t" "$1" || return 0
  timeout 2 sh -c 'printf "\r\nasm: this SSH lease ends at %s (in about %s minutes). To keep running processes, run on the agent machine: asm ssh extend %s \"<reason>\"\r\n" "$1" "$2" "$3" > "$4"' \
    asm-warn "$(date -u -d "@$4" '+%Y-%m-%d %H:%M UTC')" $(((rem + 59) / 60)) "$3" "$tty" 2>/dev/null
  echo "warned=$4:$t" >> "$1"
  echo "warned $2 $3"
}
# live: print the ids of the sessions logind lists; a failed listing is an error.
live() { l=$(loginctl list-sessions --no-legend 2>/dev/null) && printf '%s\n' "$l" | awk '{ print $1 }'; }
LIVE=$(live) || fail logind "cannot list logind sessions"
kill=; unknown=0
set +f; RECORDS=$(printf '%s\n' "$RUN"/sessions/[A-Za-z0-9]*); set -f
for f in $RECORDS; do
  [ -f "$f" ] || continue
  s=${f##*/}
  lease=$(sed -n 's/^lease=//p' "$f")
  # A record whose session logind no longer lists is stale.
  printf '%s\n' "$LIVE" | grep -qx "$s" || { rm -f "$f"; continue; }
  [ "$MODE" != stdin ] || [ "$lease" = "$LEASE" ] || continue
  # A listed session logind doesn't describe stays recorded: the next run tries again,
  # and ending a lease reports it as not ended.
  mono=$(prop "$s" TimestampMonotonic)
  if [ -z "$mono" ]; then
    unknown=$((unknown + 1)); echo "unknown $s"; continue
  fi
  # logind gave the id to a newer session: the recorded one is gone.
  [ "$mono" = "$(sed -n 's/^mono=//p' "$f")" ] || { rm -f "$f"; continue; }
  if [ "$MODE" = --sweep ]; then
    dl=$(cat "$RUN/leases/$lease" 2>/dev/null) || dl=0
    if [ "$dl" -gt "$NOW" ] && ! is_ended "$lease"; then warn "$f" "$s" "$lease" "$dl"; continue; fi
  fi
  kill="$kill $s"; echo "ending $s $(sed -n 's/^user=//p' "$f") $lease"
done
if [ "$MODE" = --sweep ]; then
  if [ -f "$RUN/ended" ]; then
    awk -v now="$NOW" '$2 > now' "$RUN/ended" > "$RUN/.ended" && mv -f "$RUN/.ended" "$RUN/ended"
  fi
  set +f; LEASES=$(printf '%s\n' "$RUN"/leases/[0-9a-f]*); set -f
  for f in $LEASES; do
    [ -f "$f" ] || continue
    l=${f##*/}
    dl=$(cat "$f" 2>/dev/null) || dl=0
    [ "$dl" -gt "$NOW" ] || grep -rqx "lease=$l" "$RUN/sessions" || rm -f "$f"
  done
fi
for s in $kill; do loginctl terminate-session "$s" 2>/dev/null; done
# New logins of an ended or expired lease are refused under the lock, so it can go now.
[ "$MODE" = --all ] || flock -u 9
# left: set LEFT to the sessions of $kill that logind still lists.
left() {
  l=$(live) || fail logind "cannot list logind sessions"
  LEFT=
  for s in $kill; do printf '%s\n' "$l" | grep -qx "$s" && LEFT="$LEFT $s"; done
}
left; i=0
while [ -n "$LEFT" ] && [ "$i" -lt 20 ]; do sleep 0.5; i=$((i + 1)); left; done
if [ -n "$LEFT" ]; then
  for s in $LEFT; do loginctl kill-session "$s" --signal=SIGKILL 2>/dev/null; done
  i=0; left
  while [ -n "$LEFT" ] && [ "$i" -lt 10 ]; do sleep 0.5; i=$((i + 1)); left; done
fi
# The sweep tries undescribed sessions again next minute; ending a lease or removing asm
# can't say they ended.
ended=0; failed=0; [ "$MODE" = --sweep ] || failed=$unknown
for s in $kill; do
  case " $LEFT " in
    *" $s "*) failed=$((failed + 1)); echo "failed $s" ;;
    *) ended=$((ended + 1)); rm -f "$RUN/sessions/$s" ;;
  esac
done
[ "$failed" -eq 0 ] || fail sessions "could not end $failed of $((ended + failed)) sessions"
echo "asm-end-ok $ended"
