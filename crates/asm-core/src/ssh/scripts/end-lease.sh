#!/bin/sh
# asm-end-lease: records the sessions of asm SSH leases, and ends them.
#   register LEASE UNTIL TTY [USER]  asm-dispatch and asm-shell run this through sudo
#                             before a lease session does anything. It records the
#                             caller's systemd-logind session, refuses an ended lease and,
#                             for a login as USER, an account that changed since enrollment.
#                             An asm-priv login also records the files asm watches (below).
#   (no arguments)            asm-dispatch runs this through sudo for the manager's cleanup
#                             login. Reads one line: "end LEASE VALID_BEFORE" or "check".
#                             "end" prints "changed <path>" for at most 20 watched paths that
#                             changed during the lease, then "asm-end-ok <ended> <changed>".
#   --sweep                   asm-end-lease.timer: ends sessions past their lease's end or
#                             of ended leases, and warns lease terminals 10 and 2 minutes
#                             before the end.
#   --all                     asm-remove, which holds the lock: ends every lease session.
# State lives in /run/asm-ssh (root-only, gone at reboot like the sessions it describes):
#   sessions/<id>  lease=, user=, mono= (the session's start) and tty= of one logind session
#   leases/<id>    the latest end any login of that lease presented
#   ended          "<lease> <valid before>" for each lease the manager ended
# and in /var/lib/asm-ssh/baselines (root-only, kept across reboots until the lease's end
# reaches this host, or 30 days after it):
#   <lease>        the files asm watches as the lease's first login found them
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

# ---- Change report ----
# A login that can leave things behind (asm-priv, as the privileged login or as a user)
# records a snapshot of the places its scope watches at the lease's first login:
# $BASE/<lease> holds "until=<end>", "scope=<root or user:NAME>", "complete=<1 or 0>",
# then the snapshot. When the manager ends the lease, the scope is listed again, and
# every path whose line was added, removed or changed is reported.
#
# A snapshot reads metadata only (no file is opened): one GNU `find -P` walk, which does
# not follow symbolic links, with one line per entry, sorted with LC_ALL=C:
#   <type> <device>:<inode> <size> <ctime> <mtime> <mode> <uid>:<gid> <path>
# Any write by an account other than root changes the ctime, so contents need no hash. A
# directory prints "-" for size, ctime and mtime, so only a change to the directory
# itself (mode, owner, a new inode) reports it, not one inside it. A path with a line
# break prints "(a name with a line break)" instead (its inode keeps it apart). The whole
# line is compared; the reported path is everything after the seventh field.
#
# The walk stops after 20 seconds, 20000 lines or 4 MiB; then the snapshot is incomplete
# (complete=0) and the lease's end reports that asm could not check every file.
BASE=$STATE/baselines
NL='
'
INCOMPLETE="changed (asm could not check every watched file: too many files or too slow)"
# home_entries HOME: the watched entries of one home directory that exist, each only
# when no symbolic link leads into it below HOME (the entry itself may be one).
home_entries() {
  rh=$(readlink -f "$1") || return 0
  for f in .ssh .config/systemd/user .profile .bash_profile .bash_login .bashrc .bash_logout .zshrc .zprofile \
      .zshenv .zlogin; do
    e="${1%/}/$f"
    [ -e "$e" ] || [ -L "$e" ] || continue
    d=${f%/*}; want=$rh; [ "$d" = "$f" ] || want="${rh%/}/$d"
    [ "$(readlink -f "$(dirname "$e")")" = "$want" ] && printf '%s\n' "$e"
  done
  return 0
}
# watched SCOPE: the paths SCOPE watches, one per line. root: every home and the places
# that decide who logs in, what runs at boot or on a schedule, and what every shell
# loads. user:NAME: what NAME itself can change to keep access.
watched() {
  if [ "$1" = root ]; then
    getent passwd | head -n 500 | cut -d: -f6 | while IFS= read -r h; do
      case "$h" in /|/var/lib/asm-*) continue ;; /*) ;; *) continue ;; esac
      [ ! -d "$h" ] || home_entries "$h"
    done
    printf '%s\n' /var/spool/cron /var/spool/at /var/lib/systemd/linger /etc/passwd /etc/group /etc/shadow \
      /etc/gshadow /etc/sudoers /etc/sudoers.d /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily \
      /etc/cron.weekly /etc/cron.monthly /etc/anacrontab /etc/systemd/system /etc/systemd/user \
      /usr/lib/systemd/system /lib/systemd/system /etc/ssh /etc/pam.d /etc/security /etc/ld.so.preload \
      /etc/profile /etc/profile.d /etc/environment /etc/bash.bashrc /etc/rc.local
  else
    wu=${1#user:}
    wh=$(getent passwd "$wu" | cut -d: -f6)
    case "$wh" in /*) [ ! -d "$wh" ] || home_entries "$wh" ;; esac
    printf '%s\n' "/var/spool/cron/crontabs/$wu" "/var/spool/cron/$wu" "/var/lib/systemd/linger/$wu"
    for d in /var/spool/cron/atjobs /var/spool/at; do
      [ ! -d "$d" ] || timeout 20 find -P "$d" -type f -user "$wu" ! -path "*$NL*" 2>/dev/null | head -n 1000
    done
  fi
}
# start_paths: the paths on stdin that exist, each once. A path that resolves to one
# already listed (/lib on a usr-merged host) is left out; a symbolic link counts as itself.
start_paths() {
  seen=
  while IFS= read -r p; do
    [ -e "$p" ] || [ -L "$p" ] || continue
    if [ -L "$p" ]; then r="$(readlink -f "$(dirname "$p")")/${p##*/}"; else r=$(readlink -f "$p") || r=$p; fi
    case "$seen$NL" in *"$NL$r$NL"*) continue ;; esac
    seen="$seen$NL$r"
    printf '%s\n' "$p"
  done
}
# walk PATH...: the snapshot lines of one bounded walk, unsorted; a last line "incomplete"
# when it stopped early.
walk() {
  m='%m %U:%G'
  { timeout 20 find -P "$@" \
      \( -path "*$NL*" \( -type d -printf "%y %D:%i - - - $m (a name with a line break)\n" \
          -o -printf "%y %D:%i %s %C@ %T@ $m (a name with a line break)\n" \) \) \
      -o \( -type d -printf "%y %D:%i - - - $m %p\n" \) \
      -o -printf "%y %D:%i %s %C@ %T@ $m %p\n" 2>/dev/null
    [ "$?" -lt 124 ] || echo incomplete; } \
    | LC_ALL=C awk '$0 == "incomplete" { print; exit }
        { n++; b += length($0) + 1; if (n > 20000 || b > 4194304) { print "incomplete"; exit } print }'
}
# snapshot SCOPE: "complete=1" (or 0), then the sorted snapshot of SCOPE (nothing when
# incomplete).
snapshot() {
  starts=$(watched "$1" | start_paths)
  oifs=$IFS; IFS=$NL; set -- $starts; IFS=$oifs
  [ "$#" -gt 0 ] || { echo complete=1; return 0; }
  snap=$(walk "$@")
  case "$NL$snap$NL" in *"${NL}incomplete$NL"*) echo complete=0; return 0 ;; esac
  echo complete=1
  [ -z "$snap" ] || printf '%s\n' "$snap" | LC_ALL=C sort
}
# baseline LEASE UNTIL SCOPE: record SCOPE's snapshot for LEASE once; a later end of the
# lease only moves its "until" line.
baseline() {
  bfile=$BASE/$1
  if [ -f "$bfile" ]; then
    bold=$(sed -n '1s/^until=//p' "$bfile")
    case "$bold" in ''|*[!0-9]*) bold=0 ;; esac
    [ "$2" -gt "$bold" ] || return 0
    sed "1s/.*/until=$2/" "$bfile" > "$BASE/.$1" && mv -f "$BASE/.$1" "$bfile"
    return
  fi
  { [ -d "$BASE" ] || mkdir -m 0700 "$BASE"; } || return 1
  bsnap=$(snapshot "$3")
  printf 'until=%s\nscope=%s\n%s\n' "$2" "$3" "$bsnap" > "$BASE/.$1" && mv -f "$BASE/.$1" "$bfile"
}
# changed_paths BASELINE: the paths whose lines differ between the snapshot in BASELINE
# (after its three header lines) and the one on stdin, sorted, each once.
changed_paths() {
  awk 'part == 1 { if (FNR > 3) old[$0] = 1; next }
    $0 == "" { next }
    $0 in old { delete old[$0]; next }
    { print }
    END { for (l in old) print l }' part=1 "$1" part=2 - | sed 's/^\([^ ]* \)\{7\}//' | LC_ALL=C sort -u
}
# report BASELINE SNAPSHOT: print "changed <path>" for at most 20 watched paths that
# changed since BASELINE and set TOTAL to how many changed; when either snapshot is
# incomplete, one line that says so, counted as 1.
report() {
  TOTAL=0
  if [ "$(sed -n '3p' "$1")" = complete=1 ] && [ "${2%%"$NL"*}" = complete=1 ]; then
    changed=$(printf '%s\n' "$2" | sed 1d | changed_paths "$1")
    [ -n "$changed" ] || return 0
    TOTAL=$(printf '%s\n' "$changed" | awk 'END { print NR }')
    printf '%s\n' "$changed" | head -n 20 | sed 's/^/changed /'
  else
    TOTAL=1; echo "$INCOMPLETE"
  fi
}
# ---- End of the change report ----

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
  # Change report: a login that can leave things behind records the watched files once.
  # asm-ops runs only the restricted operations; a user that can become root leaves
  # things anywhere.
  scope=
  if [ "$SUDO_UID" = "$priv" ]; then
    if [ -z "$as" ] || [ "${rec##*:}" = 1 ]; then scope=root; else scope="user:$as"; fi
  fi
  [ -z "$scope" ] || baseline "$lease" "$until" "$scope" || fail io "cannot record the files asm watches"
  # Recording took a while: the lease must still be on.
  { [ "$until" -gt "$(date +%s)" ] && ! is_ended "$lease"; } || fail ended "the SSH lease has ended"
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
  # Change reports of leases whose end never reached this host go 30 days after the end.
  set +f; BASELINES=$(printf '%s\n' "$BASE"/[0-9a-f]*); set -f
  for f in $BASELINES; do
    [ -f "$f" ] || continue
    u=$(sed -n '1s/^until=//p' "$f")
    case "$u" in ''|*[!0-9]*) u=0 ;; esac
    [ "$((NOW - u))" -le 2592000 ] || rm -f "$f"
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
if [ "$MODE" != stdin ]; then echo "asm-end-ok $ended"; exit 0; fi
# The lease's sessions are over: report the watched paths that changed during it, then
# forget its baseline.
total=0
if [ -f "$BASE/$LEASE" ]; then
  scope=$(sed -n '2s/^scope=//p' "$BASE/$LEASE")
  case "$scope" in
    root) ;;
    user:*) printf '%s\n' "${scope#user:}" | grep -Eqx '[a-z_][a-z0-9_-]{0,31}' || scope= ;;
    *) scope= ;;
  esac
  [ -n "$scope" ] || { rm -f "$BASE/$LEASE"; fail baseline "the record of the files asm watches was damaged; asm removed it"; }
  report "$BASE/$LEASE" "$(snapshot "$scope")"
  total=$TOTAL
  rm -f "$BASE/$LEASE" || fail io "cannot remove $BASE/$LEASE"
fi
echo "asm-end-ok $ended $total"
