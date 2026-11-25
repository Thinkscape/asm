#!/bin/sh
# Shared by enroll.sh and asm-remove. Both run as root; SCRIPT names the caller.
PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH
umask 022
LIB=/usr/lib/asm-ssh
STATE=/var/lib/asm-ssh
RUN=/run/asm-ssh
fail() { echo "asm-$SCRIPT-error $1 $2"; exit 3; }
# mf KEY: every value of KEY in the manifest, one per line.
mf() { [ -f "$STATE/manifest" ] && sed -n "s/^$1=//p" "$STATE/manifest"; }
# root_only DIR: DIR and each ancestor are real directories owned by root and not
# writable by group or others.
root_only() {
  d=$1
  while :; do
    [ -d "$d" ] && [ ! -L "$d" ] && [ "$(stat -c %u "$d")" = 0 ] || return 1
    case "$(stat -c %A "$d")" in ?????w????|????????w?) return 1 ;; esac
    [ "$d" = / ] && return 0
    d=$(dirname "$d")
  done
}
# lock SECONDS: take the host-wide asm lock on fd 9. The lock file is never deleted.
lock() {
  root_only /run || fail unsafe-path "/run is writable by group or others"
  [ -d "$RUN" ] || install -d -m 0700 -o root -g root "$RUN" || fail io "cannot create $RUN"
  root_only "$RUN" || fail unsafe-path "$RUN is not a root-only directory"
  { exec 9>>"$RUN/lock" && flock -w "$1" 9; } || fail busy "another asm operation is running on this host"
}
# snap USER LADDR: set SNAP to `sshd -T` for USER connecting to LADDR:$PORT.
snap() {
  SNAP=$(sshd -T -C "user=$1,host=localhost,addr=127.0.0.1,laddr=$2,lport=$PORT" 2>/dev/null) && [ -n "$SNAP" ] \
    || fail sshd-config "sshd -T failed for $1 at $2:$PORT"
}
# val KEY: every value of KEY in SNAP, one per line.
val() { printf '%s\n' "$SNAP" | awk -v k="$1" '$1 == k { $1 = ""; sub(/^ /, ""); print }'; }
# akfile ACCOUNT HOME: set AK to ACCOUNT's first AuthorizedKeysFile (from SNAP) as an
# absolute path. Returns 1 with the reason in WHY.
akfile() {
  AK=$(val authorizedkeysfile | awk '{ print $1 }'); WHY=
  case "$AK" in ''|none) WHY="sshd reads no authorized_keys file for $1"; return 1 ;; esac
  case "$AK" in *%U*) WHY="AuthorizedKeysFile $AK uses %U; use %h or %u"; return 1 ;; esac
  case "$AK" in /*%h*|/*%u*|[!/]*) ;; *) WHY="AuthorizedKeysFile $AK is one file for every account; asm needs a per-account file"; return 1 ;; esac
  AK=$(printf '%s\n' "$AK" | sed -e "s|%h|$2|g" -e "s|%u|$1|g")
  case "$AK" in *%*|*/../*|*/./*) WHY="unsupported AuthorizedKeysFile $AK"; return 1 ;; /*) ;; *) AK="$2/$AK" ;; esac
}
# ours FILE: every line of FILE is one asm wrote for this target (an I/O error is not).
ours() { grep -qv " $MARK\$" "$1"; [ "$?" -eq 1 ]; }
# put DIR NAME MODE: install stdin as DIR/NAME, owned by root, replacing it atomically.
put() {
  tmp=; tmp=$(mktemp "$1/.$2.XXXXXX") && cat > "$tmp" && chmod "$3" "$tmp" && mv -f "$tmp" "$1/$2" \
    || { [ -z "$tmp" ] || rm -f "$tmp"; fail io "cannot install $1/$2"; }
}
# drop_keys FILE: delete FILE when it holds only this target's asm lines.
drop_keys() {
  [ -e "$1" ] || [ -L "$1" ] || return 0
  [ -f "$1" ] && [ ! -L "$1" ] && root_only "$(dirname "$1")" \
    || fail unsafe-path "$1 is not a regular file in a root-only directory"
  ours "$1" || fail foreign-keys "$1 has lines asm did not write; remove them, then try again"
  rm -f "$1" || fail io "cannot remove $1"
}
# drop_account NAME UID: end every process of the account asm created, then delete it
# and its home. Does nothing when NAME is absent or has another UID.
drop_account() {
  getent passwd "$1" >/dev/null && [ -n "$2" ] && [ "$(id -u "$1")" = "$2" ] || return 0
  loginctl terminate-user "$1" >/dev/null 2>&1
  i=0
  while pgrep -U "$2" >/dev/null 2>&1; do
    [ "$i" -lt 20 ] || fail processes "processes of $1 are still running"
    pkill -KILL -U "$2" >/dev/null 2>&1; sleep 0.5; i=$((i + 1))
  done
  userdel "$1" || fail userdel "userdel $1 failed"
  if [ -d "/var/lib/$1" ] && root_only "/var/lib/$1"; then rm -rf "/var/lib/$1"; fi
}
# admin_why USER: why USER can become root ("uid 0", "in group docker", "has sudo rules");
# nothing when asm finds no way. Groups that grant root through a daemon or the disk count.
# Needs root, for sudo -l -U.
admin_why() {
  [ "$(id -u "$1" 2>/dev/null)" != 0 ] || { echo "uid 0"; return 0; }
  for g in $(id -Gn "$1" 2>/dev/null); do
    case "$g" in root|sudo|wheel|admin|docker|lxd|incus-admin|libvirt|disk) echo "in group $g"; return 0 ;; esac
  done
  case "$(LC_ALL=C timeout 10 sudo -n -l -U "$1" 2>&1)" in
    *"is not allowed to run sudo"*) ;;
    *) echo "has sudo rules" ;;
  esac
}
# shell_ok SHELL: SHELL can run a login session (asm-shell uses /bin/sh otherwise).
shell_ok() {
  case "$1" in ''|*/nologin|*/false) return 1 ;; esac
  [ -x "$1" ]
}
