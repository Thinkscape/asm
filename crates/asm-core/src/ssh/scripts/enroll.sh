SCRIPT=enroll
TID='@@TID@@'; PRIV='@@PRIV@@'; PRIV_TRUST='@@PRIV_TRUST@@'
CA_KEY='@@CA_KEY@@'; CA_FP='@@CA_FP@@'
LOG_UNITS='@@LOG_UNITS@@'
# The other users agents may log in as, one "NAME:ADMIN" each; ADMIN is 1 when the
# operator chose the user knowing it can become root.
USERS='@@USERS@@'
RESTART_UNITS='@@RESTART_UNITS@@'
RELOAD_UNITS='@@RELOAD_UNITS@@'
# Files restricted leases may read; their grammar (asm_proto::ssh::validate_read_path)
# leaves out every character sudoers or the shell would interpret.
READ_FILES='@@READ_FILES@@'
AGENT_HOST='@@AGENT_HOST@@'; PORT='@@AGENT_PORT@@'
MARK="asm-ca-$TID"; TAIL="asm managed CA $CA_FP $MARK"
set -f

# ---- 1. Preflight. Nothing changes until every check passes. ----
[ "$(id -u)" = 0 ] || fail not-root "enrollment must run as root"
[ "$(uname -s)" = Linux ] && [ -d /run/systemd/system ] || fail unsupported-os "only Linux hosts running systemd are supported"
for tool in sshd systemctl journalctl loginctl useradd usermod userdel getent flock mktemp stat awk sed grep id install sudo visudo pgrep pkill timeout date find sha256sum sort head readlink; do
  command -v "$tool" >/dev/null 2>&1 || fail missing-tool "$tool not found"
done
SYSTEMCTL=$(command -v systemctl)
sed -n 's|.*/session-\([A-Za-z0-9][A-Za-z0-9]*\)\.scope$|\1|p' /proc/$$/cgroup | grep -q . \
  || fail no-logind "ssh logins get no systemd-logind session here; install libpam-systemd and set UsePAM yes"
grep -Eq '^[@#]includedir[[:space:]]+/etc/sudoers\.d' /etc/sudoers || fail sudoers "/etc/sudoers does not include /etc/sudoers.d"
for d in /usr/lib /var/lib /etc/systemd/system /etc/sudoers.d; do
  root_only "$d" || fail unsafe-path "$d is writable by group or others"
done
lock 30
getent passwd "$PRIV" >/dev/null || fail no-user "user $PRIV does not exist"
if [ "$PRIV_TRUST" = 1 ]; then
  PRIV_SHELL=$(getent passwd "$PRIV" | cut -d: -f7)
  shell_ok "$PRIV_SHELL" || fail no-shell "user $PRIV has no login shell"
fi
# Each user must be what the operator saw when choosing it: an account that can become
# root needs privileged access to be allowed. The manifest records each user's UID and
# whether it could become root, so asm-end-lease can check both at every login.
NAMES=; USER_RECORDS=
for u in $USERS; do
  n=${u%%:*}; chosen_admin=${u#*:}
  getent passwd "$n" >/dev/null || fail no-user "user $n does not exist"
  [ "$n" != "$PRIV" ] || fail user "user $n is the privileged login"
  why=$(admin_why "$n")
  if [ -n "$why" ]; then
    [ "$chosen_admin" = 1 ] || fail user-changed "$n can now become root ($why); choose the target's users again"
    [ "$PRIV_TRUST" = 1 ] || fail user-admin "$n can become root ($why); allow privileged access to let agents use it"
  else
    [ "$chosen_admin" = 0 ] || fail user-changed "$n can no longer become root; choose the target's users again"
  fi
  NAMES="$NAMES $n"; USER_RECORDS="$USER_RECORDS $n:$(id -u "$n"):$chosen_admin"
done
# asm-priv runs shells as the privileged login and as each user.
PRIV_ACCT=0; { [ "$PRIV_TRUST" = 1 ] || [ -n "$NAMES" ]; } && PRIV_ACCT=1
if [ -e "$STATE" ] || [ -L "$STATE" ]; then
  root_only "$STATE" || fail unsafe-path "$STATE is not a root-only directory"
fi
if [ -f "$STATE/manifest" ]; then
  root_file "$STATE/manifest" || fail unsafe-path "$STATE/manifest is not a root-only file"
  [ "$(mf tid | head -n 1)" = "$TID" ] || fail other-target "this host is enrolled as another SSH target; remove that one first"
else
  for f in "$STATE" "$LIB" /var/lib/asm-ops /var/lib/asm-priv /etc/sudoers.d/asm-ssh \
      /etc/systemd/system/asm-end-lease.service /etc/systemd/system/asm-end-lease.timer; do
    [ ! -e "$f" ] && [ ! -L "$f" ] || fail file-exists "$f exists but asm did not install it here"
  done
fi
OPS_UID=$(mf ops_uid | head -n 1); PRIV_UID=$(mf priv_uid | head -n 1)
for a in "asm-ops:$OPS_UID" "asm-priv:$PRIV_UID"; do
  n=${a%%:*}; u=${a#*:}
  if getent passwd "$n" >/dev/null; then
    [ -n "$u" ] && [ "$(id -u "$n")" = "$u" ] || fail user-exists "user $n exists and was not created by asm here"
  fi
done
ADDRS="127.0.0.1 $(getent ahosts "$AGENT_HOST" 2>/dev/null | awk '{ print $1 }' | sort -u | head -n 8)"
ACCOUNTS=asm-ops; [ "$PRIV_ACCT" = 0 ] || ACCOUNTS="asm-ops asm-priv"
# check_sshd: every asm account, at every agent-facing address, gets settings that keep
# asm's forced commands in charge and accept no credentials but asm's certificates.
# Sets OPS_AK and PRIV_AK.
check_sshd() {
  OPS_AK=; PRIV_AK=
  for acct in $ACCOUNTS; do
    first=
    for a in $ADDRS; do
      snap "$acct" "$a"
      [ "$(val pubkeyauthentication)" = yes ] || fail pubkey-disabled "sshd does not accept public keys for $acct"
      [ "$(val usepam)" = yes ] || fail no-pam "UsePAM must be yes; asm ends sessions through systemd-logind"
      [ "$(val forcecommand)" = none ] || fail force-command "sshd_config sets ForceCommand for $acct, which would replace asm's forced commands"
      [ "$(val permittunnel)" = no ] || fail tunnel-enabled "PermitTunnel must be no for $acct"
      [ "$(val permituserenvironment)" = no ] || fail user-environment "PermitUserEnvironment must be no for $acct"
      bad=$(val acceptenv | tr ' ' '\n' | grep -vxE 'LANG|LC_\*|COLORTERM|NO_COLOR|' | head -n 1)
      [ -z "$bad" ] || fail accept-env "AcceptEnv $bad lets clients set environment variables for $acct; allow only LANG LC_* COLORTERM NO_COLOR"
      # A login without asm's certificate has no forced command, so asm-shell would take
      # the client's command as one. sshd builds without GSSAPI or Kerberos omit those.
      for k in AuthorizedKeysCommand:none AuthorizedPrincipalsCommand:none TrustedUserCAKeys:none \
          HostbasedAuthentication:no GSSAPIAuthentication:no KerberosAuthentication:no; do
        v=$(val "$(printf '%s\n' "${k%%:*}" | tr 'A-Z' 'a-z')")
        [ -z "$v" ] || [ "$v" = "${k#*:}" ] \
          || fail auth-path "sshd_config sets ${k%%:*} for $acct, so other credentials could log in to it; set ${k%%:*} ${k#*:} in a Match User asm-ops,asm-priv block"
      done
      akfile "$acct" "/var/lib/$acct" || fail keys-file "$WHY"
      [ -z "$first" ] || [ "$AK$EXTRA" = "$first" ] || fail keys-file "AuthorizedKeysFile for $acct depends on the address"
      first=$AK$EXTRA
    done
    d=$(dirname "$AK"); while [ ! -e "$d" ]; do d=$(dirname "$d"); done
    root_only "$d" || fail unsafe-path "$d is not a root-only directory"
    { [ ! -L "$AK" ] && { [ ! -e "$AK" ] || [ -f "$AK" ]; }; } || fail unsafe-path "$AK is not a regular file"
    [ ! -e "$AK" ] || ours "$AK" || fail foreign-keys "$AK has lines asm did not write; remove them, then try again"
    # sshd also reads the other AuthorizedKeysFile entries: they must not exist, and only
    # root may create them.
    for x in $EXTRA; do
      [ ! -e "$x" ] && [ ! -L "$x" ] \
        || fail keys-file "sshd also reads $x for $acct; remove it, or set one AuthorizedKeysFile in a Match User asm-ops,asm-priv block"
      d=$(dirname "$x"); while [ ! -e "$d" ]; do d=$(dirname "$d"); done
      root_only "$d" || fail unsafe-path "$d is not a root-only directory"
    done
    if [ "$acct" = asm-ops ]; then OPS_AK=$AK; else PRIV_AK=$AK; fi
  done
  [ "$PRIV_ACCT" = 0 ] || [ "$OPS_AK" != "$PRIV_AK" ] || fail keys-file "asm-ops and asm-priv would share $OPS_AK"
}
check_sshd
OLD_OPS_AK=$(mf ops_ak); OLD_PRIV_AK=$(mf priv_ak)

# ---- 2. Install. The manifest comes first, so asm-remove can undo a partial install. ----
# manifest STATE: rewrite the manifest. While installing it keeps earlier key file paths,
# so a failed run still records every file that may hold asm's lines.
manifest() {
  tmp=; tmp=$(mktemp "$STATE/.manifest.XXXXXX") || fail io "cannot write $STATE/manifest"
  {
    printf 'tid=%s\nca=%s\npriv_login=%s\npriv_trust=%s\nport=%s\nops_uid=%s\npriv_uid=%s\nstate=%s\n' \
      "$TID" "$CA_FP" "$PRIV" "$PRIV_TRUST" "$PORT" "$OPS_UID" "$PRIV_UID" "$1"
    for r in $USER_RECORDS; do echo "user=$r"; done
    { echo "$OPS_AK"; [ "$1" = enrolled ] || echo "$OLD_OPS_AK"; } | sed '/^$/d' | sort -u | sed 's/^/ops_ak=/'
    { echo "$PRIV_AK"; [ "$1" = enrolled ] || echo "$OLD_PRIV_AK"; } | sed '/^$/d' | sort -u | sed 's/^/priv_ak=/'
  } > "$tmp" && chmod 0600 "$tmp" && mv -f "$tmp" "$STATE/manifest" || { rm -f "$tmp"; fail io "cannot write $STATE/manifest"; }
}
[ -d "$STATE" ] || install -d -m 0755 -o root -g root "$STATE" || fail io "cannot create $STATE"
manifest installing
[ -d "$LIB" ] || install -d -m 0755 -o root -g root "$LIB" || fail io "cannot create $LIB"
root_only "$LIB" || fail unsafe-path "$LIB is not a root-only directory"
put "$LIB" asm-dispatch 0755 <<'ASM_EOF'
@@DISPATCH@@
ASM_EOF
put "$LIB" asm-shell 0755 <<'ASM_EOF'
@@SHELL@@
ASM_EOF
put "$LIB" asm-end-lease 0755 <<'ASM_EOF'
@@END_LEASE@@
ASM_EOF
put "$LIB" asm-logs 0755 <<'ASM_EOF'
@@LOGS@@
ASM_EOF
put "$LIB" asm-status 0755 <<'ASM_EOF'
@@STATUS@@
ASM_EOF
put "$LIB" asm-read 0755 <<'ASM_EOF'
@@READ@@
ASM_EOF
put "$LIB" asm-remove 0755 <<'ASM_EOF'
@@REMOVE@@
ASM_EOF
# account NAME SHELL: create the asm account NAME once, then set its shell, home, groups
# and password field.
account() {
  if ! getent passwd "$1" >/dev/null; then
    useradd --system --user-group --no-create-home --home-dir "/var/lib/$1" --shell "$LIB/$2" \
      --comment "asm managed" "$1" || fail useradd "useradd $1 failed"
  fi
  usermod --shell "$LIB/$2" --home "/var/lib/$1" -G "" -p '*' "$1" || fail usermod "usermod $1 failed"
  [ "$(id -Gn "$1")" = "$1" ] || fail groups "$1 must belong only to its own group"
  [ -d "/var/lib/$1" ] || install -d -m 0755 -o root -g root "/var/lib/$1" || fail io "cannot create /var/lib/$1"
  root_only "/var/lib/$1" || fail unsafe-path "/var/lib/$1 is not a root-only directory"
}
account asm-ops asm-dispatch; OPS_UID=$(id -u asm-ops); manifest installing
if [ "$PRIV_ACCT" = 1 ]; then
  account asm-priv asm-shell; PRIV_UID=$(id -u asm-priv); manifest installing
else
  for f in $OLD_PRIV_AK; do drop_keys "$f"; done
  drop_account asm-priv "$PRIV_UID"; PRIV_UID=; OLD_PRIV_AK=; manifest installing
fi
tmp=; tmp=$(mktemp /etc/sudoers.d/.asm-ssh.XXXXXX) || fail io "cannot write /etc/sudoers.d"
# status works for every unit restricted leases may read the logs of, restart or reload.
STATUS_UNITS=$(printf '%s\n' $LOG_UNITS $RESTART_UNITS $RELOAD_UNITS | sort -u)
{
  echo "# Installed by asm for SSH target $TID; $LIB/asm-remove removes it."
  echo "asm-ops ALL=(root) NOPASSWD: $LIB/asm-end-lease register *"
  echo "asm-ops ALL=(root) NOPASSWD: $LIB/asm-end-lease \"\""
  for u in $LOG_UNITS; do echo "asm-ops ALL=(root) NOPASSWD: $LIB/asm-logs $u *"; done
  for u in $STATUS_UNITS; do echo "asm-ops ALL=(root) NOPASSWD: $LIB/asm-status $u"; done
  for u in $RESTART_UNITS; do echo "asm-ops ALL=(root) NOPASSWD: $SYSTEMCTL restart $u"; done
  for u in $RELOAD_UNITS; do echo "asm-ops ALL=(root) NOPASSWD: $SYSTEMCTL reload $u"; done
  for f in $READ_FILES; do echo "asm-ops ALL=(root) NOPASSWD: $LIB/asm-read $f"; done
  if [ "$PRIV_ACCT" = 1 ]; then
    RUNAS=; [ "$PRIV_TRUST" = 0 ] || RUNAS=$PRIV
    for n in $NAMES; do RUNAS="${RUNAS:+$RUNAS, }$n"; done
    echo "asm-priv ALL=(root) NOPASSWD: $LIB/asm-end-lease register *"
    echo "asm-priv ALL=($RUNAS) NOPASSWD: ALL"
  fi
} > "$tmp" && chmod 0440 "$tmp" || { rm -f "$tmp"; fail io "cannot write /etc/sudoers.d"; }
visudo -cf "$tmp" >/dev/null 2>&1 || { rm -f "$tmp"; fail sudoers "visudo rejected the asm rules"; }
mv -f "$tmp" /etc/sudoers.d/asm-ssh || fail io "cannot install /etc/sudoers.d/asm-ssh"
# sudo_ok USER COMMAND...: sudo lets USER run COMMAND as root without a password.
sudo_ok() { u=$1; shift; sudo -n -l -U "$u" "$@" >/dev/null 2>&1 || fail sudoers "sudo does not let $u run $*"; }
sudo_ok asm-ops "$LIB/asm-end-lease" register 00000000-0000-4000-8000-000000000000 1 -
sudo_ok asm-ops "$LIB/asm-end-lease"
for u in $LOG_UNITS; do sudo_ok asm-ops "$LIB/asm-logs" "$u" 1; done
for u in $STATUS_UNITS; do sudo_ok asm-ops "$LIB/asm-status" "$u"; done
for u in $RESTART_UNITS; do sudo_ok asm-ops "$SYSTEMCTL" restart "$u"; done
for u in $RELOAD_UNITS; do sudo_ok asm-ops "$SYSTEMCTL" reload "$u"; done
for f in $READ_FILES; do sudo_ok asm-ops "$LIB/asm-read" "$f"; done
if [ "$PRIV_ACCT" = 1 ]; then
  sudo_ok asm-priv "$LIB/asm-end-lease" register 00000000-0000-4000-8000-000000000000 1 -
fi
if [ "$PRIV_TRUST" = 1 ]; then
  sudo -n -l -U asm-priv -u "$PRIV" "$PRIV_SHELL" -l >/dev/null 2>&1 || fail sudoers "sudo does not let asm-priv run a shell as $PRIV"
fi
for n in $NAMES; do
  sudo -n -l -U asm-priv -u "$n" /bin/sh >/dev/null 2>&1 || fail sudoers "sudo does not let asm-priv run a shell as $n"
done
put /etc/systemd/system asm-end-lease.service 0644 <<'ASM_EOF'
[Unit]
Description=End SSH sessions of expired or revoked asm leases
[Service]
Type=oneshot
ExecStart=/usr/lib/asm-ssh/asm-end-lease --sweep
ASM_EOF
put /etc/systemd/system asm-end-lease.timer 0644 <<'ASM_EOF'
[Unit]
Description=End SSH sessions of expired or revoked asm leases every minute
[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
AccuracySec=5s
[Install]
WantedBy=timers.target
ASM_EOF
systemctl daemon-reload && systemctl enable --now asm-end-lease.timer >/dev/null 2>&1 \
  || fail systemd "cannot start asm-end-lease.timer"
# The accounts exist now, so Match rules on their names and groups apply.
WANT_OPS_AK=$OPS_AK; WANT_PRIV_AK=$PRIV_AK
check_sshd
[ "$OPS_AK" = "$WANT_OPS_AK" ] && [ "$PRIV_AK" = "$WANT_PRIV_AK" ] || fail keys-file "AuthorizedKeysFile changed once the asm accounts existed"

# ---- 3. Trust, last: it is what makes the target usable. ----
# keys FILE LINE...: replace FILE with LINE..., inside a root-only directory chain.
keys() {
  f=$1; shift; d=$(dirname "$f")
  [ -d "$d" ] || install -d -m 0755 -o root -g root "$d" || fail io "cannot create $d"
  root_only "$d" || fail unsafe-path "$d is not a root-only directory"
  tmp=; tmp=$(mktemp "$d/.asm-keys.XXXXXX") && printf '%s\n' "$@" > "$tmp" && chmod 0644 "$tmp" && mv -f "$tmp" "$f" \
    || { [ -z "$tmp" ] || rm -f "$tmp"; fail io "cannot write $f"; }
}
keys "$OPS_AK" "cert-authority,principals=\"asm-$TID-restricted\",restrict $CA_KEY $TAIL" \
  "cert-authority,principals=\"asm-$TID-cleanup\",restrict,command=\"asm-cleanup\" $CA_KEY $TAIL"
if [ "$PRIV_ACCT" = 1 ]; then
  set --
  [ "$PRIV_TRUST" = 0 ] || set -- "$@" "cert-authority,principals=\"asm-$TID-privileged\",restrict,pty $CA_KEY $TAIL"
  [ -z "$NAMES" ] || set -- "$@" "cert-authority,principals=\"asm-$TID-user\",restrict,pty $CA_KEY $TAIL"
  keys "$PRIV_AK" "$@"
fi
for f in $OLD_OPS_AK; do [ "$f" = "$OPS_AK" ] || drop_keys "$f"; done
for f in $OLD_PRIV_AK; do [ "$f" = "$PRIV_AK" ] || drop_keys "$f"; done
# SELinux labels for exactly what asm created, nothing below or beside it.
if command -v restorecon >/dev/null 2>&1; then
  set -- /var/lib/asm-ops "$(dirname "$OPS_AK")" "$OPS_AK"
  [ "$PRIV_ACCT" = 0 ] || set -- "$@" /var/lib/asm-priv "$(dirname "$PRIV_AK")" "$PRIV_AK"
  restorecon "$@" >/dev/null 2>&1
fi
manifest enrolled
echo "asm-enroll-ok"
