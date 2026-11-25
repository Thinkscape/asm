#!/bin/sh
set -u
set -f
PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH
LIB=/usr/lib/asm-ssh
# Fixed at enrollment: the privileged login (when privileged access is allowed) and the
# other users agents may log in as, one "NAME:ADMIN" each. sudo allows exactly these.
PRIV='@@PRIV@@'; PRIV_TRUST='@@PRIV_TRUST@@'
USERS='@@USERS@@'
fail() { echo "asm: $*" >&2; exit 126; }
[ "$#" -eq 2 ] && [ "$1" = "-c" ] || fail "this account only accepts asm SSH lease logins"
# The certificate's forced command: asm-shell lease=ID until=UNIX [as=USER]
set -- $2
{ [ "$#" -eq 3 ] || [ "$#" -eq 4 ]; } && [ "$1" = asm-shell ] || fail "no asm lease"
case "$2" in lease=*) lease=${2#lease=} ;; *) fail "no asm lease" ;; esac
case "$3" in until=*) until=${3#until=} ;; *) fail "no asm lease" ;; esac
printf '%s\n' "$lease" | grep -Eqx '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' || fail "no asm lease"
case "$until" in ''|*[!0-9]*) fail "no asm lease" ;; esac
[ "$(date +%s)" -lt "$until" ] || fail "the SSH lease has ended"
AS=
if [ "$#" -eq 4 ]; then
  case "$4" in as=?*) LOGIN=${4#as=} ;; *) fail "no asm lease" ;; esac
  allowed=
  for u in $USERS; do [ "${u%%:*}" = "$LOGIN" ] && allowed=1; done
  [ -n "$allowed" ] || fail "this host does not allow access as $LOGIN"
  AS=$LOGIN
else
  [ "$PRIV_TRUST" = 1 ] || fail "this host does not allow privileged access"
  LOGIN=$PRIV
fi
tty=$(tty 2>/dev/null) || tty=-
case "$tty" in /dev/pts/[0-9]*) ;; *) tty=- ;; esac
# Record this session before the agent's code runs, so the lease's end can end it. For a
# login as another user, asm-end-lease also checks that account is still what was enrolled.
r=$(sudo -n "$LIB/asm-end-lease" register "$lease" "$until" "$tty" ${AS:+"$AS"} 2>&1) || { m=${r##*asm-end-error }; fail "${m#* }"; }
getent passwd "$LOGIN" >/dev/null || fail "user $LOGIN does not exist"
shell=$(getent passwd "$LOGIN" | cut -d: -f7)
# Like sshd, a session starts in the login's home directory, or in / when it has none.
# /bin/sh does that, then runs the login's shell (which may not be a POSIX shell). An
# account without a login shell (www-data, nologin) gets /bin/sh.
login_shell=1
case "$shell" in ''|*/nologin|*/false) login_shell=0 ;; esac
[ "$login_shell" = 0 ] || [ -x "$shell" ] || login_shell=0
start='cd 2>/dev/null || cd /'
[ "$login_shell" = 1 ] || { shell=/bin/sh; start="$start; SHELL=/bin/sh; export SHELL"; }
if [ -z "${SSH_ORIGINAL_COMMAND+x}" ]; then
  [ "$login_shell" = 1 ] && exec sudo -n -i -u "$LOGIN"
  exec sudo -n -H -u "$LOGIN" -- /bin/sh -c "$start; exec /bin/sh -l"
fi
cmd=$SSH_ORIGINAL_COMMAND
unset SSH_ORIGINAL_COMMAND
case "$cmd" in
  internal-sftp|internal-sftp\ *)
    for p in /usr/lib/openssh/sftp-server /usr/libexec/openssh/sftp-server /usr/libexec/sftp-server /usr/lib/ssh/sftp-server; do
      if [ -x "$p" ]; then cmd="$p${cmd#internal-sftp}"; break; fi
    done
    case "$cmd" in internal-sftp*) fail "sftp needs the sftp-server program on this host" ;; esac ;;
esac
exec sudo -n -H -u "$LOGIN" -- /bin/sh -c "$start; exec \"\$0\" -c \"\$1\"" "$shell" "$cmd"
