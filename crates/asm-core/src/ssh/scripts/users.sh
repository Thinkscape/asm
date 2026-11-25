SCRIPT=users
PRIV='@@PRIV@@'
set -f
# Lists the accounts agents could log in as, one line each:
#   asm-user NAME UID SYSTEM LOGIN_SHELL WHY
# SYSTEM is 1 outside UID_MIN..UID_MAX, LOGIN_SHELL is 1 when the account's shell can run a
# session, and WHY says how it can become root ("-" when asm finds no way). root, the
# privileged login, asm's accounts, nobody and names asm can't use are left out.
[ "$(id -u)" = 0 ] || fail not-root "listing users must run as root"
for tool in getent sudo id awk timeout; do
  command -v "$tool" >/dev/null 2>&1 || fail missing-tool "$tool not found"
done
min=$(awk '$1 == "UID_MIN" { print $2 }' /etc/login.defs 2>/dev/null | head -n 1)
max=$(awk '$1 == "UID_MAX" { print $2 }' /etc/login.defs 2>/dev/null | head -n 1)
case "$min" in ''|*[!0-9]*) min=1000 ;; esac
case "$max" in ''|*[!0-9]*) max=60000 ;; esac
getent passwd | head -n 500 | while IFS=: read -r name _ uid _ _ _ shell; do
  case "$uid" in ''|*[!0-9]*) continue ;; esac
  [ "$uid" != 0 ] && [ "$uid" != 65534 ] && [ "$name" != "$PRIV" ] || continue
  printf '%s\n' "$name" | grep -Eqx '[a-z_][a-z0-9_-]{0,31}' || continue
  case "$name" in asm-*) continue ;; esac
  system=0; { [ "$uid" -ge "$min" ] && [ "$uid" -le "$max" ]; } || system=1
  login=0; shell_ok "$shell" && login=1
  why=$(admin_why "$name")
  echo "asm-user $name $uid $system $login ${why:--}"
done
echo "asm-users-ok"
