SCRIPT=unenroll
WANT=${1:-}
set -f
[ "$(id -u)" = 0 ] || fail not-root "removal must run as root"
lock 30
if [ ! -e "$STATE" ] && [ ! -L "$STATE" ]; then echo "asm-unenroll-ok 0"; exit 0; fi
root_only "$STATE" || fail unsafe-path "$STATE is not a root-only directory"
if [ ! -f "$STATE/manifest" ]; then
  rmdir "$STATE" 2>/dev/null || fail foreign-state "$STATE exists without asm's manifest; inspect it and remove it by hand"
  echo "asm-unenroll-ok 0"; exit 0
fi
TID=$(mf tid | head -n 1); PORT=$(mf port | head -n 1)
OPS_UID=$(mf ops_uid | head -n 1); PRIV_UID=$(mf priv_uid | head -n 1)
printf '%s\n' "$TID" | grep -Eqx '[0-9a-f]{8}' || fail manifest "$STATE/manifest is damaged"
[ -z "$WANT" ] || [ "$WANT" = "$TID" ] || fail other-target "this host is enrolled as SSH target $TID, not $WANT"
case "$PORT" in ''|*[!0-9]*) PORT=22 ;; esac
MARK="asm-ca-$TID"
# 1. Trust, so no new asm login starts: the key files enrollment recorded, plus wherever
#    sshd looks today.
OPS_AKS=$(mf ops_ak); PRIV_AKS=$(mf priv_ak)
for acct in asm-ops asm-priv; do
  getent passwd "$acct" >/dev/null || continue
  SNAP=$(sshd -T -C "user=$acct,host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=$PORT" 2>/dev/null) || continue
  akfile "$acct" "/var/lib/$acct" || continue
  if [ "$acct" = asm-ops ]; then OPS_AKS="$OPS_AKS $AK"; else PRIV_AKS="$PRIV_AKS $AK"; fi
done
for f in $OPS_AKS $PRIV_AKS; do drop_keys "$f"; done
# 2. Every lease session. This script holds the lock asm-end-lease would take.
ended=0
if [ -x "$LIB/asm-end-lease" ]; then
  last=$("$LIB/asm-end-lease" --all </dev/null | tail -n 1)
  case "$last" in
    "asm-end-ok "*) ended=${last#asm-end-ok } ;;
    *) fail sessions "ending lease sessions failed: ${last:-no output}" ;;
  esac
  case "$ended" in ''|*[!0-9]*) fail sessions "ending lease sessions failed: $last" ;; esac
fi
# 3. The timer.
[ ! -e /etc/systemd/system/asm-end-lease.timer ] || systemctl disable --now asm-end-lease.timer >/dev/null 2>&1
rm -f /etc/systemd/system/asm-end-lease.timer /etc/systemd/system/asm-end-lease.service
systemctl daemon-reload >/dev/null 2>&1
# 4. The accounts this enrollment created.
drop_account asm-priv "$PRIV_UID"
drop_account asm-ops "$OPS_UID"
# 5. Files. The lock file stays.
rm -f /etc/sudoers.d/asm-ssh
rm -rf "$LIB" "$RUN/sessions" "$RUN/leases" "$RUN/ended"
# 6. Check, then forget the installation.
for f in $OPS_AKS $PRIV_AKS; do [ ! -e "$f" ] || fail trust-remains "$f still exists"; done
{ rm -f "$STATE/manifest" && rmdir "$STATE"; } || fail io "cannot remove $STATE"
echo "asm-unenroll-ok $ended"
