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
