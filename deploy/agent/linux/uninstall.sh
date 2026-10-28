#!/usr/bin/env bash
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/install.sh"
[[ $EUID = 0 ]] || fail root_required
[[ $(cat /proc/1/comm) = systemd ]] || fail native_systemd_required
validate_account
validate_existing_service
protected_path /opt/aegis-agent 0 binary
if [[ -e /var/lib/aegis-agent ]]; then protected_path /var/lib/aegis-agent "$(id -u aegis-agent)" state; fi
if [[ -e /etc/systemd/system/aegis-agent.service ]]; then
    systemctl disable --now aegis-agent.service
    rm -- /etc/systemd/system/aegis-agent.service
    systemctl daemon-reload
fi
rm -rf -- /opt/aegis-agent
printf '%s\n' 'Agent service and binaries removed. Protected identity and service account are preserved.'
