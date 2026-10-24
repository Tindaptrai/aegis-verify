#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
[[ -f "$repo/deploy/agent/linux/install.sh" ]] || { echo 'RED: Linux installer contract is not implemented' >&2; exit 1; }
source "$repo/deploy/agent/linux/install.sh"
temp=$(mktemp -d)
trap 'rm -rf -- "$temp"' EXIT
mkdir "$temp/bin"
printf 'synthetic executable\n' > "$temp/bin/aegis-agent"
cp "$repo/deploy/agent/linux/"{install.sh,uninstall.sh,aegis-agent.service} "$temp/"
manifest() { (cd "$temp" && sha256sum --text bin/aegis-agent install.sh uninstall.sh aegis-agent.service > SHA256SUMS.txt); }
rejected() { if ( "$@" ) >/dev/null 2>&1; then echo 'Expected installer rejection' >&2; exit 1; fi; }
manifest
verify_package "$temp"
printf 'tampered\n' >> "$temp/bin/aegis-agent"
rejected verify_package "$temp"
manifest
printf '%064d  ../escape\n' 0 >> "$temp/SHA256SUMS.txt"
rejected verify_package "$temp"
manifest
printf 'unlisted\n' > "$temp/extra"
rejected verify_package "$temp"
rm "$temp/extra"
mv "$temp/bin/aegis-agent" "$temp/elsewhere"
ln -s ../elsewhere "$temp/bin/aegis-agent"
rejected verify_package "$temp"
rm "$temp/bin/aegis-agent" "$temp/elsewhere"
validate_service_values 'aegis-agent' 'aegis-agent' '/opt/aegis-agent/bin/aegis-agent run --state-dir /var/lib/aegis-agent' '/etc/systemd/system/aegis-agent.service'
rejected validate_service_values root root '/opt/aegis-agent/bin/aegis-agent run --state-dir /var/lib/aegis-agent' '/etc/systemd/system/aegis-agent.service'
rejected validate_service_values aegis-agent aegis-agent '/tmp/foreign run' '/etc/systemd/system/aegis-agent.service'
echo '8 Linux installer contracts passed; systemd was not invoked'
