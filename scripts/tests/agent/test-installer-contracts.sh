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
for boundary in before_promotion after_promotion; do
    fixture=$temp/rollback-$boundary
    mkdir -p "$fixture/installed/bin" "$fixture/stage/bin" "$fixture/state"
    printf 'old reviewed binary\n' > "$fixture/installed/bin/aegis-agent"
    printf 'new reviewed binary\n' > "$fixture/stage/bin/aegis-agent"
    printf 'old reviewed unit\n' > "$fixture/unit"
    printf 'synthetic protected identity bytes\n' > "$fixture/state/state.json"
    before_key=$(sha256sum "$fixture/state/state.json" | cut -d ' ' -f1)
    cp "$fixture/unit" "$fixture/unit.previous"
    mv "$fixture/installed" "$fixture/backup"
    promoted=0
    if [[ $boundary = before_promotion ]]; then
        # The real source rename now fails after the old binary path moved away.
        rm -rf -- "$fixture/stage"
        if mv "$fixture/stage" "$fixture/installed" 2>/dev/null; then echo unexpected_promotion_success >&2; exit 1; fi
    else
        mv "$fixture/stage" "$fixture/installed"; promoted=1
        printf 'new unit\n' > "$fixture/unit"
    fi
    restore_agent_files "$fixture/installed" "$fixture/backup" "$fixture/unit" "$fixture/unit.previous" "$promoted" 1
    [[ -f $fixture/installed/bin/aegis-agent && $(cat "$fixture/installed/bin/aegis-agent") = 'old reviewed binary' ]] || { echo "rollback lost executable at $boundary" >&2; exit 1; }
    [[ $(cat "$fixture/unit") = 'old reviewed unit' ]] || { echo "rollback lost unit at $boundary" >&2; exit 1; }
    [[ $(sha256sum "$fixture/state/state.json" | cut -d ' ' -f1) = "$before_key" ]] || { echo "rollback changed identity at $boundary" >&2; exit 1; }
done
echo '10 Linux installer contracts passed; systemd was not invoked'
