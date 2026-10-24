#!/usr/bin/env bash
set -euo pipefail
fail() { printf '%s\n' "$1" >&2; exit 1; }
no_links() {
    local path=$1
    [[ $path = /* ]] || fail absolute_path_required
    while [[ $path != / ]]; do
        [[ ! -L $path ]] || fail symlink_path_refused
        path=$(dirname -- "$path")
    done
}
verify_package() {
    local root=$1 line hash relative file
    no_links "$root"
    [[ -f $root/SHA256SUMS.txt ]] || fail manifest_missing
    no_links "$root/SHA256SUMS.txt"
    local -A seen=()
    while IFS= read -r line || [[ -n $line ]]; do
        [[ $line =~ ^([0-9a-fA-F]{64})\ \ ([A-Za-z0-9][A-Za-z0-9._/-]*)$ ]] || fail manifest_invalid
        hash=${BASH_REMATCH[1]}; relative=${BASH_REMATCH[2]}
        [[ /$relative/ != */../* && /$relative/ != */./* && $relative != *//* && $relative != SHA256SUMS.txt && ! -v seen[$relative] ]] || fail manifest_path_invalid
        file=$root/$relative
        no_links "$file"
        [[ -f $file && $(sha256sum -- "$file" | cut -d ' ' -f 1) = "${hash,,}" ]] || fail package_hash_mismatch
        seen[$relative]=1
    done < <(if [[ $# -ge 2 ]]; then printf '%s\n' "$2"; else cat -- "$root/SHA256SUMS.txt"; fi)
    for relative in bin/aegis-agent install.sh uninstall.sh aegis-agent.service; do
        [[ -v seen[$relative] ]] || fail package_incomplete
    done
    while IFS= read -r -d '' file; do
        no_links "$file"
        if [[ ! -d $file ]]; then
            relative=${file#"$root/"}
            [[ $relative = SHA256SUMS.txt || -v seen[$relative] ]] || fail package_unlisted_file
        fi
    done < <(find "$root" -mindepth 1 -print0)
}
validate_service_values() {
    [[ $1 = aegis-agent && $2 = aegis-agent && $3 = '/opt/aegis-agent/bin/aegis-agent run --state-dir /var/lib/aegis-agent' && $4 = /etc/systemd/system/aegis-agent.service ]] || fail service_configuration_conflict
}
protected_path() {
    local path=$1 owner=$2 mode=$3 entry permissions
    no_links "$path"
    [[ -e $path ]] || return 0
    while IFS= read -r -d '' entry; do
        no_links "$entry"
        [[ $(stat -c %u -- "$entry") = "$owner" ]] || fail path_owner_invalid
        permissions=$(stat -c %a -- "$entry")
        if [[ $mode = state ]]; then
            if [[ -d $entry ]]; then [[ $permissions = 700 ]] || fail state_permissions_invalid
            else [[ -f $entry && $permissions = 600 ]] || fail state_permissions_invalid; fi
        else
            (( (8#$permissions & 0022) == 0 )) || fail binary_permissions_invalid
            [[ -d $entry || -f $entry ]] || fail file_type_invalid
        fi
    done < <(find "$path" -print0)
}
validate_existing_service() {
    local unit=/etc/systemd/system/aegis-agent.service
    local expected_unit
    expected_unit=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/aegis-agent.service
    no_links "$unit"
    if [[ -e $unit ]]; then
        protected_path "$unit" 0 binary
        cmp -s -- "$unit" "$expected_unit" || fail service_unit_conflict
        local user group exec fragment
        user=$(systemctl show aegis-agent.service -p User --value)
        group=$(systemctl show aegis-agent.service -p Group --value)
        fragment=$(systemctl show aegis-agent.service -p FragmentPath --value)
        exec=$(sed -n 's/^ExecStart=//p' "$unit")
        validate_service_values "$user" "$group" "$exec" "$fragment"
        [[ ! -d /etc/systemd/system/aegis-agent.service.d && ! -d /run/systemd/system/aegis-agent.service.d && ! -e /run/systemd/system/aegis-agent.service ]] || fail service_override_conflict
        [[ -z $(systemctl show aegis-agent.service -p DropInPaths --value) ]] || fail service_override_conflict
    elif systemctl cat aegis-agent.service >/dev/null 2>&1; then fail service_configuration_conflict
    fi
}
validate_account() {
    local record uid gid home shell grouprecord
    if record=$(getent passwd aegis-agent); then
        IFS=: read -r _ _ uid gid _ home shell <<< "$record"
        [[ $uid -gt 0 && $uid -lt 1000 && $home = /var/lib/aegis-agent && $shell = /usr/sbin/nologin ]] || fail account_configuration_conflict
        grouprecord=$(getent group aegis-agent) || fail account_configuration_conflict
        [[ $(cut -d: -f3 <<< "$grouprecord") = "$gid" && $(cut -d: -f4 <<< "$grouprecord") = '' ]] || fail account_configuration_conflict
        [[ $(id -G aegis-agent) = "$gid" ]] || fail account_configuration_conflict
    elif getent group aegis-agent >/dev/null; then fail account_configuration_conflict
    fi
}
install_agent() {
    [[ $EUID = 0 ]] || fail root_required
    [[ $(uname -m) = x86_64 && $(cat /proc/1/comm) = systemd ]] || fail native_systemd_required
    local package manager='' ca='' arg
    package=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
    while (($#)); do
        arg=$1; shift
        case $arg in
            --manager) [[ -z $manager && $# -gt 0 ]] || fail usage_invalid; manager=$1; shift;;
            --server-ca) [[ -z $ca && $# -gt 0 ]] || fail usage_invalid; ca=$1; shift;;
            *) fail usage_invalid;;
        esac
    done
    verify_package "$package"
    local verified_manifest
    verified_manifest=$(cat -- "$package/SHA256SUMS.txt")
    verify_package "$package" "$verified_manifest"
    local root=/opt/aegis-agent state=/var/lib/aegis-agent unit=/etc/systemd/system/aegis-agent.service uid
    no_links "$root"; no_links "$state"; no_links "$unit"
    [[ $(stat -c %u /opt) = 0 ]] || fail path_owner_invalid
    (( (8#$(stat -c %a /opt) & 0022) == 0 )) || fail parent_permissions_invalid
    # /var and /var/lib are not recursively traversed: their own ownership and modes protect the fixed state path.
    for arg in /var /var/lib /etc /etc/systemd /etc/systemd/system; do
        no_links "$arg"
        [[ $(stat -c %u "$arg") = 0 ]] || fail path_owner_invalid
        (( (8#$(stat -c %a "$arg") & 0022) == 0 )) || fail parent_permissions_invalid
    done
    validate_account
    validate_existing_service
    protected_path "$root" 0 binary
    if [[ -e $state ]]; then
        uid=$(id -u aegis-agent) || fail state_account_missing
        protected_path "$state" "$uid" state
    fi
    [[ -f $state/state.json || ( -n $manager && -n $ca ) ]] || fail manager_and_server_ca_required
    if [[ -n $ca ]]; then no_links "$ca"; [[ -f $ca && $(stat -c %s "$ca") -le 8192 ]] || fail server_ca_invalid; fi
    local stage backup promoted=0 backed_up=0 unit_backup='' success=0 ca_temp=''
    stage=$(mktemp -d /opt/.aegis-agent-stage.XXXXXXXX)
    backup=$stage.previous
    cleanup_install() {
        local result=$?
        if (( ! success )); then
            systemctl stop aegis-agent.service >/dev/null 2>&1 || true
            systemctl disable aegis-agent.service >/dev/null 2>&1 || true
            if (( promoted && backed_up )); then rm -rf -- "$root"; mv -- "$backup" "$root"; backed_up=0; fi
            if [[ -n $unit_backup ]]; then install -o root -g root -m 644 "$unit_backup" "$unit"; systemctl daemon-reload || true; fi
        fi
        [[ -z $ca_temp || ! -f $ca_temp ]] || rm -f -- "$ca_temp"
        [[ ! -e $stage ]] || rm -rf -- "$stage"
        if (( success && backed_up )); then rm -rf -- "$backup"; fi
        return "$result"
    }
    trap cleanup_install EXIT
    cp -R -- "$package/." "$stage/"
    verify_package "$stage" "$verified_manifest"
    chown -R root:root "$stage"
    find "$stage" -type d -exec chmod 755 {} +
    find "$stage" -type f -exec chmod 644 {} +
    chmod 755 "$stage/bin/aegis-agent"
    # No service/state mutation occurs before all artifact and existing-install checks.
    if [[ -e $unit ]]; then cp -- "$unit" "$stage/unit.previous"; unit_backup=$stage/unit.previous; systemctl stop aegis-agent.service; systemctl disable aegis-agent.service; fi
    if ! getent passwd aegis-agent >/dev/null; then useradd --system --user-group --home-dir "$state" --shell /usr/sbin/nologin aegis-agent; fi
    if [[ ! -e $state ]]; then install -d -o aegis-agent -g aegis-agent -m 700 "$state"; fi
    if [[ -e $root ]]; then mv -- "$root" "$backup"; backed_up=1; fi
    # Keep a prior unit backup outside the promoted tree's public payload.
    if [[ -n $unit_backup ]]; then unit_backup=$backup.unit; cp -- "$stage/unit.previous" "$unit_backup"; rm -- "$stage/unit.previous"; fi
    mv -- "$stage" "$root"; promoted=1
    install -o root -g root -m 644 "$root/aegis-agent.service" "$unit"
    systemctl daemon-reload
    local status current_origin configured_ca supplied_ca
    status=$(runuser -u aegis-agent -- "$root/bin/aegis-agent" status --state-dir "$state") || fail state_invalid
    current_origin=$(sed -n 's/.*"manager_origin":"\([^"]*\)".*/\1/p' <<< "$status")
    [[ -z $manager || -z $current_origin || $manager = "$current_origin" ]] || fail configuration_mismatch
    if [[ -n $ca && -f $state/state.json ]]; then
        configured_ca=$(sed -n 's/.*"server_ca_pem":"\([^"]*\)".*/\1/p' "$state/state.json")
        configured_ca=$(printf '%b' "$configured_ca" | tr -d '[:space:]')
        supplied_ca=$(tr -d '[:space:]' < "$ca")
        [[ $configured_ca = "$supplied_ca" ]] || fail configuration_mismatch
    fi
    if [[ $status != *'"device_id":"'* ]]; then
        [[ -n $manager && -n $ca ]] || fail manager_and_server_ca_required
        # The public CA may live in root's private download directory. Copy only it to protected state, remove after connect.
        ca_temp=$(mktemp "$state/.server-ca.XXXXXXXX")
        install -o aegis-agent -g aegis-agent -m 600 "$ca" "$ca_temp"
        if ! runuser -u aegis-agent -- "$root/bin/aegis-agent" connect --manager "$manager" --server-ca "$ca_temp" --state-dir "$state"; then rm -f -- "$ca_temp"; fail enrollment_requires_action; fi
        rm -f -- "$ca_temp"
        status=$(runuser -u aegis-agent -- "$root/bin/aegis-agent" status --state-dir "$state") || fail state_invalid
    fi
    [[ $status = *'"state":"enrolled"'* && $status = *'"device_id":"'* ]] || fail identity_requires_action
    systemctl enable --now aegis-agent.service
    systemctl is-active --quiet aegis-agent.service
    success=1
    [[ -z $unit_backup ]] || rm -f -- "$unit_backup"
    trap - EXIT
    cleanup_install
}
if [[ ${BASH_SOURCE[0]} = "$0" ]]; then install_agent "$@"; fi
