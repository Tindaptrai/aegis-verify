#!/usr/bin/env bash
# Disposable GitHub Ubuntu host only. Pairing code is a single closed stdin line.
set -euo pipefail
native_library=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$native_library/installer-diagnostics.sh"
helper_fail() { printf '{"stage":"helper","code":"%s"}\n' "$1" >&2; exit 1; }
[[ ${GITHUB_ACTIONS:-} = true && ${RUNNER_OS:-} = Linux && $EUID = 0 && $(cat /proc/1/comm) = systemd ]] || helper_fail disposable_native_systemd_ci_required
action='' package='' manager='' ca='' expected=''
while (($#)); do
    argument=$1; shift
    (($#)) || helper_fail usage_invalid
    case $argument in
        --action) action=$1;; --package-root) package=$1;; --manager-origin) manager=$1;; --server-ca) ca=$1;; --expected-device-id) expected=$1;;
        *) helper_fail usage_invalid;;
    esac
    shift
done
[[ $action = Install || $action = Restart || $action = Reinstall || $action = Status || $action = Uninstall ]] || helper_fail usage_invalid
source "$package/install.sh"
fail() { local code=$1; diagnostic_code "$code" || code=diagnostic_unknown; printf '{"stage":"helper","code":"%s"}\n' "$code" >&2; exit 1; }
root=/opt/aegis-agent; state=/var/lib/aegis-agent; unit=/etc/systemd/system/aegis-agent.service; binary=$root/bin/aegis-agent
read_status() {
    status=$(runuser -u aegis-agent -- "$binary" status --state-dir "$state") || fail status_failed
    device=$(sed -n 's/.*"device_id":"\([^"]*\)".*/\1/p' <<< "$status")
    identity_state=$(sed -n 's/.*"state":"\([^"]*\)".*/\1/p' <<< "$status")
    [[ $device =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ && $identity_state =~ ^[a-z_]+$ ]] || fail status_invalid
    [[ -z $expected || $device = "$expected" ]] || fail ci_identity_conflict
}
key_hash() { sed -n 's/.*"private_key_pem":"\([^"]*\)".*/\1/p' "$state/state.json" | sha256sum | cut -d ' ' -f1; }
assert_configuration() {
    validate_existing_service
    validate_account
    protected_path "$root" 0 binary
    protected_path "$state" "$(id -u aegis-agent)" state
    systemctl is-enabled --quiet aegis-agent.service
}
closed_installer() {
    local code=${1:-} output result
    local -a arguments=()
    [[ -z $manager ]] || arguments+=(--manager "$manager")
    [[ -z $ca ]] || arguments+=(--server-ca "$ca")
    set +e
    if [[ -n $code ]]; then output=$(printf '%s\n' "$code" | bash "$native_library/invoke-linux-installer-diagnostic.sh" "$package" "${arguments[@]}" 2>&1); result=$?
    else output=$(bash "$native_library/invoke-linux-installer-diagnostic.sh" "$package" "${arguments[@]}" </dev/null 2>&1); result=$?; fi
    set -e
    diagnostic=$(captured_diagnostic "$output" "$code" installer)
    if [[ $result != 0 || $diagnostic = *'"code":"installer_output_secret_leak"'* ]]; then printf '%s\n' "$diagnostic" >&2; exit 1; fi
}
if [[ $action = Install ]]; then
    [[ ! -e $root && ! -e $state && ! -e $unit ]] || fail ci_target_already_exists
    ! getent passwd aegis-agent >/dev/null || fail ci_account_already_exists
    ! systemctl cat aegis-agent.service >/dev/null 2>&1 || fail ci_service_already_exists
    [[ -n $manager && -n $ca ]] || fail manager_and_server_ca_required
    IFS= read -r code
    [[ $code =~ ^[0-9a-f]{64}$ ]] || fail synthetic_code_required_on_stdin
    closed_installer "$code"
    unset code
    assert_configuration
    read_status
else
    [[ $action = Status || -n $expected ]] || fail expected_device_id_required_for_mutation
    read_status
    if [[ $action = Restart || $action = Reinstall ]]; then
        before_id=$device; before_key=$(key_hash)
        started=$SECONDS
        systemctl stop aegis-agent.service
        (( SECONDS - started < 20 )) || fail service_stop_deadline_exceeded
        if [[ $action = Restart ]]; then systemctl start aegis-agent.service; else closed_installer; fi
        assert_configuration
        read_status
        [[ $device = "$before_id" && $(key_hash) = "$before_key" ]] || fail restart_or_reinstall_changed_identity
    elif [[ $action = Uninstall ]]; then
        systemctl stop aegis-agent.service
        before=$(sha256sum "$state/state.json" | cut -d ' ' -f1)
        bash "$package/uninstall.sh" >/dev/null
        [[ ! -e $root && ! -e $unit && -f $state/state.json ]] || fail uninstall_contract_failed
        [[ $(sha256sum "$state/state.json" | cut -d ' ' -f1) = "$before" ]] || fail uninstall_changed_identity
    fi
fi
if [[ -e $unit ]]; then
    service_status=$(systemctl is-active aegis-agent.service || true)
    [[ $service_status =~ ^[a-z-]+$ ]] || fail service_status_invalid
else service_status=absent; fi
printf '{"action":"%s","device_id":"%s","state":"%s","service_status":"%s","identity_preserved":true}\n' "$action" "$device" "$identity_state" "$service_status"
