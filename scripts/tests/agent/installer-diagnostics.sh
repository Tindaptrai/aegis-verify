# Closed public diagnostics only; captured source content is never returned.
diagnostic_library=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
diagnostic_code() {
    local code=$1 number
    if grep -Fxq -- "$code" "$diagnostic_library/native-diagnostic-codes.txt"; then return 0; fi
    if [[ $code =~ ^win32_(0|[1-9][0-9]{0,4})$ ]]; then (( 10#${BASH_REMATCH[1]} <= 65535 )); return; fi
    if [[ $code =~ ^hresult_(0|-?[1-9][0-9]{0,9})$ ]]; then
        number=${BASH_REMATCH[1]}
        if [[ $number = -* ]]; then (( 10#${number#-} <= 2147483648 )); else (( 10#$number <= 2147483647 )); fi
        return
    fi
    return 1
}
diagnostic_stage() { [[ $1 = preflight || $1 = installer || $1 = configuration || $1 = status || $1 = restart || $1 = uninstall || $1 = owner_conflict || $1 = helper ]]; }
captured_diagnostic() {
    local output=$1 secret=$2 stage=$3 line candidate candidate_stage selected=diagnostic_unknown
    diagnostic_stage "$stage" || stage=helper
    if [[ ( -n $secret && $output = *"$secret"* ) || $output = *'PRIVATE KEY'* || $output = *'csr_pem'* ]]; then printf '%s\n' '{"stage":"helper","code":"installer_output_secret_leak"}'; return; fi
    if (( ${#output} <= 65536 )); then
        while IFS= read -r line; do
            candidate=''; candidate_stage=$stage
            if diagnostic_code "$line"; then candidate=$line
            elif [[ $line =~ ^\{\"error\":\{\"code\":\"([a-z_]+)\"\}\}$ ]]; then candidate=${BASH_REMATCH[1]}
            elif [[ $line =~ ^\{\"stage\":\"([a-z_]+)\",\"code\":\"([a-z0-9_-]+)\"\}$ ]]; then candidate_stage=${BASH_REMATCH[1]}; candidate=${BASH_REMATCH[2]}; fi
            if [[ -n $candidate ]] && diagnostic_stage "$candidate_stage" && diagnostic_code "$candidate"; then selected=$candidate; stage=$candidate_stage; break; fi
        done <<< "$output"
    fi
    printf '{"stage":"%s","code":"%s"}\n' "$stage" "$selected"
}
diagnostic_command_failure() {
    local command=$1 stage=installer code=native_command_failed
    case $command in
        stat\ *|sha256sum\ *|id\ *|getent\ *) stage=preflight;;
        systemctl\ *) stage=configuration;;
        *\ status\ --state-dir\ *) stage=status;;
    esac
    case $command in
        chmod\ *) code=command_chmod_failed;; chown\ *) code=command_chown_failed;; cp\ *) code=command_cp_failed;;
        find\ *) code=command_find_failed;; getent\ *) code=command_getent_failed;; id\ *) code=command_id_failed;;
        install\ *) code=command_install_failed;; mkdir\ *) code=command_mkdir_failed;; mktemp\ *) code=command_mktemp_failed;;
        mv\ *) code=command_mv_failed;; runuser\ *) code=command_runuser_failed;; sha256sum\ *) code=command_sha256sum_failed;;
        stat\ *) code=command_stat_failed;; systemctl\ *) code=command_systemctl_failed;;
    esac
    printf '{"stage":"%s","code":"%s"}\n' "$stage" "$code" >&2
}
