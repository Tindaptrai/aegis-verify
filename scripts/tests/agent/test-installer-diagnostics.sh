#!/usr/bin/env bash
set -euo pipefail
library=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/installer-diagnostics.sh
[[ -f $library ]] || { echo 'RED: safe installer diagnostics are not implemented' >&2; exit 1; }
source "$library"
assert_code() {
    local text=$1 secret=$2 expected=$3 actual
    actual=$(captured_diagnostic "$text" "$secret" installer)
    [[ $actual = "{\"stage\":\"installer\",\"code\":\"$expected\"}" || ( $expected = installer_output_secret_leak && $actual = '{"stage":"helper","code":"installer_output_secret_leak"}' ) ]] || { echo safe_diagnostic_contract_failed >&2; exit 1; }
}
assert_code state_invalid '' state_invalid
assert_code '{"error":{"code":"pairing_denied"}}' '' pairing_denied
assert_code 'private source says state_invalid' '' diagnostic_unknown
assert_code '{"stage":"installer","code":"hresult_-2147024891"}' '' hresult_-2147024891
assert_code '{"stage":"installer","code":"win32_999999"}' '' diagnostic_unknown
assert_code '{"stage":"installer","code":"state_invalid","private":"hidden"}' '' diagnostic_unknown
assert_code '{"stage":"installer","code":"state_invalid","code":"pairing_denied"}' '' diagnostic_unknown
secret=$(printf '%064d' 0)
assert_code "state_invalid $secret" "$secret" installer_output_secret_leak
assert_code 'PRIVATE KEY state_invalid' '' installer_output_secret_leak
assert_code "$(printf '%65537s' x)" '' diagnostic_unknown
test_package=$(mktemp -d)
trap 'rm -rf -- "$test_package"' EXIT
cat > "$test_package/install.sh" <<'SYNTHETIC'
install_agent() { read -r value; printf '%s\n' "$value" >&2; printf '%s\n' state_invalid >&2; return 1; }
SYNTHETIC
set +e
output=$(printf '%s\n' "$secret" | bash "$(dirname -- "${BASH_SOURCE[0]}")/invoke-linux-installer-diagnostic.sh" "$test_package" 2>&1)
result=$?
set -e
[[ $result != 0 ]] || { echo synthetic_failure_not_observed >&2; exit 1; }
assert_code "$output" "$secret" installer_output_secret_leak
echo '11 safe Bash diagnostic contracts passed; systemd was not invoked'
