#!/usr/bin/env bash
# Required native mode is only for an explicitly disposable hosted CI machine.
set -euo pipefail
output_root=''
source_commit=''
run_url=''
require_native=0
while (($#)); do
  case "$1" in
    --help)
      printf '%s\n' 'Usage: test-registered-worker-systemd.sh --output-root ABS_PATH --source-commit SHA --run-url URL --require-native'
      exit 0 ;;
    --output-root|--source-commit|--run-url)
      if (($# < 2)) || [[ -z "$2" || "$2" == --* ]]; then
        printf '%s\n' invalid_worker_gate_arguments >&2; exit 2
      fi
      case "$1" in
        --output-root) output_root="$2" ;;
        --source-commit) source_commit="$2" ;;
        --run-url) run_url="$2" ;;
      esac
      shift 2 ;;
    --require-native) require_native=1; shift ;;
    *) printf '%s\n' invalid_worker_gate_arguments >&2; exit 2 ;;
  esac
done
if [[ "$output_root" != /* || -z "$source_commit" || -z "$run_url" ]]; then
  printf '%s\n' invalid_worker_gate_arguments >&2; exit 2
fi
repo="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
if ((require_native)); then export AEGIS_MANAGER_REQUIRE_WORKER_SYSTEMD=1; fi
# This runner writes fixed, sanitized failure artifacts for prerequisites,
# setup failures, zero executed tests, skips and ordinary test failures alike.
exec python "$repo/scripts/run_required_manager_tests.py" \
  --require manager_worker_service --settings aegis_manager.ci_settings \
  --output "$output_root/manager-worker-service.json" \
  --source-commit "$source_commit" --run-url "$run_url" \
  control.tests.test_execution_worker_service.RegisteredWorkerSystemdTests
