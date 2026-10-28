#!/usr/bin/env bash
# CI source helper only; no diagnostic code is added to the public installer.
set -Eeuo pipefail
library=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$library/installer-diagnostics.sh"
package=$1; shift
source "$package/install.sh"
trap 'diagnostic_command_failure "$BASH_COMMAND"' ERR
install_agent "$@"
