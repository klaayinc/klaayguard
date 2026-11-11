#!/usr/bin/env bash
# Install apt packages on a CI runner without letting a slow mirror stall the job.
#
# A stalled fetch from azure.archive.ubuntu.com once held `apt-get install` for
# 55-60 minutes. This script makes apt retry each file, gives up on a dead
# connection in seconds, and bounds each attempt in wall-clock time.
#
# Usage: .github/scripts/apt-install.sh <package>...
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <package>..." >&2
  exit 2
fi

ATTEMPTS=3
ATTEMPT_TIMEOUT=4m

sudo tee /etc/apt/apt.conf.d/80-ci-network >/dev/null <<'CONF'
Acquire::Retries "5";
Acquire::http::Timeout "20";
Acquire::https::Timeout "20";
Acquire::ForceIPv4 "true";
CONF

# `timeout` kills a command that runs past the limit and exits 124; the loop
# then starts the next attempt.
for attempt in $(seq 1 "$ATTEMPTS"); do
  if sudo timeout "$ATTEMPT_TIMEOUT" apt-get update \
    && sudo DEBIAN_FRONTEND=noninteractive timeout "$ATTEMPT_TIMEOUT" apt-get install -y "$@"; then
    exit 0
  fi
  echo "apt attempt ${attempt}/${ATTEMPTS} failed" >&2
done

echo "apt install failed after ${ATTEMPTS} attempts" >&2
exit 1
