#!/bin/sh
# Build the static Landlock runner helper used to sandbox Terraform/OpenTofu runs.
# Requires gcc + libc6-dev (Debian/Ubuntu: apt-get install gcc libc6-dev).
set -eu
cd "$(dirname "$0")"
gcc -static -O2 -Wall -Wextra -o landlock-runner landlock-runner.c
if ./landlock-runner --probe; then
  :
else
  status=$?
  if [ "$status" -ne 2 ]; then
    exit "$status"
  fi
  echo "warning: Landlock is unavailable on this host; the binary was still built" >&2
fi
echo "built: $(pwd)/landlock-runner"
