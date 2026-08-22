#!/bin/sh
# Build the static Landlock runner helper used to sandbox Terraform/OpenTofu runs.
# Requires gcc + libc6-dev (Debian/Ubuntu: apt-get install gcc libc6-dev).
set -eu
umask 022

# Keep the compiler overridable for cross-builds, but don't inherit arbitrary
# CFLAGS/LDFLAGS from a caller. The helper is security-sensitive and should be
# built with the same warnings and hardening in local builds, CI, and Docker.
CC=${CC:-cc}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$script_dir"

"$CC" \
  -std=c11 -O2 -Wall -Wextra -Werror \
  -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -fstack-protector-strong -fPIE \
  -static-pie -s \
  -Wl,-z,relro,-z,now,-z,noexecstack \
  -o landlock-runner landlock-runner.c
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
