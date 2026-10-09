#!/usr/bin/env bash
# Asserts the outcome of an earlier action step.
#
# Usage: assert-outcome.sh EXPECTED ACTUAL
#
# The self-test runs the action with continue-on-error so the job keeps going,
# then checks steps.<id>.outcome is "success" or "failure" as expected. A
# missing or wrong outcome fails here, which is the actual test failure.
set -euo pipefail

expected="${1:?usage: assert-outcome.sh EXPECTED ACTUAL}"
actual="${2:?usage: assert-outcome.sh EXPECTED ACTUAL}"

if [[ "$actual" != "$expected" ]]; then
  echo "::error::expected the step outcome to be '$expected', got '$actual'"
  exit 1
fi
echo "step outcome is '$actual' as expected"
