#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${CI_TON_ARTIFACT_DIR:-${RUNNER_TEMP:-/tmp}/pillar-ton-release-gate}"
mkdir -p "$out"
cd "$root"

{
  echo "identityCapturedAtUtc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "identityCapturedAtKst=$(TZ=Asia/Seoul date '+%Y-%m-%d %H:%M KST')"
  echo "sourceCommit=$(git rev-parse HEAD)"
  echo "testSourceSHA256=$(shasum -a 256 crates/pillar-runtime/src/tests/transport_wire_tests.rs | cut -d' ' -f1)"
  echo "cargoLockSHA256=$(shasum -a 256 Cargo.lock | cut -d' ' -f1)"
  echo "runner=$(uname -a)"
  sw_vers
  cargo --version
  rustc --version
} > "$out/source-identity.txt" 2>&1

command='cargo test --locked --release -p pillar-runtime tests::transport_wire_tests::ton_depth_limit_and_trace_traversal_are_worker_safe_over_http -- --exact --nocapture'
printf '%s\n' "$command" > "$out/command.txt"
TZ=Asia/Seoul date '+%Y-%m-%d %H:%M KST' > "$out/started-at-kst.txt"
set +e
/usr/bin/time -l cargo test --locked --release -p pillar-runtime tests::transport_wire_tests::ton_depth_limit_and_trace_traversal_are_worker_safe_over_http -- --exact --nocapture > "$out/cargo.stdout" 2> "$out/cargo.stderr"
status=$?
printf '%s\n' "$status" > "$out/exit-status.txt"
TZ=Asia/Seoul date '+%Y-%m-%d %H:%M KST' > "$out/finished-at-kst.txt"
node scripts/ci-ton-release-summary.mjs "$out" "$status"
summary_status=$?
set -e
if [[ "$status" -ne 0 || "$summary_status" -ne 0 ]]; then
  exit 1
fi
