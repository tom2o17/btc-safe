#!/usr/bin/env bash
# Watch-only invariant (DESIGN.md §6.1). Fails if any non-test crate can touch private keys.
set -euo pipefail
cd "$(dirname "$0")/.."

# 1. Clippy with disallowed types/methods denied, across all targets.
cargo clippy --workspace --all-targets -- -D warnings

# 2. Only testkit may opt out of the lint.
offenders=$(grep -rln "allow(clippy::disallowed_types\|allow(clippy::disallowed_methods" crates --include=*.rs | grep -v '^crates/testkit/' || true)
if [ -n "$offenders" ]; then echo "disallowed-type opt-out outside testkit: $offenders"; exit 1; fi

# 3. testkit must only ever be a dev-dependency.
for m in crates/*/Cargo.toml; do
  if awk '/^\[dependencies\]/{d=1;next} /^\[/{d=0} d && /btc-safe-testkit/' "$m" | grep -q .; then
    echo "$m depends on testkit outside [dev-dependencies]"; exit 1
  fi
done

# 4. The release binary's dependency graph doesn't include testkit.
if cargo tree -p btc-safe-api -e normal --prefix none | grep -q btc-safe-testkit; then
  echo "testkit reachable from the api binary"; exit 1
fi
echo "watch-only invariant: OK"
