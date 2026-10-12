#!/bin/sh
# Restart the API on a fresh btc_safe_dev DB (CHAIN=memory keeps chain state in memory only,
# so old wallets would show stale balances). Dev DB only. Creates the dev admin account used
# by the e2e scripts (e2e/session.mjs): dev@btcsafe.local / devpassword-123. Keep two-factor off
# on that account: the scripts log it in with a password only.
set -e
cd "$(dirname "$0")/../.."
pkill -f target/debug/btc-safe-api || true
sleep 1
dropdb -h /tmp --if-exists btc_safe_dev && createdb -h /tmp btc_safe_dev
export DATABASE_URL="postgres:///btc_safe_dev?host=/tmp&user=$USER"
cargo build -q -p btc-safe-api
# OPEN_SIGNUP=1: e2e/auth.mjs and e2e/csp.mjs exercise self-signup (/signup).
CHAIN=memory COOKIE_SECURE=false SYNC_SECS=5 RATE_IP=6000/2000 RATE_LOGIN=600/100 RATE_SIGNUP=600/100 OPEN_SIGNUP=1 \
  nohup ./target/debug/btc-safe-api > /tmp/btcsafe-api.log 2>&1 &
sleep 2
TOKEN=$(./target/debug/btc-safe-api invite dev@btcsafe.local --admin | sed 's/.*token=//')
curl -s -o /dev/null -w "dev account: %{http_code}\n" -H 'content-type: application/json' \
  localhost:8080/auth/setup -d "{\"token\":\"$TOKEN\",\"password\":\"devpassword-123\"}"
curl -s localhost:8080/health
