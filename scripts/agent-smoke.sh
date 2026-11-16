#!/usr/bin/env bash
# Agent IPC smoke test (Linux/macOS): start wgp-agent, talk to it over the Unix socket, shut it down.
#
# Checks:
#   1. agent becomes ready and creates its socket
#   2. a second agent on the same endpoint refuses to bind (exit code 3)
#   3. `wgp-agent ping` gets GetVersion + GetSnapshot and triggers ShutdownAgent
#   4. the agent exits by itself through the graceful path (log marker) and removes the socket
#
# ASCII-only on purpose: it runs under whatever locale the CI box has.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT}/target/debug/wgp-agent"
if [ "${1:-}" = "--skip-build" ]; then
  shift
else
  ( cd "$ROOT" && cargo build -p wgp-agent --quiet )
fi
if [ ! -x "$BIN" ]; then
  echo "missing binary: $BIN" >&2
  exit 1
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/wgp-agent-smoke-XXXXXX")"
IDENTITY="$WORK/agent.key"
SOCKET="$WORK/agent.sock"
LOG="$WORK/agent.log"
FAILED=0

cleanup() {
  if [ -n "${AGENT_PID:-}" ] && kill -0 "$AGENT_PID" 2>/dev/null; then
    kill "$AGENT_PID" 2>/dev/null || true
    wait "$AGENT_PID" 2>/dev/null || true
  fi
  if [ "${KEEP_LOGS:-0}" = "0" ]; then
    rm -rf "$WORK"
  else
    echo "logs kept in $WORK"
  fi
}
trap cleanup EXIT

check() {
  local name="$1" ok="$2"
  if [ "$ok" = "1" ]; then
    echo "   PASS  $name"
  else
    echo "   FAIL  $name"
    FAILED=1
  fi
}

wait_for() {
  local pattern="$1" timeout_ms="$2" waited=0
  while [ "$waited" -lt "$timeout_ms" ]; do
    if [ -f "$LOG" ] && grep -q "$pattern" "$LOG"; then
      return 0
    fi
    sleep 0.1
    waited=$((waited + 100))
  done
  return 1
}

echo "== temp dir $WORK"
echo "== start agent"
"$BIN" --identity "$IDENTITY" --socket "$SOCKET" >"$LOG" 2>"$LOG.err" &
AGENT_PID=$!

if wait_for "ready" 15000; then check "agent logged readiness" 1; else check "agent logged readiness" 0; fi
if [ -S "$SOCKET" ]; then check "socket created" 1; else check "socket created" 0; fi

echo "== second agent must refuse the same endpoint (exit code 3)"
set +e
"$BIN" --identity "$WORK/agent2.key" --socket "$SOCKET" >"$WORK/dup.log" 2>&1
DUP_CODE=$?
set -e
if [ "$DUP_CODE" -eq 3 ]; then check "duplicate endpoint refused (exit 3)" 1; else
  echo "   duplicate exit code = $DUP_CODE"
  check "duplicate endpoint refused (exit 3)" 0
fi

echo "== ping over IPC"
set +e
PING_OUT="$("$BIN" ping --socket "$SOCKET" 2>&1)"
PING_CODE=$?
set -e
echo "$PING_OUT"
echo "$PING_OUT" | grep -q "version:" && check "ping reported version" 1 || check "ping reported version" 0
echo "$PING_OUT" | grep -q "snapshot:" && check "ping reported snapshot" 1 || check "ping reported snapshot" 0
[ "$PING_CODE" -eq 0 ] && check "ping exit code 0" 1 || check "ping exit code 0" 0

echo "== agent exits after ShutdownAgent"
EXITED=0
for _ in $(seq 1 100); do
  if ! kill -0 "$AGENT_PID" 2>/dev/null; then EXITED=1; break; fi
  sleep 0.1
done
[ "$EXITED" = "1" ] && check "agent exited by itself" 1 || check "agent exited by itself" 0
wait_for "exited" 2000 && check "agent reached its shutdown path" 1 || check "agent reached its shutdown path" 0
if [ -s "$LOG.err" ]; then
  echo "   agent stderr:"
  sed 's/^/     /' "$LOG.err"
  grep -q "panicked" "$LOG.err" && check "no panic on stderr" 0 || check "no panic on stderr" 1
else
  check "no panic on stderr" 1
fi
if [ -e "$SOCKET" ]; then check "socket cleaned up" 0; else check "socket cleaned up" 1; fi

if [ "$FAILED" -ne 0 ]; then
  echo "RESULT: FAIL"
  exit 1
fi
echo "RESULT: PASS"
exit 0
