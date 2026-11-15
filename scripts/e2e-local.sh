#!/usr/bin/env bash
# Local end-to-end check on Linux with real binaries, loopback only (no real network needed).
# Same scenarios as scripts/e2e-local.ps1 -- see that file for the full description:
#   default      one seed, observer given by hand
#   --discovery  two advertising seeds; each client knows only one of them and no observer
#   --hobby      the only seed (or seed 2 with --discovery) is a wgp-node-hobby
#
# usage: scripts/e2e-local.sh <bin-dir> [--discovery] [--hobby] [--keep-logs]
#   <bin-dir> holds wgp-node, wgp-node-hobby, wgp-client and examples/echo_tool, e.g.
#     cargo build --release --bins --examples && scripts/e2e-local.sh target/release
# Exit code 0 = all checks passed.
set -u -o pipefail

usage() {
  echo "usage: $0 <bin-dir> [--discovery] [--hobby] [--keep-logs]" >&2
  exit 2
}
[ $# -ge 1 ] || usage
BIN="$(cd "$1" 2>/dev/null && pwd)" || usage
shift
DISCOVERY=0
HOBBY=0
KEEP=0
for arg in "$@"; do
  case "$arg" in
    --discovery) DISCOVERY=1 ;;
    --hobby) HOBBY=1 ;;
    --keep-logs) KEEP=1 ;;
    *) usage ;;
  esac
done
for exe in wgp-node wgp-node-hobby wgp-client examples/echo_tool; do
  [ -x "$BIN/$exe" ] || { echo "missing executable: $BIN/$exe" >&2; exit 2; }
done

SEED_PORT=21010
STUN_PORT=23478
TCP_PORT=23481
SEED2_PORT=21011
STUN2_PORT=23479
TCP2_PORT=23482
SERVICE_PORT=45565
FORWARD_PORT=45566
UDP_SERVICE_PORT=45532
UDP_FORWARD_PORT=45533
BYTES=4194304

WORK="$(mktemp -d -t wgp-e2e-XXXXXXXX)"
PIDS=()
FAILED=0
ROOM_KEY="$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"

# log markers printed by the programs
MARK_NODE_READY='已就绪'
MARK_JOINED='已入表'
MARK_TUNNEL_READY='隧道] 就绪'
MARK_SEED_DIR_ONE='种子目录：1 个'
MARK_SEED_FOUND='[发现] 种子 '
MARK_STORAGE='[存储]'
MARK_AUTO_OBSERVER='[观察者] 自动选用'

start_bg() { # name exe args...
  local name="$1"
  shift
  (cd "$WORK" && exec "$@" >"$WORK/$name.out" 2>"$WORK/$name.err") &
  PIDS+=("$!")
  printf '  started %-8s pid=%s\n' "$name" "$!"
}

wait_log() { # name marker timeout_sec [count]
  local name="$1" marker="$2" timeout="$3" count="${4:-1}" tries=0 hits
  while [ "$tries" -lt $((timeout * 5)) ]; do
    hits="$(grep -c -F -- "$marker" "$WORK/$name.out" 2>/dev/null)"
    [ "${hits:-0}" -ge "$count" ] && return 0
    sleep 0.2
    tries=$((tries + 1))
  done
  return 1
}

storage_of() { # name -> storage node address chosen by that client
  grep -F -- "$MARK_STORAGE" "$WORK/$1.out" 2>/dev/null | head -n 1 | sed 's/.*= //; s/（.*//'
}

step() { # title command...
  local title="$1"
  shift
  echo "== $title"
  if "$@"; then
    echo '   PASS'
    return 0
  fi
  echo '   FAIL'
  FAILED=1
  return 1
}

run_check() { # echo_tool arguments...
  "$BIN/examples/echo_tool" "$@" 2>&1 | sed 's/^/   /'
}

client_args() { # command identity seed_port extra... -> CLIENT_ARGS
  local command="$1" identity="$2" seed="$3"
  shift 3
  CLIENT_ARGS=("$command" --name e2e-local --key "$ROOM_KEY"
    --seed "udp://127.0.0.1:$seed" -i "$WORK/$identity")
  # discovery mode: no --observer on purpose, the client has to find one by itself
  [ "$DISCOVERY" -eq 1 ] || CLIENT_ARGS+=(--observer "127.0.0.1:$STUN_PORT")
  CLIENT_ARGS+=("$@")
}

# All clients share the source IP 127.0.0.1, hence one observer rate-limit bucket (default
# 12 requests / 10 s; one negotiation costs 4). Raise the limit for the test seeds.
node_args() { # port stun tcp identity -> NODE_ARGS
  NODE_ARGS=(--bind "127.0.0.1:$1" --stun "$2" --tcp "$3"
    --observer-rate-limit 1000 --identity "$WORK/$4")
}

cleanup() {
  local pid name
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
  if [ "$FAILED" -ne 0 ] || [ "$KEEP" -eq 1 ]; then
    echo "== logs kept in $WORK"
    for name in node node2 host joiner joiner2; do
      [ -s "$WORK/$name.out" ] || [ -s "$WORK/$name.err" ] || continue
      echo "---- $name (last 25 lines) ----"
      tail -n 25 "$WORK/$name.out" 2>/dev/null | sed 's/^/   /'
      if [ -s "$WORK/$name.err" ]; then
        echo "---- $name stderr (last 10 lines) ----"
        tail -n 10 "$WORK/$name.err" | sed 's/^/   /'
      fi
    done
  else
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

seeds_met() {
  wait_log node "$MARK_SEED_DIR_ONE" 15 && wait_log node2 "$MARK_SEED_DIR_ONE" 15
}
same_storage() {
  local a b
  a="$(storage_of host)"
  b="$(storage_of joiner)"
  echo "   host -> $a ; joiner -> $b"
  [ -n "$a" ] && [ "$a" = "$b" ]
}
storage_is_seed1() { [ "$(storage_of host)" = "127.0.0.1:$SEED_PORT" ]; }
auto_observer() {
  wait_log host "$MARK_AUTO_OBSERVER" 5 && wait_log joiner "$MARK_AUTO_OBSERVER" 5
}

HOST_SEED=$SEED_PORT
JOINER_SEED=$SEED_PORT
echo "== start processes (work dir: $WORK)"
if [ "$DISCOVERY" -eq 1 ]; then
  JOINER_SEED=$SEED2_PORT
  NODE2_EXE=wgp-node
  [ "$HOBBY" -eq 1 ] && NODE2_EXE=wgp-node-hobby
  node_args "$SEED_PORT" "$STUN_PORT" "$TCP_PORT" node.key
  start_bg node "$BIN/wgp-node" "${NODE_ARGS[@]}" --advertise 127.0.0.1
  node_args "$SEED2_PORT" "$STUN2_PORT" "$TCP2_PORT" node2.key
  start_bg node2 "$BIN/$NODE2_EXE" "${NODE_ARGS[@]}" --advertise 127.0.0.1 \
    --peers "udp://127.0.0.1:$SEED_PORT"
else
  NODE_EXE=wgp-node
  [ "$HOBBY" -eq 1 ] && NODE_EXE=wgp-node-hobby
  node_args "$SEED_PORT" "$STUN_PORT" "$TCP_PORT" node.key
  start_bg node "$BIN/$NODE_EXE" "${NODE_ARGS[@]}"
fi
start_bg echo-tcp "$BIN/examples/echo_tool" serve-tcp "$SERVICE_PORT"
start_bg echo-udp "$BIN/examples/echo_tool" serve-udp "$UDP_SERVICE_PORT"

step 'seed node ready' wait_log node "$MARK_NODE_READY" 15 || exit 1
if [ "$DISCOVERY" -eq 1 ]; then
  step 'second seed ready' wait_log node2 "$MARK_NODE_READY" 15 || exit 1
  step 'the two seeds discovered each other' seeds_met
fi

client_args host host.key "$HOST_SEED" --expose "$SERVICE_PORT" --expose-udp "$UDP_SERVICE_PORT"
start_bg host "$BIN/wgp-client" "${CLIENT_ARGS[@]}"
step 'host created the room' wait_log host "$MARK_JOINED" 20 || exit 1

JOINER_EXTRA=(--forward "$FORWARD_PORT:$SERVICE_PORT" --forward-udp "$UDP_FORWARD_PORT:$UDP_SERVICE_PORT")
client_args join joiner.key "$JOINER_SEED" "${JOINER_EXTRA[@]}"
start_bg joiner "$BIN/wgp-client" "${CLIENT_ARGS[@]}"
JOINER_PID=$!
JOINED=0
step 'joiner entered the room table' wait_log joiner "$MARK_JOINED" 30 && JOINED=1

if [ "$DISCOVERY" -eq 1 ]; then
  step 'host (configured with seed 1 only) learned both seeds' wait_log host "$MARK_SEED_FOUND" 5 2
  step 'joiner (configured with seed 2 only) learned both seeds' wait_log joiner "$MARK_SEED_FOUND" 5 2
  step 'both clients picked the same storage node' same_storage
  if [ "$HOBBY" -eq 1 ]; then
    step 'the storage node is the relaying seed, not the hobby one' storage_is_seed1
  fi
  step 'both clients found an observer without --observer' auto_observer
fi

if [ "$JOINED" -eq 1 ] && step 'tunnel ready on joiner (punch + handshake)' wait_log joiner "$MARK_TUNNEL_READY" 60; then
  step "TCP forward: $BYTES bytes round trip through 127.0.0.1:$FORWARD_PORT" \
    run_check check-tcp "127.0.0.1:$FORWARD_PORT" "$BYTES"
  step "UDP forward: datagrams through 127.0.0.1:$UDP_FORWARD_PORT" \
    run_check check-udp "127.0.0.1:$UDP_FORWARD_PORT" 40

  echo '== simulate joiner crash, then restart it'
  kill -9 "$JOINER_PID" 2>/dev/null
  wait "$JOINER_PID" 2>/dev/null
  sleep 0.5
  start_bg joiner2 "$BIN/wgp-client" "${CLIENT_ARGS[@]}"
  if step 'tunnel ready again after restart (re-punch, new session key)' wait_log joiner2 "$MARK_TUNNEL_READY" 90; then
    step 'TCP forward works again after reconnect' run_check check-tcp "127.0.0.1:$FORWARD_PORT" 1048576
  fi
fi

if [ "$FAILED" -ne 0 ]; then
  echo 'RESULT: FAIL'
  exit 1
fi
echo 'RESULT: PASS'
exit 0
