#!/usr/bin/env bash
# install-seed-frp.sh -- run a wgp seed on a machine WITHOUT a public IPv4, exposed
# through an FRP relay (frps) that does have one.
#
# ASCII-only on purpose: this file is meant to be piped into `ssh 'bash -s'` from a
# Windows PowerShell shell, which re-encodes piped text with the console codepage.
#
# Topology this sets up:
#   peers/clients --> frps(<public-ip>:21010/23478/23481) --> frpc --> wgp-node(localhost)
#
# What it does (idempotent):
#   1. install wgp-node (from a local binary via WGP_BIN, or download the release)
#   2. install frpc (pinned FRP_VERSION) and write /etc/frp/frpc.toml
#   3. write a systemd unit whose --advertise points at the FRP relay and whose
#      --advertise-*-port are the *remote* ports (not the local ones)
#   4. start both, verify local listeners and that frpc logged in
#   5. print the exact seed endpoints to hand to clients
#
# Required env:
#   FRPS_ADDR      frps host: public IPv4 or DDNS name (used for --advertise too)
#   FRP_TOKEN      shared token configured on frps
# Optional env:
#   FRPS_PORT=7000  ADVERTISE=  REMOTE_DHT=21010  REMOTE_STUN=23478  REMOTE_TCP=23481
#   LOCAL_DHT=11010 LOCAL_STUN=3478 LOCAL_TCP=3481
#   FRP_VERSION=0.61.2  INSTALL_DIR=/opt/wgp-node  WGP_BIN=<path to a built wgp-node>
#   HOBBY=1        install the hobby profile (refuses Forward relaying)
#
# Still manual afterwards: open REMOTE_DHT/REMOTE_STUN (UDP) and REMOTE_TCP (TCP)
# in the frps host's cloud security group AND its host firewall. This script only
# touches the machine it runs on (the NAT'd one).

set -euo pipefail

FRPS_ADDR="${FRPS_ADDR:-}"
FRP_TOKEN="${FRP_TOKEN:-}"
FRPS_PORT="${FRPS_PORT:-7000}"
ADVERTISE="${ADVERTISE:-$FRPS_ADDR}"
REMOTE_DHT="${REMOTE_DHT:-21010}"
REMOTE_STUN="${REMOTE_STUN:-23478}"
REMOTE_TCP="${REMOTE_TCP:-23481}"
LOCAL_DHT="${LOCAL_DHT:-11010}"
LOCAL_STUN="${LOCAL_STUN:-3478}"
LOCAL_TCP="${LOCAL_TCP:-3481}"
FRP_VERSION="${FRP_VERSION:-0.61.2}"
INSTALL_DIR="${INSTALL_DIR:-/opt/wgp-node}"
WGP_BIN="${WGP_BIN:-}"
HOBBY="${HOBBY:-0}"

say()  { printf '\n== %s\n' "$*"; }
ok()   { printf '[ok]   %s\n' "$*"; }
warn() { printf '[warn] %s\n' "$*" >&2; }
die()  { printf '[error] %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "must run as root"
[ -n "$FRPS_ADDR" ] || die "FRPS_ADDR is required (frps public IPv4 or DDNS name)"
[ -n "$FRP_TOKEN" ] || die "FRP_TOKEN is required (must match frps auth.token)"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"

if command -v curl >/dev/null 2>&1; then
  FETCH="curl -fsSL --retry 3 --max-time 180 -o"
elif command -v wget >/dev/null 2>&1; then
  FETCH="wget -q -O"
else
  die "need curl or wget"
fi

say "detect architecture"
case "$(uname -m)" in
  x86_64|amd64)  FRP_ARCH=amd64   ;;
  aarch64|arm64) FRP_ARCH=arm64   ;;
  armv7l|armv7)  FRP_ARCH=arm     ;;
  *) die "unsupported arch for frp: $(uname -m)" ;;
esac
ok "frp arch ${FRP_ARCH}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ---------------------------------------------------------------- 1. wgp-node
say "install wgp-node"
install -d -m 0755 "$INSTALL_DIR"
if [ -n "$WGP_BIN" ]; then
  [ -x "$WGP_BIN" ] || die "WGP_BIN is not executable: $WGP_BIN"
  install -m 0755 "$WGP_BIN" "$INSTALL_DIR/wgp-node"
else
  TAG="${WGP_TAG:-v0.1.0-preview.1}"
  VER="${TAG#v}"
  case "$(uname -m)" in
    x86_64|amd64)  TRIPLE=x86_64-unknown-linux-musl ;;
    aarch64|arm64) TRIPLE=aarch64-unknown-linux-musl ;;
    armv7l|armv7)  TRIPLE=armv7-unknown-linux-musleabihf ;;
    loongarch64)   TRIPLE=loongarch64-unknown-linux-musl ;;
    i686|i386)     TRIPLE=i686-unknown-linux-musl ;;
    *) die "unsupported arch for wgp-node: $(uname -m)" ;;
  esac
  PKG="wgp-${VER}-${TRIPLE}"
  URL="https://github.com/StarBridge-Team/wgp-core/releases/download/${TAG}/${PKG}.tar.gz"
  $FETCH "$TMP/$PKG.tar.gz" "$URL" || die "download failed: $URL"
  if $FETCH "$TMP/$PKG.tar.gz.sha256" "$URL.sha256" 2>/dev/null; then
    ( cd "$TMP" && sha256sum -c "$PKG.tar.gz.sha256" >/dev/null ) && ok "sha256 verified" || die "sha256 mismatch"
  else
    warn "checksum file missing, skipped verification"
  fi
  tar -xzf "$TMP/$PKG.tar.gz" -C "$TMP" || die "extract failed"
  install -m 0755 "$TMP/$PKG/wgp-node" "$INSTALL_DIR/wgp-node"
fi
id wgp >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin wgp
chown -R wgp:wgp "$INSTALL_DIR"
"$INSTALL_DIR/wgp-node" --version || die "wgp-node does not run on this host"
ok "installed $("$INSTALL_DIR/wgp-node" --version)"

# ---------------------------------------------------------------- 2. frpc
say "install frpc ${FRP_VERSION}"
FRP_PKG="frp_${FRP_VERSION}_linux_${FRP_ARCH}"
FRP_URL="https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/${FRP_PKG}.tar.gz"
$FETCH "$TMP/$FRP_PKG.tar.gz" "$FRP_URL" || die "download failed: $FRP_URL"
tar -xzf "$TMP/$FRP_PKG.tar.gz" -C "$TMP" || die "extract failed"
install -d -m 0755 /etc/frp
install -m 0755 "$TMP/$FRP_PKG/frpc" /usr/local/bin/frpc
ok "frpc installed: $(frpc -v 2>/dev/null || echo unknown)"

say "write /etc/frp/frpc.toml (token is written 0600, never printed)"
cat > /etc/frp/frpc.toml <<EOF
serverAddr = "${FRPS_ADDR}"
serverPort = ${FRPS_PORT}
auth.method = "token"
auth.token = "${FRP_TOKEN}"
loginFailExit = false

[[proxies]]
name = "wgp-dht-udp"
type = "udp"
localIP = "127.0.0.1"
localPort = ${LOCAL_DHT}
remotePort = ${REMOTE_DHT}

[[proxies]]
name = "wgp-stun-udp"
type = "udp"
localIP = "127.0.0.1"
localPort = ${LOCAL_STUN}
remotePort = ${REMOTE_STUN}

[[proxies]]
name = "wgp-tcp-signal"
type = "tcp"
localIP = "127.0.0.1"
localPort = ${LOCAL_TCP}
remotePort = ${REMOTE_TCP}
EOF
chmod 0600 /etc/frp/frpc.toml
ok "frpc config written"

cat > /etc/systemd/system/frpc.service <<EOF
[Unit]
Description=frp client (exposes the local wgp seed to a public relay)
After=network-online.target
Wants=network-online.target
Before=wgp-node.service

[Service]
Type=simple
ExecStart=/usr/local/bin/frpc -c /etc/frp/frpc.toml
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

# ---------------------------------------------------------------- 3. wgp-node unit
say "write wgp-node unit (advertise = relay address, remote ports)"
say "  advertise ${ADVERTISE}  dht=${REMOTE_DHT} stun=${REMOTE_STUN} tcp=${REMOTE_TCP}"
HOBBY_FLAG=""
if [ "$HOBBY" = "1" ]; then
  HOBBY_FLAG=" --hobby"
  ok "hobby profile: Forward relaying refused (PCDN self-protection)"
fi

cat > /etc/systemd/system/wgp-node.service <<EOF
[Unit]
Description=wgp seed node behind FRP (DHT + observer/STUN + TCP signaling)
After=network-online.target frpc.service
Wants=network-online.target
Requires=frpc.service

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/wgp-node --bind 0.0.0.0:${LOCAL_DHT} --stun ${LOCAL_STUN} --tcp ${LOCAL_TCP} --identity ${INSTALL_DIR}/node_identity.key --log-level info --advertise ${ADVERTISE} --advertise-dht-port ${REMOTE_DHT} --advertise-stun-port ${REMOTE_STUN} --advertise-tcp-port ${REMOTE_TCP}${HOBBY_FLAG}
Environment=WGP_RUNTIME_WORKERS=2
User=wgp
Group=wgp
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF
ok "units written"

# ---------------------------------------------------------------- 4. start
say "start frpc + wgp-node"
systemctl daemon-reload
systemctl enable frpc >/dev/null 2>&1 || true
systemctl enable wgp-node >/dev/null 2>&1 || true
systemctl restart frpc
sleep 3
systemctl restart wgp-node
sleep 3

say "verify: local listeners"
if ss -lunp 2>/dev/null | grep -Eq ":(${LOCAL_DHT}|${LOCAL_STUN})\b"; then
  ss -lunpt 2>/dev/null | grep -E ":(${LOCAL_DHT}|${LOCAL_STUN}|${LOCAL_TCP})\b" || true
  ok "local ports are listening"
else
  warn "expected local ports are not listening; check: journalctl -u wgp-node -n 50"
fi

say "verify: frpc logged in to ${FRPS_ADDR}:${FRPS_PORT}"
if journalctl -u frpc -n 40 --no-pager 2>/dev/null | grep -qi "login to server success"; then
  ok "frpc tunnel established"
else
  warn "no 'login to server success' yet: check FRP_TOKEN, FRPS_PORT, and that the relay is reachable"
fi
journalctl -u frpc -n 15 --no-pager 2>/dev/null || true

say "verify: wgp-node log"
journalctl -u wgp-node -n 25 --no-pager 2>/dev/null || true

# ---------------------------------------------------------------- 5. summary
cat <<EOF

============================================================
seed is up behind FRP.

  relay  ${FRPS_ADDR}:${FRPS_PORT}  (frps must allow: UDP ${REMOTE_DHT}, UDP ${REMOTE_STUN}, TCP ${REMOTE_TCP})
  local  wgp-node on ${LOCAL_DHT}/${LOCAL_STUN}/${LOCAL_TCP}

client seed endpoints:
  udp://${ADVERTISE}:${REMOTE_DHT}
  tcp://${ADVERTISE}:${REMOTE_TCP}    (signaling fallback only)

REMINDER (cannot be automated from here):
  1. open UDP ${REMOTE_DHT}, UDP ${REMOTE_STUN}, TCP ${REMOTE_TCP} on the FRPS host
     (cloud security group + host firewall) and keep frps' allowPorts in sync;
  2. FRP UDP proxies track visitors: the seed's *outbound* advert pushes are dropped
     until some peer has contacted it first, so this node is best used as a
     queryable seed (PING / FIND_SEEDS / FIND_VALUE), not as a push source;
  3. DDNS on the relay? --advertise accepts the hostname directly; wgp-node
     re-resolves it every WGP_DDNS_REFRESH seconds (default 300) and re-advertises
     with a new epoch when the address changes.

logs:   journalctl -u wgp-node -f    /    journalctl -u frpc -f
stop:   systemctl stop wgp-node frpc
============================================================
EOF
