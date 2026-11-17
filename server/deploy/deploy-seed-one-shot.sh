#!/usr/bin/env bash
# deploy-seed-one-shot.sh -- turn a fresh public Linux box into a wgp seed node.
#
# Why ASCII-only: this file is meant to be piped into `ssh 'bash -s'` from a Windows
# PowerShell shell, and PowerShell re-encodes piped text with the console codepage.
# Non-ASCII bytes would arrive mangled. Same reason as scripts/e2e-local.ps1.
#
# What it does (idempotent, safe to re-run):
#   1. detect arch, download the matching release tarball, verify sha256
#   2. install wgp-node to /opt/wgp-node, create the `wgp` system user
#   3. write a systemd unit (DHT 11010 / observer-STUN 3478 / TCP signaling 3481)
#   4. open the three ports in whatever firewall is active (ufw / firewalld / nft / iptables)
#   5. start it, then verify: ports listening, log says ready, identity survives a restart
#
# Usage (from Windows PowerShell, in the repo root):
#   cmd /c "ssh root@70.39.201.151 \"bash -s -- 70.39.201.151\" < server\deploy\deploy-seed-one-shot.sh"
#
# Args:
#   $1  public IPv4 to advertise (so clients find the observer by themselves).
#       Pass `none` to skip advertising (clients then need --observer <ip>:3478).
#   $2  release tag (default: v0.1.0-preview.1)
#
# Still manual after this script: open the same three ports in the cloud
# provider's security group (Aliyun/Tencent/AWS console) -- the script cannot.

set -euo pipefail

ADVERTISE="${1:-}"
TAG="${2:-v0.1.0-preview.1}"
VER="${TAG#v}"
REPO="StarBridge-Team/wgp-core"

PORT_DHT=11010
PORT_STUN=3478
PORT_TCP=3481
INSTALL_DIR=/opt/wgp-node

say()  { printf '\n== %s\n' "$*"; }
ok()   { printf '[ok]   %s\n' "$*"; }
warn() { printf '[warn] %s\n' "$*" >&2; }
die()  { printf '[error] %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "must run as root (ssh root@<host>)"
command -v systemctl >/dev/null 2>&1 || die "systemd is required on the seed host"

# ---------------------------------------------------------------- 1. download
say "detect arch and download"
case "$(uname -m)" in
  x86_64|amd64)      TRIPLE=x86_64-unknown-linux-musl ;;
  aarch64|arm64)     TRIPLE=aarch64-unknown-linux-musl ;;
  armv7l|armv7)      TRIPLE=armv7-unknown-linux-musleabihf ;;
  loongarch64)       TRIPLE=loongarch64-unknown-linux-musl ;;
  i686|i386)         TRIPLE=i686-unknown-linux-musl ;;
  *) die "unsupported arch: $(uname -m)" ;;
esac
PKG="wgp-${VER}-${TRIPLE}"
URL="https://github.com/${REPO}/releases/download/${TAG}/${PKG}.tar.gz"
ok "arch $(uname -m) -> ${TRIPLE}"
ok "package ${PKG}"

if command -v curl >/dev/null 2>&1; then
  FETCH="curl -fsSL --retry 3 --max-time 180 -o"
elif command -v wget >/dev/null 2>&1; then
  FETCH="wget -q -O"
else
  die "need curl or wget on the seed host"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
$FETCH "$TMP/$PKG.tar.gz" "$URL" || die "download failed: $URL"
ok "downloaded $(du -h "$TMP/$PKG.tar.gz" | cut -f1)"

if $FETCH "$TMP/$PKG.tar.gz.sha256" "$URL.sha256" 2>/dev/null; then
  ( cd "$TMP" && sha256sum -c "$PKG.tar.gz.sha256" >/dev/null ) \
    && ok "sha256 verified" || die "sha256 mismatch"
else
  warn "checksum file missing, skipped verification"
fi

tar -xzf "$TMP/$PKG.tar.gz" -C "$TMP" || die "extract failed"
SRC="$TMP/$PKG"
[ -x "$SRC/wgp-node" ] || die "wgp-node not found inside the tarball"
ok "extracted"

# ---------------------------------------------------------------- 2. install
say "install to $INSTALL_DIR"
install -d -m 0755 "$INSTALL_DIR"
install -m 0755 "$SRC/wgp-node" "$INSTALL_DIR/wgp-node"
id wgp >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin wgp
chown -R wgp:wgp "$INSTALL_DIR"
"$INSTALL_DIR/wgp-node" --version || die "binary does not run on this host"
ok "installed $("$INSTALL_DIR/wgp-node" --version)"

# ---------------------------------------------------------------- 3. unit
say "write systemd unit"
if [ -n "$ADVERTISE" ] && [ "$ADVERTISE" != "none" ]; then
  ENV_LINES="Environment=WGP_ADVERTISE=${ADVERTISE}
Environment=WGP_RUNTIME_WORKERS=2"
  ok "advertising ${ADVERTISE} (clients will discover the observer automatically)"
else
  ENV_LINES="Environment=WGP_RUNTIME_WORKERS=2"
  warn "no --advertise: clients must pass --observer <this-host>:$PORT_STUN"
fi

cat > /etc/systemd/system/wgp-node.service <<EOF
[Unit]
Description=wgp seed node (DHT seed + observer/STUN + TCP signaling)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/wgp-node --bind 0.0.0.0:${PORT_DHT} --stun ${PORT_STUN} --tcp ${PORT_TCP} --identity ${INSTALL_DIR}/node_identity.key --log-level info
${ENV_LINES}
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
ok "unit written"

# ---------------------------------------------------------------- 4. firewall
say "open UDP ${PORT_DHT}, UDP ${PORT_STUN}, TCP ${PORT_TCP}"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow "${PORT_DHT}/udp"  >/dev/null && ufw allow "${PORT_STUN}/udp" >/dev/null \
    && ufw allow "${PORT_TCP}/tcp" >/dev/null && ok "ufw rules added"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port="${PORT_DHT}/udp" >/dev/null
  firewall-cmd --permanent --add-port="${PORT_STUN}/udp" >/dev/null
  firewall-cmd --permanent --add-port="${PORT_TCP}/tcp" >/dev/null
  firewall-cmd --reload >/dev/null && ok "firewalld rules added"
elif command -v nft >/dev/null 2>&1 && nft list table inet filter >/dev/null 2>&1; then
  nft add rule inet filter input udp dport "{ ${PORT_DHT}, ${PORT_STUN} }" accept 2>/dev/null \
    && ok "nft rules appended to inet filter" \
    || warn "could not append nft rules; open the ports by hand"
  nft add rule inet filter input tcp dport "${PORT_TCP}" accept 2>/dev/null || true
elif command -v iptables >/dev/null 2>&1; then
  iptables -C INPUT -p udp --dport "$PORT_DHT"  -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport "$PORT_DHT"  -j ACCEPT
  iptables -C INPUT -p udp --dport "$PORT_STUN" -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport "$PORT_STUN" -j ACCEPT
  iptables -C INPUT -p tcp --dport "$PORT_TCP"  -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "$PORT_TCP"  -j ACCEPT
  ok "iptables rules added (not persistent across reboot unless you save them)"
else
  warn "no active firewall detected; nothing to open (check the cloud security group anyway)"
fi

# ---------------------------------------------------------------- 5. start
say "start"
systemctl daemon-reload
systemctl enable wgp-node >/dev/null 2>&1 || true
systemctl restart wgp-node
sleep 3

say "verify: ports"
if ss -lunp 2>/dev/null | grep -Eq ":(${PORT_DHT}|${PORT_STUN})\b" || ss -ltnp 2>/dev/null | grep -Eq ":${PORT_TCP}\b"; then
  ss -lunpt 2>/dev/null | grep -E ":(${PORT_DHT}|${PORT_STUN}|${PORT_TCP})\b" || true
  ok "ports are listening"
else
  warn "expected ports are not listening yet"
fi

say "verify: log"
journalctl -u wgp-node -n 25 --no-pager || true

say "verify: identity survives a restart"
NODE_ID_1="$(journalctl -u wgp-node -n 60 --no-pager | grep -o 'node_id=\[[0-9a-f, ]*\]' | tail -n 1 || true)"
systemctl restart wgp-node
sleep 3
NODE_ID_2="$(journalctl -u wgp-node -n 60 --no-pager | grep -o 'node_id=\[[0-9a-f, ]*\]' | tail -n 1 || true)"
if [ -n "$NODE_ID_1" ] && [ "$NODE_ID_1" = "$NODE_ID_2" ]; then
  ok "node_id stable across restart: $NODE_ID_1"
else
  warn "node_id changed or not found (1='$NODE_ID_1' 2='$NODE_ID_2') -- check $INSTALL_DIR/node_identity.key"
fi

say "verify: advertised address is really this box"
if [ -n "$ADVERTISE" ] && [ "$ADVERTISE" != "none" ]; then
  DETECTED="$(curl -4 -s --max-time 8 https://ifconfig.me 2>/dev/null || true)"
  if [ -z "$DETECTED" ]; then
    warn "could not detect the outbound public IP; check by hand that $ADVERTISE is this host"
  elif [ "$DETECTED" = "$ADVERTISE" ]; then
    ok "outbound public IP matches $ADVERTISE"
  else
    warn "advertise=$ADVERTISE but outbound public IP looks like $DETECTED -- clients would be handed an address that may not reach this box"
  fi
fi

# ---------------------------------------------------------------- summary
ADDR_FOR_PRINT="${ADVERTISE}"
[ "$ADDR_FOR_PRINT" = "none" ] && ADDR_FOR_PRINT="<this-host>"

cat <<EOF

============================================================
seed is up on ${ADDR_FOR_PRINT}
  UDP ${PORT_DHT}  DHT / signaling
  UDP ${PORT_STUN}  observer (STUN)
  TCP ${PORT_TCP}  signaling fallback

REMINDER: open the same three ports in the cloud provider
security group (Aliyun / Tencent / AWS console). The script
cannot do that, and the seed is unreachable without it.

client commands (Windows, same release tag):
  host  : wgp-client host -n <name> -k <key> -p udp://${ADDR_FOR_PRINT}:${PORT_DHT} --expose 25565
  joiner: wgp-client join -n <name> -k <key> -p udp://${ADDR_FOR_PRINT}:${PORT_DHT} --forward 25565

  (with --advertise the clients pick the observer by themselves;
   no --observer needed)

logs:   journalctl -u wgp-node -f
stop:   systemctl stop wgp-node
============================================================
EOF
