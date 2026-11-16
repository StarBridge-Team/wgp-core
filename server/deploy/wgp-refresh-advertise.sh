#!/bin/sh
set -eu

ENV_FILE=${WGP_ENV_FILE:-/etc/wgp-node/env}
RUN_USER=${WGP_RUN_USER:-wgp}
SERVICE=${WGP_SERVICE_NAME:-wgp-node-hobby}
IP_URL=${WGP_IP_CHECK_URL:-https://api.ipify.org}

[ -r "$ENV_FILE" ] || { echo "cannot read $ENV_FILE" >&2; exit 1; }
command -v curl >/dev/null
command -v python3 >/dev/null
command -v flock >/dev/null
exec 9>/run/lock/wgp-refresh-advertise.lock
flock -n 9 || exit 0

NEW_IP=$(curl --fail --silent --show-error --max-time 8 "$IP_URL" | tr -d '\r\n')
python3 - "$NEW_IP" <<'PY'
import ipaddress, sys
try:
    addr = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit("IP check endpoint returned an invalid address")
if addr.version != 4 or not addr.is_global:
    raise SystemExit("advertised address must be a globally routable IPv4 address")
PY

CURRENT=$(sed -n 's/^WGP_ADVERTISE=//p' "$ENV_FILE" | tail -n 1)
[ "$CURRENT" = "$NEW_IP" ] && exit 0

DIR=$(dirname "$ENV_FILE")
TMP=$(mktemp "$DIR/.wgp-env.XXXXXX")
BACKUP=$(mktemp "$DIR/.wgp-env-backup.XXXXXX")
cleanup() { rm -f "$TMP" "$BACKUP"; }
trap cleanup EXIT HUP INT TERM
cp -p "$ENV_FILE" "$BACKUP"
awk -v ip="$NEW_IP" '
  BEGIN { done=0 }
  /^[[:space:]]*#?[[:space:]]*WGP_ADVERTISE=/ {
    if (!done) print "WGP_ADVERTISE=" ip
    done=1
    next
  }
  { print }
  END { if (!done) print "WGP_ADVERTISE=" ip }
' "$ENV_FILE" > "$TMP"
chown root:"$RUN_USER" "$TMP"
chmod 0640 "$TMP"
mv -f "$TMP" "$ENV_FILE"

if ! systemctl restart "$SERVICE"; then
    cp -p "$BACKUP" "$TMP"
    chown root:"$RUN_USER" "$TMP"
    chmod 0640 "$TMP"
    mv -f "$TMP" "$ENV_FILE"
    systemctl restart "$SERVICE" || true
    echo "failed to restart $SERVICE; restored previous environment file" >&2
    exit 1
fi
logger -t wgp-refresh-advertise "updated $SERVICE advertised IPv4 to $NEW_IP"
