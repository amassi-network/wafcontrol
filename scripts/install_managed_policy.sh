#!/usr/bin/env bash
# Install WAFControl-owned policy includes around the active CRS rule include.
set -euo pipefail

export PATH="/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin:$PATH"

POLICY_DIR="${1:-/etc/nginx/modsec/wafcontrol}"
SERVICE_USER="${WAFCONTROL_SERVICE_USER:-wafcontrol}"
MAIN_CONF="/etc/nginx/modsec/main.conf"
BEFORE_FILE="$POLICY_DIR/REQUEST-890-WAFCONTROL-BEFORE.conf"
AFTER_FILE="$POLICY_DIR/RESPONSE-990-WAFCONTROL-AFTER.conf"

if [[ ! "$POLICY_DIR" =~ ^/etc/nginx/modsec/[A-Za-z0-9._/-]+$ ]] || [[ "$POLICY_DIR" == *".."* ]]; then
  echo "[x] Policy directory must be a safe absolute path below /etc/nginx/modsec."
  exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
  echo "[x] Run this installer as root."
  exit 1
fi
if ! command -v nginx >/dev/null 2>&1 || [[ ! -f "$MAIN_CONF" ]]; then
  echo "[x] Nginx ModSecurity main.conf was not found."
  exit 1
fi
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  echo "[x] Service account does not exist: $SERVICE_USER"
  exit 1
fi

POLICY_GROUP="$(id -gn "$SERVICE_USER")"
install -d -o "$SERVICE_USER" -g "$POLICY_GROUP" -m 0750 "$POLICY_DIR"
for managed_file in "$BEFORE_FILE" "$AFTER_FILE"; do
  if [[ ! -e "$managed_file" ]]; then
    install -o "$SERVICE_USER" -g "$POLICY_GROUP" -m 0640 /dev/null "$managed_file"
  fi
done

TEMP_DIR="$(mktemp -d -t wafcontrol-policy-XXXXXX)"
trap 'rm -rf "$TEMP_DIR"' EXIT
cp -a "$MAIN_CONF" "$TEMP_DIR/main.conf.previous"

awk -v before_line="Include $BEFORE_FILE" -v after_line="Include $AFTER_FILE" '
  $0 != before_line && $0 != after_line { print }
' "$MAIN_CONF" > "$TEMP_DIR/main.conf.clean"
if ! awk -v before="Include $BEFORE_FILE" -v after="Include $AFTER_FILE" '
  /Include[[:space:]].*rules\/\*\.conf/ && !inserted {
    print before
    print
    print after
    inserted = 1
    next
  }
  { print }
  END { if (!inserted) exit 42 }
' "$TEMP_DIR/main.conf.clean" > "$TEMP_DIR/main.conf.candidate"; then
  echo "[x] Active CRS rules include was not found; main.conf was not changed."
  exit 1
fi

install -o root -g root -m 0644 "$TEMP_DIR/main.conf.candidate" "$MAIN_CONF"
if ! nginx -t; then
  cp -a "$TEMP_DIR/main.conf.previous" "$MAIN_CONF"
  nginx -t || true
  echo "[x] Validation failed; main.conf was restored."
  exit 1
fi
if ! nginx -s reload; then
  cp -a "$TEMP_DIR/main.conf.previous" "$MAIN_CONF"
  nginx -t || true
  nginx -s reload || true
  echo "[x] Reload failed; main.conf was restored and reloaded."
  exit 1
fi

echo "[ok] WAFControl managed policy includes installed."
echo "[ok] Before CRS: $BEFORE_FILE"
echo "[ok] After CRS:  $AFTER_FILE"

