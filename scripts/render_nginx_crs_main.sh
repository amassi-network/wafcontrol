#!/usr/bin/env bash
# Render Nginx main.conf in this order: base, WAF before, CRS, WAF after.
set -euo pipefail

CURRENT_CONF="${1:-}"
CRS_DIR="${2:-}"
OUTPUT_CONF="${3:-}"
POLICY_DIR="${WAFCONTROL_POLICY_DIR:-/etc/nginx/modsec/wafcontrol}"
BEFORE_FILE="${POLICY_DIR}/REQUEST-890-WAFCONTROL-BEFORE.conf"
AFTER_FILE="${POLICY_DIR}/RESPONSE-990-WAFCONTROL-AFTER.conf"

if [[ -z "$CURRENT_CONF" || -z "$CRS_DIR" || -z "$OUTPUT_CONF" ]]; then
  echo "Usage: $0 CURRENT_MAIN_CONF CRS_DIRECTORY OUTPUT_CONF" >&2
  exit 2
fi
if [[ "$CURRENT_CONF" == "$OUTPUT_CONF" ]]; then
  echo "Input and output files must be different." >&2
  exit 2
fi
if [[ "$CRS_DIR" != /* || "$POLICY_DIR" != /* ]]; then
  echo "CRS and policy directories must be absolute paths." >&2
  exit 2
fi

if [[ -f "$CURRENT_CONF" ]]; then
  awk -v before="Include $BEFORE_FILE" -v after="Include $AFTER_FILE" '
    $0 == before || $0 == after { next }
    /Include[[:space:]].*crs-setup\.conf/ { next }
    /Include[[:space:]].*rules\/\*\.conf/ { next }
    { print }
  ' "$CURRENT_CONF" > "$OUTPUT_CONF"
else
  : > "$OUTPUT_CONF"
fi

if [[ -f "$BEFORE_FILE" ]]; then
  printf 'Include %s\n' "$BEFORE_FILE" >> "$OUTPUT_CONF"
fi
printf 'Include %s/crs-setup.conf\n' "$CRS_DIR" >> "$OUTPUT_CONF"
printf 'Include %s/rules/*.conf\n' "$CRS_DIR" >> "$OUTPUT_CONF"
if [[ -f "$AFTER_FILE" ]]; then
  printf 'Include %s\n' "$AFTER_FILE" >> "$OUTPUT_CONF"
fi
