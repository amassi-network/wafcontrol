#!/usr/bin/env bash
# Render site-specific deployment files without installing them.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_DIR="${1:-$ROOT_DIR/deployment-rendered}"

required=(
  WAF_DOMAIN WAF_PUBLIC_IP WAF_ADMIN_ALLOW_IP WAF_CRS_VERSION
  WAF_MAPATTACK_HOST
)
for name in "${required[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "[x] Required environment variable is missing: $name" >&2
    exit 2
  fi
done

WAF_ADMIN_PORT="${WAF_ADMIN_PORT:-7000}"
WAF_MAPATTACK_PORT="${WAF_MAPATTACK_PORT:-514}"
WAF_CERT_NAME="${WAF_CERT_NAME:-$WAF_DOMAIN}"
WAF_APP_ROOT="${WAF_APP_ROOT:-/opt/WafControl}"
WAF_SERVICE_USER="${WAF_SERVICE_USER:-root}"
WAF_SERVICE_GROUP="${WAF_SERVICE_GROUP:-www-data}"

[[ "$WAF_DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "[x] Invalid domain."; exit 2; }
[[ "$WAF_CERT_NAME" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "[x] Invalid certificate name."; exit 2; }
[[ "$WAF_PUBLIC_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "[x] This renderer currently requires a public IPv4 address."; exit 2; }
[[ "$WAF_ADMIN_ALLOW_IP" =~ ^[0-9A-Fa-f:./]+$ ]] || { echo "[x] Invalid administration address/CIDR."; exit 2; }
[[ "$WAF_MAPATTACK_HOST" =~ ^[A-Za-z0-9:.-]+$ ]] || { echo "[x] Invalid MapAttack host."; exit 2; }
[[ "$WAF_ADMIN_PORT" =~ ^[0-9]{1,5}$ ]] || { echo "[x] Invalid administration port."; exit 2; }
[[ "$WAF_MAPATTACK_PORT" =~ ^[0-9]{1,5}$ ]] || { echo "[x] Invalid MapAttack port."; exit 2; }
[[ "$WAF_CRS_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "[x] CRS version must be MAJOR.MINOR.PATCH."; exit 2; }
[[ "$WAF_APP_ROOT" =~ ^/[A-Za-z0-9._/-]+$ && "$WAF_APP_ROOT" != *".."* ]] || { echo "[x] Invalid application root."; exit 2; }
[[ "$WAF_SERVICE_USER" =~ ^[A-Za-z_][A-Za-z0-9_-]*$ ]] || { echo "[x] Invalid service user."; exit 2; }
[[ "$WAF_SERVICE_GROUP" =~ ^[A-Za-z_][A-Za-z0-9_-]*$ ]] || { echo "[x] Invalid service group."; exit 2; }

umask 077
mkdir -p "$OUTPUT_DIR"/{nginx,systemd,rsyslog,modsecurity}

render() {
  local source="$1"
  local destination="$2"
  sed     -e "s|@@DOMAIN@@|$WAF_DOMAIN|g"     -e "s|@@PUBLIC_IP@@|$WAF_PUBLIC_IP|g"     -e "s|@@SENSOR_IP@@|$WAF_PUBLIC_IP|g"     -e "s|@@ADMIN_ALLOW_IP@@|$WAF_ADMIN_ALLOW_IP|g"     -e "s|@@ADMIN_PORT@@|$WAF_ADMIN_PORT|g"     -e "s|@@CERT_NAME@@|$WAF_CERT_NAME|g"     -e "s|@@MAPATTACK_HOST@@|$WAF_MAPATTACK_HOST|g"     -e "s|@@MAPATTACK_PORT@@|$WAF_MAPATTACK_PORT|g"     -e "s|@@APP_ROOT@@|$WAF_APP_ROOT|g"     -e "s|@@SERVICE_USER@@|$WAF_SERVICE_USER|g"     -e "s|@@SERVICE_GROUP@@|$WAF_SERVICE_GROUP|g"     "$source" > "$destination"
}

render "$ROOT_DIR/deploy/nginx/wafcontrol-admin.conf.template" "$OUTPUT_DIR/nginx/wafcontrol-admin.conf"
render "$ROOT_DIR/deploy/nginx/site-modsecurity.conf.snippet.template" "$OUTPUT_DIR/nginx/site-modsecurity.conf.snippet"
render "$ROOT_DIR/deploy/rsyslog-wafcontrol-mapattack.conf.template" "$OUTPUT_DIR/rsyslog/60-wafcontrol-mapattack.conf"
render "$ROOT_DIR/deploy/env.production.template" "$OUTPUT_DIR/wafcontrol.env"
for unit in wafcontrol wafcontrol-celery-worker wafcontrol-celery-beat wafcontrol-backup; do
  render "$ROOT_DIR/deploy/systemd/$unit.service.template" "$OUTPUT_DIR/systemd/$unit.service"
done
render "$ROOT_DIR/deploy/systemd/wafcontrol-backup.timer.template" "$OUTPUT_DIR/systemd/wafcontrol-backup.timer"
cp "$ROOT_DIR/deploy/modsecurity/site-before-crs.conf.example" "$OUTPUT_DIR/modsecurity/site-before-crs.conf"

cat > "$OUTPUT_DIR/modsecurity/main.conf" <<EOF
Include /etc/nginx/modsec/modsecurity.conf
Include /etc/nginx/modsec/site-before-crs.conf
Include /etc/nginx/modsec/wafcontrol/REQUEST-890-WAFCONTROL-BEFORE.conf
Include /etc/nginx/modsec/coreruleset-$WAF_CRS_VERSION/crs-setup.conf
Include /etc/nginx/modsec/coreruleset-$WAF_CRS_VERSION/rules/*.conf
Include /etc/nginx/modsec/wafcontrol/RESPONSE-990-WAFCONTROL-AFTER.conf
EOF

if grep -R '@@[A-Z_][A-Z_]*@@' "$OUTPUT_DIR" >/dev/null; then
  echo "[x] At least one unresolved deployment placeholder remains." >&2
  exit 1
fi
chmod 0600 "$OUTPUT_DIR/wafcontrol.env"
find "$OUTPUT_DIR" -type f ! -name wafcontrol.env -exec chmod 0644 {} +

echo "[ok] Rendered deployment files in $OUTPUT_DIR"
echo "[!] Complete secrets and database values in $OUTPUT_DIR/wafcontrol.env"
