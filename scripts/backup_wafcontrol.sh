#!/usr/bin/env bash
set -euo pipefail

APP_ROOT="${WAFCONTROL_APP_ROOT:-/opt/WafControl}"
ENV_FILE="${WAFCONTROL_ENV_FILE:-$APP_ROOT/.env}"
BACKUP_DIR="${WAFCONTROL_BACKUP_DIR:-/var/backups/wafcontrol}"
RETENTION_DAYS="${WAFCONTROL_BACKUP_RETENTION_DAYS:-14}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[x] Backup must run as root." >&2
  exit 1
fi
if [[ "$APP_ROOT" != /* || "$APP_ROOT" == "/" || "$APP_ROOT" == *".."* ]]; then
  echo "[x] Unsafe application root." >&2
  exit 2
fi
if [[ "$BACKUP_DIR" != /var/backups/* || "$BACKUP_DIR" == "/var/backups/"*"/.."* ]]; then
  echo "[x] Backup directory must be below /var/backups." >&2
  exit 2
fi
[[ "$RETENTION_DAYS" =~ ^[0-9]+$ ]] || {
  echo "[x] Invalid retention." >&2
  exit 2
}
[[ -r "$ENV_FILE" ]] || {
  echo "[x] Environment file is not readable: $ENV_FILE" >&2
  exit 1
}

set -a
# The root-owned deployment environment is trusted input.
. "$ENV_FILE"
set +a
for name in DB_NAME DB_USER DB_PASS DB_HOST DB_PORT; do
  [[ -n "${!name:-}" ]] || {
    echo "[x] Missing $name in $ENV_FILE" >&2
    exit 1
  }
done

install -d -o root -g root -m 0700 "$BACKUP_DIR"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
db_file="$BACKUP_DIR/wafcontrol-db-$stamp.dump"
code_file="$BACKUP_DIR/wafcontrol-code-$stamp.tar.gz"
config_file="$BACKUP_DIR/wafcontrol-config-$stamp.tar.gz"
checksum_file="$BACKUP_DIR/wafcontrol-$stamp.sha256"

PGPASSWORD="$DB_PASS" pg_dump \
  -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
  -Fc -f "$db_file"

tar \
  --exclude=.git --exclude=.env --exclude=venv --exclude=.venv \
  --exclude=staticfiles --exclude=celerybeat-schedule.db \
  -czf "$code_file" -C "$(dirname "$APP_ROOT")" "$(basename "$APP_ROOT")"

config_paths=()
for path in \
  /etc/nginx \
  /etc/rsyslog.d/60-wafcontrol-mapattack.conf \
  /etc/systemd/system/wafcontrol.service \
  /etc/systemd/system/wafcontrol-celery-worker.service \
  /etc/systemd/system/wafcontrol-celery-beat.service \
  /etc/systemd/system/wafcontrol-backup.service \
  /etc/systemd/system/wafcontrol-backup.timer; do
  [[ -e "$path" ]] && config_paths+=("${path#/}")
done
if [[ "${#config_paths[@]}" -eq 0 ]]; then
  echo "[x] No deployment configuration path was found." >&2
  exit 1
fi
tar -C / -czf "$config_file" "${config_paths[@]}"

sha256sum "$db_file" "$code_file" "$config_file" > "$checksum_file"

find "$BACKUP_DIR" -maxdepth 1 -type f \
  \( -name 'wafcontrol-db-*.dump' \
     -o -name 'wafcontrol-code-*.tar.gz' \
     -o -name 'wafcontrol-config-*.tar.gz' \
     -o -name 'wafcontrol-*.sha256' \) \
  -mtime "+$RETENTION_DAYS" -delete

echo "[ok] Backup completed: $stamp"
echo "[!] The configuration archive may contain sensitive site configuration;"
echo "    encrypt and restrict any off-host copy."
