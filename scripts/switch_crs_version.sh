#!/usr/bin/env bash
# Safely switch to a selected stable CRS release.
set -euo pipefail

export PATH="/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin:$PATH"

VERSION="${1:-}"
[[ "$VERSION" == v* ]] || VERSION="v$VERSION"
VERSION_NUM="${VERSION#v}"
if [[ ! "$VERSION_NUM" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "[✗] Invalid CRS version. Expected vMAJOR.MINOR.PATCH."
  exit 2
fi

for tool in wget tar; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "[✗] Required tool is missing: $tool"
    exit 1
  fi
done

SERVER="none"
if systemctl is-active --quiet nginx || command -v nginx >/dev/null 2>&1; then
  SERVER="nginx"
elif systemctl is-active --quiet apache2 || systemctl is-active --quiet httpd; then
  SERVER="apache"
elif command -v apache2ctl >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1; then
  SERVER="apache"
fi
if [[ "$SERVER" == "none" ]]; then
  echo "[✗] No Nginx or Apache server was detected."
  exit 1
fi

TMP_DIR="$(mktemp -d -t crs-switch-XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

if [[ "$SERVER" == "nginx" ]]; then
  CRS_PARENT="/etc/nginx/modsec"
  MAIN_CONF="${CRS_PARENT}/main.conf"
  TARGET_DIR="${CRS_PARENT}/coreruleset-${VERSION_NUM}"
  TEST_CMD=(nginx -t)
  RELOAD_CMD=(nginx -s reload)
else
  CRS_PARENT="/etc/modsecurity/crs/versions"
  CRS_CURRENT="/etc/modsecurity/crs/current"
  MAIN_CONF="/etc/modsecurity/modsecurity.conf"
  TARGET_DIR="${CRS_PARENT}/coreruleset-${VERSION_NUM}"
  if command -v apache2ctl >/dev/null 2>&1; then
    TEST_CMD=(apache2ctl configtest)
    RELOAD_CMD=(systemctl reload apache2)
  else
    TEST_CMD=(httpd -t)
    RELOAD_CMD=(systemctl reload httpd)
  fi
fi

active_version() {
  local active=""
  if [[ "$SERVER" == "nginx" && -f "$MAIN_CONF" ]]; then
    active="$(grep -Eo 'coreruleset-[0-9]+\.[0-9]+\.[0-9]+' "$MAIN_CONF" | head -n1 | sed 's/coreruleset-//' || true)"
  elif [[ "$SERVER" == "apache" && -L "$CRS_CURRENT" ]]; then
    active="$(readlink -f "$CRS_CURRENT" | grep -Eo 'coreruleset-[0-9]+\.[0-9]+\.[0-9]+' | head -n1 | sed 's/coreruleset-//' || true)"
  fi
  printf '%s' "$active"
}

ACTIVE_VERSION="$(active_version)"
echo "[+] Server: $SERVER"
echo "[+] Target CRS: $VERSION"
if [[ "$ACTIVE_VERSION" == "$VERSION_NUM" ]]; then
  echo "[=] CRS $VERSION_NUM is already active. No configuration change and no reload required."
  exit 0
fi

mkdir -p "$CRS_PARENT"
if [[ -d "$TARGET_DIR/rules" ]]; then
  echo "[=] CRS $VERSION already downloaded."
elif [[ -e "$TARGET_DIR" ]]; then
  echo "[✗] CRS target exists but is incomplete: $TARGET_DIR"
  exit 1
else
  echo "[+] Downloading $VERSION..."
  wget -q "https://github.com/coreruleset/coreruleset/archive/refs/tags/${VERSION}.tar.gz" -O "$TMP_DIR/crs.tgz"
  tar -xzf "$TMP_DIR/crs.tgz" -C "$TMP_DIR"
  EXTRACTED="$TMP_DIR/coreruleset-${VERSION_NUM}"
  if [[ ! -d "$EXTRACTED/rules" ]]; then
    echo "[✗] Downloaded CRS archive is incomplete."
    exit 1
  fi
  mv "$EXTRACTED" "$TARGET_DIR"
fi

if [[ -f "$TARGET_DIR/crs-setup.conf.example" && ! -f "$TARGET_DIR/crs-setup.conf" ]]; then
  cp "$TARGET_DIR/crs-setup.conf.example" "$TARGET_DIR/crs-setup.conf"
fi
for exclusion in REQUEST-900-EXCLUSION-RULES-BEFORE-CRS RESPONSE-999-EXCLUSION-RULES-AFTER-CRS; do
  if [[ -f "$TARGET_DIR/rules/${exclusion}.conf.example" && ! -f "$TARGET_DIR/rules/${exclusion}.conf" ]]; then
    cp "$TARGET_DIR/rules/${exclusion}.conf.example" "$TARGET_DIR/rules/${exclusion}.conf"
  fi
done

# Preserve the dashboard self-protection exclusions until they are migrated to
# WAFControl-owned exclusion files in milestone 3.
DASHBOARD_EXCLUSIONS="$TARGET_DIR/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"
if [[ -f "$DASHBOARD_EXCLUSIONS" ]] && ! grep -q 'id:1500010' "$DASHBOARD_EXCLUSIONS"; then
  cat >> "$DASHBOARD_EXCLUSIONS" <<'EOR'
# WAF dashboard exclusions
SecRule REQUEST_URI "@beginsWith /crs/rules/save/"         "id:1500010,phase:1,nolog,pass,ctl:ruleEngine=Off"
SecRule REQUEST_URI "@beginsWith /dashboard/crs/settings/" "id:1500011,phase:1,nolog,pass,ctl:ruleEngine=Off"
EOR
fi

CONF_EXISTED=0
if [[ -f "$MAIN_CONF" ]]; then
  cp -a "$MAIN_CONF" "$TMP_DIR/main.conf.previous"
  CONF_EXISTED=1
fi
PREVIOUS_LINK=""
if [[ "$SERVER" == "apache" && -L "$CRS_CURRENT" ]]; then
  PREVIOUS_LINK="$(readlink -f "$CRS_CURRENT")"
fi

rollback() {
  if [[ "$CONF_EXISTED" -eq 1 ]]; then
    cp -a "$TMP_DIR/main.conf.previous" "$MAIN_CONF"
  else
    rm -f "$MAIN_CONF"
  fi
  if [[ "$SERVER" == "apache" ]]; then
    if [[ -n "$PREVIOUS_LINK" ]]; then
      ln -sfn "$PREVIOUS_LINK" "$CRS_CURRENT"
    else
      rm -f "$CRS_CURRENT"
    fi
  fi
}

if [[ "$SERVER" == "nginx" ]]; then
  if [[ -f "$MAIN_CONF" ]]; then
    sed '/Include .*crs-setup\.conf/d; /Include .*rules\/\*\.conf/d' "$MAIN_CONF" > "$TMP_DIR/main.conf.candidate"
  else
    : > "$TMP_DIR/main.conf.candidate"
  fi
  {
    echo "Include $TARGET_DIR/crs-setup.conf"
    echo "Include $TARGET_DIR/rules/*.conf"
  } >> "$TMP_DIR/main.conf.candidate"
  cp "$TMP_DIR/main.conf.candidate" "$MAIN_CONF"
else
  mkdir -p "$(dirname "$CRS_CURRENT")"
  ln -sfn "$TARGET_DIR" "$CRS_CURRENT"
  if [[ -f "$MAIN_CONF" ]]; then
    sed -E \
      -e 's#^[[:space:]]*Include(Optional)?[[:space:]]+.*/crs-setup\.conf#IncludeOptional /etc/modsecurity/crs/current/crs-setup.conf#' \
      -e 's#^[[:space:]]*Include(Optional)?[[:space:]]+.*/rules/\*\.conf#IncludeOptional /etc/modsecurity/crs/current/rules/*.conf#' \
      "$MAIN_CONF" > "$TMP_DIR/main.conf.candidate"
  else
    : > "$TMP_DIR/main.conf.candidate"
  fi
  grep -q 'crs/current/crs-setup.conf' "$TMP_DIR/main.conf.candidate" || echo 'IncludeOptional /etc/modsecurity/crs/current/crs-setup.conf' >> "$TMP_DIR/main.conf.candidate"
  grep -q 'crs/current/rules/\*\.conf' "$TMP_DIR/main.conf.candidate" || echo 'IncludeOptional /etc/modsecurity/crs/current/rules/*.conf' >> "$TMP_DIR/main.conf.candidate"
  cp "$TMP_DIR/main.conf.candidate" "$MAIN_CONF"
fi

if ! "${TEST_CMD[@]}" >/dev/null 2>&1; then
  echo "[✗] Configuration validation failed; restoring the previous version."
  rollback
  "${TEST_CMD[@]}" || true
  exit 1
fi
if ! "${RELOAD_CMD[@]}" >/dev/null 2>&1; then
  echo "[✗] Reload failed; restoring and reloading the previous version."
  rollback
  "${TEST_CMD[@]}" || true
  "${RELOAD_CMD[@]}" >/dev/null 2>&1 || true
  exit 1
fi

echo "[✓] Switched to $VERSION and reloaded $SERVER."
