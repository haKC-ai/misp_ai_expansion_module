#!/usr/bin/env bash
set -euo pipefail

# =========================================
# Config and defaults
# =========================================
LOG_FILE="${LOG_FILE:-$(pwd)/misp_dev_environment.log}"
REPO_URL="${REPO_URL:-https://github.com/MISP/misp-docker}"
TARGET_DIR="${TARGET_DIR:-misp-docker}"
GIT_BRANCH="${GIT_BRANCH:-master}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-300}"
SLEEP_SECS="${SLEEP_SECS:-5}"
COMPOSE_BIN=""
STATE_FILE="${STATE_FILE:-$(pwd)/.misp_dev_state}"

# Hardening knobs
HARDEN_BASELINE="${HARDEN_BASELINE:-true}"
HARDEN_TLS="${HARDEN_TLS:-false}"
PUBLIC_DOMAIN="${PUBLIC_DOMAIN:-}"
ACME_EMAIL="${ACME_EMAIL:-}"
HARDEN_UFW="${HARDEN_UFW:-false}"

# AI module knobs
AI_REPO_URL="${AI_REPO_URL:-https://github.com/haKC-ai/misp_ai_expansion_module}"
AI_WORKDIR="${AI_WORKDIR:-/opt/misp-ai-expansion}"
AI_MODULE_REL="${AI_MODULE_REL:-modules/expansion/ai_event_analysis.py}"
AI_REQS_REL="${AI_REQS_REL:-requirements.txt}"

# Attach behavior
AUTO_CLONE_INSIDE_APP="${AUTO_CLONE_INSIDE_APP:-true}"
AUTO_ATTACH_APP_SHELL="${AUTO_ATTACH_APP_SHELL:-true}"
INSIDE_APP_CLONE_DIR="${INSIDE_APP_CLONE_DIR:-/opt/misp-ai-expansion}"

# Destroy behavior
DOCKER_UNINSTALL="${DOCKER_UNINSTALL:-false}"   # remove Docker only if this script installed it
NONINTERACTIVE="${NONINTERACTIVE:-false}"       # skip confirmations in destroy mode

# Build behavior (default false to avoid local builds)
FORCE_BUILD="${FORCE_BUILD:-false}"

# Runtime bind + URL (auto-detected; can override)
HOST_BIND_ADDR="${HOST_BIND_ADDR:-0.0.0.0}"
HOST_HTTP_PORT="${HOST_HTTP_PORT:-}"            # if empty we will choose 80 or 8081+
MISP_FORCED_BASEURL="${MISP_FORCED_BASEURL:-}"  # if empty we will compute

DEBUG="${DEBUG:-0}"

# =========================================
# Helpers
# =========================================
log() { printf "%s %s\n" "$(date +'%Y-%m-%dT%H:%M:%S%z')" "$*" | tee -a "$LOG_FILE"; }
fail() { log "ERROR: $*"; exit 1; }
debug_on()  { [ "$DEBUG" = "1" ] && set -x || true; }
debug_off() { [ "$DEBUG" = "1" ] && set +x || true; }

record_state() {
  local k="$1" v="$2"
  mkdir -p "$(dirname "$STATE_FILE")"
  : > "${STATE_FILE}.tmp"
  if [ -f "$STATE_FILE" ]; then
    grep -v -E "^${k}=" "$STATE_FILE" >> "${STATE_FILE}.tmp" || true
  fi
  echo "${k}=${v}" >> "${STATE_FILE}.tmp"
  mv "${STATE_FILE}.tmp" "$STATE_FILE"
}

read_state() {
  local k="$1"
  if [ -f "$STATE_FILE" ]; then
    awk -F= -v key="$k" '$1==key{print $2}' "$STATE_FILE" | tail -n1
  fi
}

prompt_yes() {
  local msg="$1"
  if [ "$NONINTERACTIVE" = "true" ]; then
    return 0
  fi
  read -r -p "$msg [y/N]: " ans
  case "$ans" in
    y|Y|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

install_pkg() {
  local pkg="$1"
  log "Installing missing package: $pkg"
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"
}

detect_compose() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    COMPOSE_BIN="docker compose"; return
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_BIN="docker-compose"; return
  fi
  fail "Docker Compose not found"
}

rand_b64() { openssl rand -base64 36 | tr -d '\n' | sed 's/[=\/+]/_/g'; }
rand_hex() { openssl rand -hex 32 | tr -d '\n'; }

safe_kv_set() {
  local file="$1" key="$2" value="$3"
  if grep -qE "^${key}=" "$file"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$file"
  else
    echo "${key}=${value}" >> "$file"
  fi
}

make_helpers_executable() {
  log "Marking helper scripts executable"
  find "$(pwd)" -maxdepth 2 -type f \( -name "*.sh" -o -name "installer.sh" \) -print0 | xargs -0 -I{} bash -c 'chmod +x "{}" || true'
  [ -d "./dev_misp_builder" ] && find ./dev_misp_builder -type f -name "*.sh" -print0 | xargs -0 chmod +x || true
}

check_prereqs() {
  log "Checking prerequisites"
  command -v git >/dev/null 2>&1 || install_pkg git
  command -v curl >/dev/null 2>&1 || install_pkg curl
  command -v gpg  >/dev/null 2>&1 || install_pkg gpg
  command -v lsb_release >/dev/null 2>&1 || install_pkg lsb-release
  if ! command -v docker >/dev/null 2>&1; then
    log "Installing Docker CE"
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl gnupg
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
      | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    sudo usermod -aG docker "$USER" || true
    record_state installed_docker "1"
    log "Docker installed"
  else
    log "Docker already present"
  fi
  detect_compose
  log "Using compose driver: $COMPOSE_BIN"
}

check_github_connectivity() {
  log "Preflight: checking connectivity to github.com"
  if ! getent hosts github.com >/dev/null 2>&1; then
    fail "DNS cannot resolve github.com. Fix DNS or set a proxy."
  fi
  if ! curl -I -sS https://github.com | head -n1 | grep -q "HTTP/"; then
    fail "Cannot reach https://github.com. Check firewall or proxy."
  fi
  log "Connectivity OK"
}

clone_repo() {
  log "Preparing to clone ${REPO_URL} into ${TARGET_DIR} (branch ${GIT_BRANCH})"
  if [ -d "$TARGET_DIR" ] && [ ! -d "$TARGET_DIR/.git" ]; then
    log "Found partial directory ${TARGET_DIR} without .git. Removing it."
    rm -rf "$TARGET_DIR"
  fi

  if [ -d "$TARGET_DIR/.git" ]; then
    log "Repo exists: $TARGET_DIR. Updating branch $GIT_BRANCH"
    debug_on
    git -C "$TARGET_DIR" fetch --all --prune 2>&1 | tee -a "$LOG_FILE" || fail "git fetch failed"
    git -C "$TARGET_DIR" checkout "$GIT_BRANCH" 2>&1 | tee -a "$LOG_FILE" || fail "git checkout failed"
    git -C "$TARGET_DIR" pull --ff-only 2>&1 | tee -a "$LOG_FILE" || fail "git pull failed"
    debug_off
  else
    log "Cloning fresh copy"
    debug_on
    local tries=3 ok=0
    for i in $(seq 1 $tries); do
      log "git clone attempt ${i}/${tries}"
      if git clone --progress --branch "$GIT_BRANCH" --depth 1 "$REPO_URL" "$TARGET_DIR" 2>&1 | tee -a "$LOG_FILE"; then
        ok=1; break
      fi
      sleep 3
    done
    debug_off
    [ "$ok" = "1" ] || { tail -n 80 "$LOG_FILE" >&2; fail "git clone failed after ${tries} attempts"; }
  fi

  [ -f "$TARGET_DIR/template.env" ] || fail "template.env not found after clone. Upstream layout changed or clone incomplete."
  log "Clone OK"
}

# ---------- Port & URL selection ----------
is_port_free() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -E "[:.]${port}\$" -q
  elif command -v lsof >/dev/null 2>&1; then
    ! lsof -iTCP -sTCP:LISTEN -P 2>/dev/null | awk '{print $9}' | grep -E "[:.]${port}\$" -q
  else
    ! (nc -z 127.0.0.1 "$port" 2>/dev/null || nc -z ::1 "$port" 2>/dev/null)
  fi
}

choose_host_port() {
  if [ -n "${HOST_HTTP_PORT:-}" ]; then
    log "HOST_HTTP_PORT pre-set: $HOST_HTTP_PORT"
    return
  fi
  if is_port_free 80; then
    HOST_HTTP_PORT=80
    log "Port 80 is free; will use 80"
  else
    for p in $(seq 8081 8099); do
      if is_port_free "$p"; then HOST_HTTP_PORT="$p"; log "Port 80 busy; selected open port $HOST_HTTP_PORT"; break; fi
    done
    [ -n "${HOST_HTTP_PORT:-}" ] || fail "No open port found in 8081-8099 range"
  fi
}

# Try to determine a public address for this VM (domain wins if provided)
detect_public_addr() {
  if [ -n "${PUBLIC_DOMAIN:-}" ]; then
    echo "$PUBLIC_DOMAIN"
    return 0
  fi

  # 1) metadata/what-is-my-ip services (fast path; ignore failures)
  for svc in \
    "https://api.ipify.org" \
    "https://ifconfig.me/ip" \
    "https://ipv4.icanhazip.com" ; do
    ip="$(curl -4 -fs --max-time 3 "$svc" | tr -d '\r\n ' || true)"
    if printf '%s' "$ip" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
      echo "$ip"; return 0
    fi
  done

  # 2) routing trick (no external call)
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')"
  if printf '%s' "$ip" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "$ip"; return 0
  fi

  # 3) last resort: first non-loopback
  ip="$(hostname -I 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i!="127.0.0.1") {print $i; exit}}')"
  [ -n "$ip" ] && echo "$ip" || echo "127.0.0.1"
}



compute_baseurl() {
  if [ -z "${MISP_FORCED_BASEURL:-}" ]; then
    host="$(detect_public_addr)"
    scheme="http"
    # if you’re enabling the Caddy/TLS proxy, we’ll advertise https
    if [ "${HARDEN_TLS:-false}" = "true" ] && [ -n "${PUBLIC_DOMAIN:-}" ]; then
      scheme="https"
    fi
    if [ "$HOST_HTTP_PORT" = "80" ] || [ "$scheme" = "https" ]; then
      MISP_FORCED_BASEURL="${scheme}://${host}"
    else
      MISP_FORCED_BASEURL="${scheme}://${host}:${HOST_HTTP_PORT}"
    fi
    log "Computed MISP_FORCED_BASEURL: ${MISP_FORCED_BASEURL}"
  else
    log "MISP_FORCED_BASEURL pre-set: ${MISP_FORCED_BASEURL}"
  fi
}


ensure_env_defaults_prebuilt() {
  local envf=".env"
  sed -i '/^CORE_COMMIT=/d' "$envf" || true
  sed -i '/^MODULES_COMMIT=/d' "$envf" || true
  grep -q '^CORE_TAG=' "$envf"     || echo "CORE_TAG=${CORE_TAG:-latest}" >> "$envf"
  grep -q '^MODULES_TAG=' "$envf"  || echo "MODULES_TAG=${MODULES_TAG:-latest}" >> "$envf"

  # kill https redirects in the container images
  grep -q '^DISABLE_SSL_REDIRECT=' "$envf" || echo "DISABLE_SSL_REDIRECT=true" >> "$envf"
  grep -q '^DISABLE_CA_REFRESH='  "$envf"  || echo "DISABLE_CA_REFRESH=true"  >> "$envf"
  grep -q '^HSTS_MAX_AGE='        "$envf"  || echo "HSTS_MAX_AGE=0"           >> "$envf"
  grep -q '^FORCE_HTTPS='         "$envf"  || echo "FORCE_HTTPS=false"        >> "$envf"
  grep -q '^ENABLE_SSL='          "$envf"  || echo "ENABLE_SSL=false"         >> "$envf"

  # prefer your domain when provided (e.g., hakc.ai), else computed public IP
  if [ -n "$PUBLIC_DOMAIN" ]; then
    if [ "${HARDEN_TLS:-false}" = "true" ]; then
      scheme="https"
    else
      scheme="http"
    fi
    url="${scheme}://${PUBLIC_DOMAIN}"
  else
    url="$MISP_FORCED_BASEURL"
  fi


  # set all three envs so init script never falls back to https://localhost
  safe_kv_set "$envf" "MISP_BASEURL" "$url"
  safe_kv_set "$envf" "MISP_EXTERNAL_BASEURL" "$url"
  safe_kv_set "$envf" "SECURITY_REST_CLIENT_BASEURL" "$url"
}


prepare_env() {
  cd "$TARGET_DIR"
  if [ ! -f "template.env" ]; then fail "template.env not found in $(pwd)"; fi
  if [ ! -f ".env" ]; then
    log "Creating .env from template.env"
    cp template.env .env
    record_state created_env "1"
  else
    log ".env already exists. Leaving as is."
  fi
  ensure_env_defaults_prebuilt
}

baseline_hardening_env() {
  [ "$HARDEN_BASELINE" = "true" ] || { log "Baseline hardening disabled"; return; }
  log "Applying baseline hardening to .env"
  local envf=".env"
  local admin_email="admin@$(hostname -f 2>/dev/null || echo localdomain)"
  local admin_pass="$(rand_b64)"
  local mysql_root="$(rand_hex)"
  local mysql_pw="$(rand_hex)"
  local redis_pw="$(rand_hex)"
  local salt="$(rand_hex)"

  safe_kv_set "$envf" "MISP_ADMIN_EMAIL" "$admin_email"
  safe_kv_set "$envf" "MISP_ADMIN_PASSPHRASE" "$admin_pass"
  safe_kv_set "$envf" "MYSQL_ROOT_PASSWORD" "$mysql_root"
  safe_kv_set "$envf" "MYSQL_PASSWORD" "$mysql_pw"
  safe_kv_set "$envf" "REDIS_PASSWORD" "$redis_pw"
  safe_kv_set "$envf" "MISP_SALT" "$salt"

  umask 077
  {
    echo "MISP_ADMIN_EMAIL=$admin_email"
    echo "MISP_ADMIN_PASSPHRASE=$admin_pass"
    echo "MYSQL_ROOT_PASSWORD=$mysql_root"
    echo "MYSQL_PASSWORD=$mysql_pw"
    echo "REDIS_PASSWORD=$redis_pw"
    echo "MISP_SALT=$salt"
    echo "MISP_BASEURL=$(grep '^MISP_BASEURL=' .env | cut -d= -f2-)"
  } > ../misp_secure_credentials.txt
  chmod 600 ../misp_secure_credentials.txt
  record_state wrote_secure_creds "1"
  log "Wrote generated secrets to misp_secure_credentials.txt"
}

write_compose_override() {
  # always overwrite in TARGET_DIR (we're already cd'ed there)
  cat > docker-compose.override.yml <<YAML
services:
  misp-modules:
    ports: []     # keep internal only
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "5"

  misp-core:
    depends_on:
      - misp-modules
    ports:
      - "${HOST_BIND_ADDR}:${HOST_HTTP_PORT}:80"
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "5"
YAML
  record_state wrote_override "1"
  log "Wrote docker-compose.override.yml (host ${HOST_BIND_ADDR}:${HOST_HTTP_PORT} -> container 80)"
  log "Override ports stanza (sanity):"
  awk '/misp-core:/,0' docker-compose.override.yml | sed -n '1,20p' | tee -a "$LOG_FILE"
}

# Inspect rendered compose to see if images are defined
config_has_images() {
  local cfg
  cfg="$($COMPOSE_BIN config 2>/dev/null || true)"
  echo "$cfg" | awk '/services:/,/^$/' | grep -A6 'misp-core:' | grep -q 'image:' && \
  echo "$cfg" | awk '/services:/,/^$/' | grep -A6 'misp-modules:' | grep -q 'image:'
}

# Build locally only if forced (default is to use prebuilt images)
maybe_build_images() {
  if [ "$FORCE_BUILD" = "true" ]; then
    log "FORCE_BUILD=true -> building misp-core and misp-modules locally"
    $COMPOSE_BIN build misp-core misp-modules | tee -a "$LOG_FILE"
    return 0
  fi
  if config_has_images; then
    log "Compose model uses prebuilt images (tags). Skipping local build."
    return 0
  fi
  log "No images found in config and FORCE_BUILD=false. Ensuring tags are set to 'latest' then pulling."
  safe_kv_set ".env" "CORE_TAG" "${CORE_TAG:-latest}"
  safe_kv_set ".env" "MODULES_TAG" "${MODULES_TAG:-latest}"
}

compose_up() {
  log "Pulling images"
  $COMPOSE_BIN pull | tee -a "$LOG_FILE" || true
  maybe_build_images
  log "Starting containers detached"
  $COMPOSE_BIN up -d | tee -a "$LOG_FILE"
}

wait_for_http() {
  local base="${1:-http://127.0.0.1}"
  local url="${base%/}/users/login"
  local deadline=$(( $(date +%s) + WAIT_TIMEOUT ))
  log "Waiting for MISP to respond at $url (timeout ${WAIT_TIMEOUT}s)"
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if curl -L -k -s -o /dev/null -w "%{http_code}" "$url" | grep -qE '^(200|302|401|403)$'; then
      log "MISP endpoint is responding"
      return 0
    fi
    sleep "$SLEEP_SECS"
  done
  fail "Timed out waiting for $url"
}


rendered_services_debug() {
  if [ "$DEBUG" = "1" ]; then
    log "Rendered compose services:"
    $COMPOSE_BIN config --services || true
  fi
}

find_container_by_service() {
  local svc="$1"
  docker ps --filter "label=com.docker.compose.service=${svc}" --format '{{.ID}}' | head -n1
}
find_misp_app_container() {
  local cid; cid="$(find_container_by_service misp-core)"
  if [ -z "$cid" ]; then
    cid="$(docker ps --format '{{.ID}} {{.Names}}' | awk '/misp-core/ {print $1}' | head -n1)"
  fi
  echo "$cid"
}
find_misp_modules_container() {
  local cid; cid="$(find_container_by_service misp-modules)"
  if [ -z "$cid" ]; then
    cid="$(docker ps --format '{{.ID}} {{.Names}}' | awk '/misp-modules/ {print $1}' | head -n1)"
  fi
  echo "$cid"
}

ensure_misp_modules_running() {
  local cid; cid="$(find_misp_modules_container)"
  if [ -z "$cid" ]; then
    log "misp-modules container not found. Starting misp-modules service."
    $COMPOSE_BIN up -d misp-modules | tee -a "$LOG_FILE"
    sleep 3
    cid="$(find_misp_modules_container)"
    [ -n "$cid" ] || fail "Could not start misp-modules container"
  else
    log "misp-modules container running: $cid"
  fi

  docker exec -i "$cid" bash -lc "command -v curl >/dev/null 2>&1 || (apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y curl)" >/dev/null 2>&1 || true
  docker exec -i "$cid" bash -lc "curl -fsS http://127.0.0.1:6666/modules >/dev/null" \
    && log "misp-modules endpoint reachable internally" \
    || log "misp-modules HTTP check not successful yet"

  echo "$cid"
}


install_ai_module_into_misp_modules() {
  local cid="$1"
  log "Installing AI expansion into misp-modules container $cid"
  docker exec -i "$cid" bash -lc "
    set -euo pipefail

    # deps + clone/update
    command -v git >/dev/null 2>&1 || (apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y git ca-certificates)
    mkdir -p '$AI_WORKDIR'
    if [ -d '$AI_WORKDIR/.git' ]; then
      git -C '$AI_WORKDIR' pull --ff-only || true
    else
      git clone --depth 1 '$AI_REPO_URL' '$AI_WORKDIR'
    fi

    # python reqs
    if command -v pip3 >/dev/null 2>&1; then
      pip3 install -r '$AI_WORKDIR/$AI_REQS_REL'
    elif command -v pip >/dev/null 2>&1; then
      pip install -r '$AI_WORKDIR/$AI_REQS_REL'
    else
      apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y python3-pip
      pip3 install -r '$AI_WORKDIR/$AI_REQS_REL'
    fi

    # where misp_modules lives
    py_site=\$(python3 -c 'import site; print([p for p in site.getsitepackages() if \"site-packages\" in p][0])')
    mod_dst=\"\$py_site/misp_modules/modules/expansion\"
    mkdir -p \"\$mod_dst\"

    # copy the module (resolve relative to \$AI_WORKDIR)
    cd '$AI_WORKDIR'
    if [ ! -f '$AI_MODULE_REL' ]; then
      echo \"ERROR: AI module not found at \$PWD/$AI_MODULE_REL\" >&2
      echo \"Available candidates:\" >&2
      (set -x; find . -maxdepth 3 -name 'ai_event_analysis.py' -print || true) >&2
      exit 1
    fi

    install -m 0644 '$AI_MODULE_REL' \"\$mod_dst/\"
    echo \"Installed ai_event_analysis.py to \$mod_dst\"
  " | tee -a "$LOG_FILE"

  # quiet restart so misp-modules picks it up
  docker restart "$cid" >/dev/null 2>&1 || log "Warn: docker restart of misp-modules returned non-zero"
}


enable_modules_in_misp_app() {
  local app_cid="$1"
  log "Enabling modules and forcing base URLs to ${MISP_FORCED_BASEURL}"
  local cake="/var/www/MISP/app/Console/cake"

  docker exec -i "$app_cid" bash -lc "
    set -euo pipefail
    if [ ! -x '$cake' ]; then echo 'Cake not found at $cake' >&2; exit 1; fi

    # helper: set a setting only if it exists for this MISP build
    set_if_exists() {
      local key=\"\$1\" val=\"\$2\"
      if sudo -u www-data $cake Admin getSetting \"\$key\" >/dev/null 2>&1; then
        sudo -u www-data $cake Admin setSetting \"\$key\" \"\$val\"
      else
        echo \"Skipping non-existent setting \$key\" >&2
      fi
    }

    # core URLs
    sudo -u www-data $cake Admin setSetting 'MISP.baseurl' '${MISP_FORCED_BASEURL}'
    sudo -u www-data $cake Admin setSetting 'MISP.external_baseurl' '${MISP_FORCED_BASEURL}'
    sudo -u www-data $cake Admin setSetting 'Security.rest_client_baseurl' '${MISP_FORCED_BASEURL}'

    # do not force HTTPS inside app (TLS handled by Caddy if enabled)
    set_if_exists 'Security.force_https' 0
    # intentionally no 'Security.strict_https' — not present in many builds

    # enable misp-modules + URLs
    sudo -u www-data $cake Admin setSetting 'Plugin.Enrichment_services_enable' true
    sudo -u www-data $cake Admin setSetting 'Plugin.Import_services_enable' true
    sudo -u www-data $cake Admin setSetting 'Plugin.Export_services_enable' true
    sudo -u www-data $cake Admin setSetting 'Plugin.Enrichment_services_url' 'http://misp-modules:6666'
    sudo -u www-data $cake Admin setSetting 'Plugin.Import_services_url' 'http://misp-modules:6666'
    sudo -u www-data $cake Admin setSetting 'Plugin.Export_services_url' 'http://misp-modules:6666'

    # no timeout keys here (they differ across versions)

    sudo -u www-data $cake Admin runUpdates
  " | tee -a "$LOG_FILE"
}



ensure_ufw() {
  if ! command -v ufw >/dev/null 2>&1; then install_pkg ufw; fi
  sudo ufw allow 22/tcp || true
  if [ "${HARDEN_TLS:-false}" = "true" ]; then
    sudo ufw allow 80/tcp || true
    sudo ufw allow 443/tcp || true
  else
    sudo ufw allow ${HOST_HTTP_PORT}/tcp || true
  fi
  echo "y" | sudo ufw enable || true
  sudo ufw status verbose | tee -a "$LOG_FILE"
}


tls_proxy_setup() {
  [ "$HARDEN_TLS" = "true" ] || return 0
  if [ -z "$PUBLIC_DOMAIN" ] || [ -z "$ACME_EMAIL" ]; then
    log "HARDEN_TLS requested but PUBLIC_DOMAIN or ACME_EMAIL missing. Skipping TLS proxy."
    return 0
  fi
  log "Configuring Caddy reverse proxy for ${PUBLIC_DOMAIN} with ACME email ${ACME_EMAIL}"
  mkdir -p caddy
  cat > caddy/Caddyfile <<EOF
{
  email ${ACME_EMAIL}
}
${PUBLIC_DOMAIN} {
  encode zstd gzip
  reverse_proxy misp-core:443 {
    transport http {
      tls_insecure_skip_verify
    }
  }
}
EOF
  cat > caddy/docker-compose.caddy.yml <<'YAML'
services:
  caddy:
    image: caddy:2
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./caddy/Caddyfile:/etc/caddy/Caddyfile:ro
    depends_on:
      - misp-core
    networks:
      - default
YAML
  $COMPOSE_BIN -f docker-compose.yml -f caddy/docker-compose.caddy.yml up -d | tee -a "$LOG_FILE"
  log "Caddy proxy started. Public URL: https://${PUBLIC_DOMAIN}"
}

print_access_info() {
  log "Access"
  if [ "$HARDEN_TLS" = "true" ] && [ -n "$PUBLIC_DOMAIN" ]; then
    log "Public URL: https://${PUBLIC_DOMAIN}"
  else
    log "Local URL: $MISP_FORCED_BASEURL"
  fi
  if [ -f "../misp_secure_credentials.txt" ]; then
    log "Generated credentials saved to misp_secure_credentials.txt. Change them as needed."
  fi
}

drop_into_app_shell() {
  local app_cid="$1"
  log "Dropping into MISP app container shell now"
  echo
  echo "Inside the container you can run, for example:"
  echo "  git clone https://github.com/haKC-ai/misp_ai_expansion_module /opt/misp-ai-expansion"
  echo "  cd /opt/misp-ai-expansion && ./installer.sh --prep"
  echo
  exec docker exec -it "$app_cid" bash
}

maybe_clone_into_app_and_attach() {
  local app_cid="$1"
  if [ "$AUTO_CLONE_INSIDE_APP" = "true" ]; then
    docker exec -i "$app_cid" bash -lc "
      set -euo pipefail
      command -v git >/dev/null 2>&1 || (apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y git ca-certificates)
      mkdir -p '$INSIDE_APP_CLONE_DIR'
      if [ -d '$INSIDE_APP_CLONE_DIR/.git' ]; then
        git -C '$INSIDE_APP_CLONE_DIR' pull --ff-only || true
      else
        git clone --depth 1 '$AI_REPO_URL' '$INSIDE_APP_CLONE_DIR'
      fi
    " | tee -a "$LOG_FILE"
  fi
  if [ "$AUTO_ATTACH_APP_SHELL" = "true" ]; then
    drop_into_app_shell "$app_cid"
  fi
}

# =========================================
# Destroy mode
# =========================================
destroy_all() {
  log "Destroy requested"

  if [ -d "$TARGET_DIR" ]; then
    pushd "$TARGET_DIR" >/dev/null
    if [ -f docker-compose.yml ]; then
      log "Compose down with volumes"
      $COMPOSE_BIN down -v --remove-orphans | tee -a "$LOG_FILE" || true
    fi
    if [ -f caddy/docker-compose.caddy.yml ]; then
      log "Caddy down with volumes"
      $COMPOSE_BIN -f docker-compose.yml -f caddy/docker-compose.caddy.yml down -v --remove-orphans | tee -a "$LOG_FILE" || true
    fi
    popd >/dev/null

    if [ "$(read_state created_env || echo 0)" = "1" ] || [ ! -d "$TARGET_DIR/.git" ]; then
      log "Removing ${TARGET_DIR} directory"
      rm -rf "$TARGET_DIR"
    fi
  fi

  log "Removing generated files"
  rm -f misp_secure_credentials.txt .misp_dev_state "$LOG_FILE" 2>/dev/null || true

  log "Pruning stray containers, networks, and volumes"
  docker container prune -f >/dev/null 2>&1 || true
  docker network prune -f >/dev/null 2>&1 || true
  docker volume prune -f >/dev/null 2>&1 || true

  if [ "$(read_state installed_docker || echo 0)" = "1" ] && [ "$DOCKER_UNINSTALL" = "true" ]; then
    if prompt_yes "Uninstall Docker CE and related packages installed by this script"; then
      log "Uninstalling Docker CE"
      sudo systemctl stop docker || true
      sudo apt-get purge -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin || true
      sudo apt-get autoremove -y || true
      sudo rm -rf /var/lib/docker /var/lib/containerd || true
      sudo rm -f /etc/apt/sources.list.d/docker.list /etc/apt/keyrings/docker.gpg || true
    else
      log "Docker uninstall skipped by user"
    fi
  fi

  log "Destroy complete"
}

# =========================================
# Usage and Main
# =========================================
usage() {
  cat <<USAGE
Usage:
  $0                       Build and configure MISP dev instance, then drop into app shell
  ACTION=destroy $0        Destroy dev instance, remove containers, volumes, generated files

Common run modes:
  1) Default dev (pull prebuilt images)
     ./misp_dev_builder_installer_hardened.sh

  2) With DEBUG trace
     DEBUG=1 ./misp_dev_builder_installer_hardened.sh

  3) With TLS via Caddy
     HARDEN_TLS=true PUBLIC_DOMAIN=misp.example.org ACME_EMAIL=ops@example.org ./misp_dev_builder_installer_hardened.sh

  4) With UFW baseline
     HARDEN_UFW=true ./misp_dev_builder_installer_hardened.sh

  5) Skip auto attach, clone manually later
     AUTO_ATTACH_APP_SHELL=false ./misp_dev_builder_installer_hardened.sh

  6) Auto clone inside app container path
     AUTO_CLONE_INSIDE_APP=true INSIDE_APP_CLONE_DIR=/opt/misp-ai-expansion ./misp_dev_builder_installer_hardened.sh

  7) Custom checkout & longer wait
     TARGET_DIR=/opt/misp-docker WAIT_TIMEOUT=600 ./misp_dev_builder_installer_hardened.sh

  8) Destroy dev instance
     ACTION=destroy ./misp_dev_builder_installer_hardened.sh

  9) Destroy and uninstall Docker that this script installed
     ACTION=destroy DOCKER_UNINSTALL=true ./misp_dev_builder_installer_hardened.sh

Notes:
  - The script auto-selects an HTTP port (80 if free, else 8081-8099), exposes it on misp-core,
    and sets MISP.baseurl to http://127.0.0.1[:port] so redirects won't point to https://localhost.
USAGE
}

main() {
  if [ "${ACTION:-}" = "destroy" ]; then
    detect_compose || true
    destroy_all
    exit 0
  fi

  log "Starting MISP dev environment with hardening"
  log "Log file: $LOG_FILE"

  make_helpers_executable
  check_prereqs
  check_github_connectivity
  clone_repo

  # choose host port & URL before writing env/override
  choose_host_port
  compute_baseurl

  log "Starting prepare_env"
  prepare_env
  log "Applying baseline hardening and writing override"
  if [ "$HARDEN_BASELINE" = "true" ]; then baseline_hardening_env; fi
  write_compose_override

  log "Bringing up docker compose"
  compose_up
  rendered_services_debug

  log "Waiting for HTTP endpoint"
  wait_for_http "$MISP_FORCED_BASEURL"

  if [ "$HARDEN_TLS" = "true" ]; then tls_proxy_setup; fi
  if [ "$HARDEN_UFW" = "true" ]; then ensure_ufw; fi

  log "Ensuring misp-modules running"
  local modules_cid app_cid
  modules_cid="$(find_misp_modules_container)"
  if [ -z "$modules_cid" ]; then
    modules_cid="$(ensure_misp_modules_running)"
  else
    log "misp-modules container running: $modules_cid"
  fi

  app_cid="$(find_misp_app_container)"; [ -n "$app_cid" ] || fail "MISP app container not found"

  log "Installing AI module and enabling plugins"
  install_ai_module_into_misp_modules "$modules_cid"
  enable_modules_in_misp_app "$app_cid"

  print_access_info
  maybe_clone_into_app_and_attach "$app_cid"

  log "Done"
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage; exit 0
fi

main "$@"
