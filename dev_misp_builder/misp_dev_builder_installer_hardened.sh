#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="${LOG_FILE:-$(pwd)/misp_dev_environment.log}"
REPO_URL="${REPO_URL:-https://github.com/MISP/misp-docker}"
TARGET_DIR="${TARGET_DIR:-misp-docker}"
GIT_BRANCH="${GIT_BRANCH:-main}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-300}"
SLEEP_SECS="${SLEEP_SECS:-5}"
COMPOSE_BIN=""

# Hardening knobs
HARDEN_BASELINE="${HARDEN_BASELINE:-true}"
HARDEN_TLS="${HARDEN_TLS:-false}"           # requires PUBLIC_DOMAIN + ACME_EMAIL
PUBLIC_DOMAIN="${PUBLIC_DOMAIN:-}"          # example: misp.example.org
ACME_EMAIL="${ACME_EMAIL:-}"                # example: ops@example.org
HARDEN_UFW="${HARDEN_UFW:-false}"

# AI module knobs
AI_REPO_URL="${AI_REPO_URL:-https://github.com/haKC-ai/misp_ai_expansion_module}"
AI_WORKDIR="${AI_WORKDIR:-/opt/misp-ai-expansion}"
AI_MODULE_REL="${AI_MODULE_REL:-modules/expansion/ai_event_analysis.py}"
AI_REQS_REL="${AI_REQS_REL:-requirements.txt}"

# Optional clone and attach inside MISP app container
AUTO_CLONE_INSIDE_APP="${AUTO_CLONE_INSIDE_APP:-false}"
AUTO_ATTACH_APP_SHELL="${AUTO_ATTACH_APP_SHELL:-false}"
INSIDE_APP_CLONE_DIR="${INSIDE_APP_CLONE_DIR:-/opt/misp-ai-expansion}"

# Utils
log() { printf "%s %s\n" "$(date +'%Y-%m-%dT%H:%M:%S%z')" "$*" | tee -a "$LOG_FILE"; }
fail() { log "ERROR: $*"; exit 1; }
trap 'fail "Unexpected error. See $LOG_FILE for details."' ERR

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
  # Args: file key value
  local file="$1" key="$2" value="$3"
  if grep -qE "^${key}=" "$file"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$file"
  else
    echo "${key}=${value}" >> "$file"
  fi
}

ensure_ufw() {
  if ! command -v ufw >/dev/null 2>&1; then install_pkg ufw; fi
  sudo ufw allow 22/tcp || true
  sudo ufw allow 80/tcp || true
  sudo ufw allow 443/tcp || true
  echo "y" | sudo ufw enable || true
  sudo ufw status verbose | tee -a "$LOG_FILE"
}

check_prereqs() {
  log "Checking prerequisites"
  command -v git >/dev/null 2>&1 || install_pkg git
  command -v curl >/dev/null 2>&1 || install_pkg curl
  command -v gpg >/dev/null 2>&1 || install_pkg gpg
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
    log "Docker installed"
  fi
  detect_compose
  log "Using compose driver: $COMPOSE_BIN"
}

clone_repo() {
  if [ -d "$TARGET_DIR/.git" ]; then
    log "Repo exists: $TARGET_DIR. Updating branch $GIT_BRANCH"
    git -C "$TARGET_DIR" fetch --all --prune >>"$LOG_FILE" 2>&1 || true
    git -C "$TARGET_DIR" checkout "$GIT_BRANCH" >>"$LOG_FILE" 2>&1 || true
    git -C "$TARGET_DIR" pull --ff-only >>"$LOG_FILE" 2>&1 || true
  else
    log "Cloning $REPO_URL into $TARGET_DIR (branch $GIT_BRANCH)"
    git clone --branch "$GIT_BRANCH" --depth 1 "$REPO_URL" "$TARGET_DIR" >>"$LOG_FILE" 2>&1
  fi
}

prepare_env() {
  cd "$TARGET_DIR"
  if [ ! -f "template.env" ]; then fail "template.env not found in $(pwd)"; fi
  if [ ! -f ".env" ]; then
    log "Creating .env from template.env"
    cp template.env .env
  else
    log ".env already exists. Leaving as is."
  fi
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

  if [ -n "$PUBLIC_DOMAIN" ]; then
    safe_kv_set "$envf" "MISP_BASEURL" "https://${PUBLIC_DOMAIN}"
  else
    safe_kv_set "$envf" "MISP_BASEURL" "https://localhost"
  fi

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
  log "Wrote generated secrets to misp_secure_credentials.txt"
}

write_compose_override() {
  # Keep misp-modules internal only and add log rotation
  cat > docker-compose.override.yml <<'YAML'
services:
  misp-modules:
    ports: []     # do not publish 6666 on the host
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "5"
  misp:
    depends_on:
      - misp-modules
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "5"
YAML
  log "Wrote docker-compose.override.yml to keep misp-modules internal and enable log rotation"
}

compose_up() {
  log "Pulling images"
  $COMPOSE_BIN pull | tee -a "$LOG_FILE"
  log "Starting containers detached"
  $COMPOSE_BIN up -d | tee -a "$LOG_FILE"
}

wait_for_http() {
  local url="${1:-https://localhost}"
  local deadline=$(( $(date +%s) + WAIT_TIMEOUT ))
  log "Waiting for MISP to respond at $url (timeout ${WAIT_TIMEOUT}s)"
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if curl -k -s -o /dev/null -w "%{http_code}" "$url" | grep -qE '^(200|302|401|403)$'; then
      log "MISP endpoint is responding"
      return 0
    fi
    sleep "$SLEEP_SECS"
  done
  fail "Timed out waiting for $url"
}

find_container_by_service() {
  local svc="$1"
  docker ps --filter "label=com.docker.compose.service=${svc}" --format '{{.ID}}' | head -n1
}
find_misp_app_container() {
  local cid; cid="$(find_container_by_service misp)"
  if [ -z "$cid" ]; then cid="$(docker ps --format '{{.ID}} {{.Names}}' | awk '/misp/ && !/proxy/ {print $1}' | head -n1)"; fi
  echo "$cid"
}
find_misp_modules_container() {
  local cid; cid="$(find_container_by_service misp-modules)"
  if [ -z "$cid" ]; then cid="$(docker ps --format '{{.ID}} {{.Names}}' | awk '/modules/ && /misp/ {print $1}' | head -n1)"; fi
  echo "$cid"
}

ensure_misp_modules_running() {
  local cid; cid="$(find_misp_modules_container)"
  if [ -z "$cid" ]; then
    log "misp-modules container not found. Starting..."
    $COMPOSE_BIN up -d misp-modules | tee -a "$LOG_FILE"
    sleep 3
    cid="$(find_misp_modules_container)"
    [ -n "$cid" ] || fail "Could not start misp-modules container"
  else
    log "misp-modules container running: $cid"
  fi
  docker exec -i "$cid" bash -lc "curl -sSf http://127.0.0.1:6666/modules | head -c 200 >/dev/null" \
    && log "misp-modules endpoint reachable internally" \
    || log "Note: misp-modules HTTP check did not return successfully yet"
  echo "$cid"
}

install_ai_module_into_misp_modules() {
  local cid="$1"
  log "Installing AI expansion into misp-modules container $cid"
  docker exec -i "$cid" bash -lc "
    set -euo pipefail
    command -v git >/dev/null 2>&1 || (apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y git ca-certificates)
    mkdir -p '$AI_WORKDIR'
    if [ -d '$AI_WORKDIR/.git' ]; then
      git -C '$AI_WORKDIR' pull --ff-only || true
    else
      git clone --depth 1 '$AI_REPO_URL' '$AI_WORKDIR'
    fi
    if command -v pip3 >/dev/null 2>&1; then pip3 install -r '$AI_WORKDIR/$AI_REQS_REL'
    elif command -v pip >/dev/null 2>&1; then pip install -r '$AI_WORKDIR/$AI_REQS_REL'
    else
      apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y python3-pip
      pip3 install -r '$AI_WORKDIR/$AI_REQS_REL'
    fi
    py_site=\$(python3 -c 'import site; print([p for p in site.getsitepackages() if "site-packages" in p][0])')
    mod_dst=\"\$py_site/misp_modules/modules/expansion\"
    mkdir -p \"\$mod_dst\"
    cp '$AI_WORKDIR/$AI_MODULE_REL' \"\$mod_dst/\"
    echo \"Installed ai_event_analysis.py to \$mod_dst\"
  " | tee -a "$LOG_FILE"

  log "Restarting misp-modules to load new module"
  docker restart "$cid" | tee -a "$LOG_FILE"
  docker exec -i "$cid" bash -lc "sleep 2; curl -sSf http://127.0.0.1:6666/modules | head -c 200 >/dev/null" \
    && log "misp-modules OK after restart" \
    || log "Warning: misp-modules still not responding. Inspect logs."
}

enable_modules_in_misp_app() {
  local app_cid="$1"
  log "Enabling Enrichment, Import, Export modules and pointing to misp-modules internal URL"
  local cake="/var/www/MISP/app/Console/cake"
  docker exec -i "$app_cid" bash -lc "
    set -euo pipefail
    if [ ! -x '$cake' ]; then echo 'Cake not found at $cake' >&2; exit 1; fi
    sudo -u www-data $cake Admin setSetting 'Plugin.Enrichment_services_enable' true
    sudo -u www-data $cake Admin setSetting 'Plugin.Import_services_enable' true
    sudo -u www-data $cake Admin setSetting 'Plugin.Export_services_enable' true
    sudo -u www-data $cake Admin setSetting 'Plugin.Enrichment_services_url' 'http://misp-modules:6666'
    sudo -u www-data $cake Admin setSetting 'Plugin.Import_services_url' 'http://misp-modules:6666'
    sudo -u www-data $cake Admin setSetting 'Plugin.Export_services_url' 'http://misp-modules:6666'
    sudo -u www-data $cake Admin setSetting 'Plugin.Enrichment_services_timeout' 120
    sudo -u www-data $cake Admin setSetting 'Plugin.Import_services_timeout' 120
    sudo -u www-data $cake Admin setSetting 'Plugin.Export_services_timeout' 120
    sudo -u www-data $cake Admin runUpdates
  " | tee -a "$LOG_FILE"
}

tls_proxy_setup() {
  [ "$HARDEN_TLS" = "true" ] || return 0
  if [ -z "$PUBLIC_DOMAIN" ] || [ -z "$ACME_EMAIL" ]; then
    log "HARDEN_TLS requested but PUBLIC_DOMAIN or ACME_EMAIL missing. Skipping TLS proxy."
    return 0
  fi
  log "Configuring Caddy reverse proxy for ${PUBLIC_DOMAIN} with ACME email ${ACME_EMAIL}"
  cat > caddy/Caddyfile <<EOF
{
  email ${ACME_EMAIL}
}
${PUBLIC_DOMAIN} {
  encode zstd gzip
  reverse_proxy misp:443 {
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
      - misp
    networks:
      - default
YAML
  mkdir -p caddy
  mv caddy/Caddyfile caddy/Caddyfile 2>/dev/null || true
  log "Starting Caddy reverse proxy"
  $COMPOSE_BIN -f docker-compose.yml -f caddy/docker-compose.caddy.yml up -d | tee -a "$LOG_FILE"
  log "Caddy proxy started. Public URL: https://${PUBLIC_DOMAIN}"
}

maybe_clone_into_app_and_attach() {
  local app_cid="$1"
  if [ "$AUTO_CLONE_INSIDE_APP" = "true" ]; then
    log "Cloning your repo into the app container at $INSIDE_APP_CLONE_DIR"
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
    log "Attaching interactive bash into app container"
    exec docker exec -it "$app_cid" bash
  fi
}

print_access_info() {
  log "Access"
  if [ "$HARDEN_TLS" = "true" ] && [ -n "$PUBLIC_DOMAIN" ]; then
    log "Public URL: https://${PUBLIC_DOMAIN}"
  else
    log "Local URL: https://localhost"
  fi
  log "Generated credentials saved to misp_secure_credentials.txt. Change them as needed."
}

main() {
  log "Starting MISP dev environment with hardening"
  log "Log file: $LOG_FILE"

  check_prereqs
  clone_repo
  prepare_env
  if [ "$HARDEN_BASELINE" = "true" ]; then baseline_hardening_env; write_compose_override; fi
  compose_up
  wait_for_http "https://localhost"
  if [ "$HARDEN_TLS" = "true" ]; then tls_proxy_setup; fi

  [ "$HARDEN_UFW" = "true" ] && ensure_ufw

  local modules_cid app_cid
  modules_cid="$(ensure_misp_modules_running)"
  app_cid="$(find_misp_app_container)"; [ -n "$app_cid" ] || fail "MISP app container not found"

  install_ai_module_into_misp_modules "$modules_cid"
  enable_modules_in_misp_app "$app_cid"
  print_access_info
  maybe_clone_into_app_and_attach "$app_cid"

  log "Done"
}

main "$@"
