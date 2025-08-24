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

# Ensure env defaults required by misp-docker on master branch
ensure_env_defaults_for_master() {
  local envf=".env"
  grep -q '^CORE_COMMIT=' "$envf" || echo "CORE_COMMIT=master" >> "$envf"
  grep -q '^MODULES_COMMIT=' "$envf" || echo "MODULES_COMMIT=master" >> "$envf"
  grep -q '^DISABLE_SSL_REDIRECT=' "$envf" || echo "DISABLE_SSL_REDIRECT=true" >> "$envf"
  grep -q '^DISABLE_CA_REFRESH='  "$envf" || echo "DISABLE_CA_REFRESH=true"  >> "$envf"
  grep -q '^MISP_BASEURL=' "$envf" || echo "MISP_BASEURL=https://0.0.0.0" >> "$envf"
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
  ensure_env_defaults_for_master
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
    safe_kv_set "$envf" "MISP_BASEURL" "https://0.0.0.0"
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
  record_state wrote_secure_creds "1"
  log "Wrote generated secrets to misp_secure_credentials.txt"
}

write_compose_override() {
  cat > docker-compose.override.yml <<'YAML'
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
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "5"
YAML
  record_state wrote_override "1"
  log "Wrote docker-compose.override.yml"
}

# Inspect rendered compose to see if images are defined
config_has_images() {
  local cfg
  cfg="$($COMPOSE_BIN config 2>/dev/null || true)"
  echo "$cfg" | awk '/services:/,/^$/' | grep -A6 'misp-core:' | grep -q 'image:' && \
  echo "$cfg" | awk '/services:/,/^$/' | grep -A6 'misp-modules:' | grep -q 'image:'
}

# Build locally if image entries are not present
maybe_build_images() {
  if config_has_images; then
    log "Compose model contains images for misp-core and misp-modules. No build needed."
    return 0
  fi
  log "Compose model lacks image entries. Performing one-time local build for misp-core and misp-modules."
  $COMPOSE_BIN build misp-core misp-modules | tee -a "$LOG_FILE"
}

compose_up() {
  log "Pulling images"
  $COMPOSE_BIN pull | tee -a "$LOG_FILE" || true
  maybe_build_images
  log "Starting containers detached"
  $COMPOSE_BIN up -d | tee -a "$LOG_FILE"
}

wait_for_http() {
  local url="${1:-https://0.0.0.0}"
  local deadline=$(( $(date +%s) + WAIT_TIMEOUT ))
  log "Waiting for MISP to respond at $url with timeout ${WAIT_TIMEOUT}s"
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if curl -k -s -o /dev/null -w "%{http_code}" "$url" | grep -qE '^(200|302|401|403)$'; then
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
  docker exec -i "$cid" bash -lc "curl -sSf http://127.0.0.1:6666/modules | head -c 200 >/dev/null" \
    && log "misp-modules endpoint reachable internally" \
    || log "misp-modules HTTP check not successful yet"
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
    if command -v pip3 >/dev/null 2>&1; then
      pip3 install -r '$AI_WORKDIR/$AI_REQS_REL'
    elif command -v pip >/dev/null 2>&1; then
      pip install -r '$AI_WORKDIR/$AI_REQS_REL'
    else
      apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y python3-pip
      pip3 install -r '$AI_WORKDIR/$AI_REQS_REL'
    fi
    py_site=\$(python3 -c 'import site; print([p for p in site.getsitepackages() if "site-packages" in p][0])')
    mod_dst=\"\$py_site/misp_modules/modules/expansion\"
    mkdir -p \"\$mod_dst\"
    cp '$AI_MODULE_REL' \"\$mod_dst/\"
    echo \"Installed ai_event_analysis.py to \$mod_dst\"
  " | tee -a "$LOG_FILE"

  log "Restarting misp-modules to load the new module"
  docker restart "$cid" | tee -a "$LOG_FILE"
}

enable_modules_in_misp_app() {
  local app_cid="$1"
  log "Enabling Enrichment, Import, Export modules in MISP app"
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

ensure_ufw() {
  if ! command -v ufw >/dev/null 2>&1; then install_pkg ufw; fi
  sudo ufw allow 22/tcp || true
  sudo ufw allow 80/tcp || true
  sudo ufw allow 443/tcp || true
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
    log "Local URL: https://0.0.0.0"
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
  1) Default dev
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

  7) Custom repo checkout location and longer wait
     TARGET_DIR=/opt/misp-docker WAIT_TIMEOUT=600 ./misp_dev_builder_installer_hardened.sh

  8) Destroy dev instance
     ACTION=destroy ./misp_dev_builder_installer_hardened.sh

  9) Destroy and uninstall Docker that this script installed
     ACTION=destroy DOCKER_UNINSTALL=true ./misp_dev_builder_installer_hardened.sh

Notes:
  The script sets CORE_COMMIT and MODULES_COMMIT to master by default to satisfy misp-docker build logic.
  If the compose model lacks images, it will run a one time local build for misp-core and misp-modules.
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
  log "Starting prepare_env"
  prepare_env
  log "Applying baseline hardening and override"
  if [ "$HARDEN_BASELINE" = "true" ]; then baseline_hardening_env; write_compose_override; fi
  log "Bringing up docker compose"
  compose_up
  rendered_services_debug
  log "Waiting for HTTPS endpoint"
  wait_for_http "https://0.0.0.0"

  if [ "$HARDEN_TLS" = "true" ]; then tls_proxy_setup; fi
  if [ "$HARDEN_UFW" = "true" ]; then ensure_ufw; fi

  log "Ensuring misp-modules running"
  local modules_cid app_cid
  modules_cid="$(ensure_misp_modules_running)"
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
