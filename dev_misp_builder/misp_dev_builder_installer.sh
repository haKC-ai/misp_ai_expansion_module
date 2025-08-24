#!/usr/bin/env bash
set -euo pipefail

# Logging
LOG_FILE="${LOG_FILE:-$(pwd)/misp_dev_environment.log}"
log() { printf "%s %s\n" "$(date +'%Y-%m-%dT%H:%M:%S%z')" "$*" | tee -a "$LOG_FILE"; }
fail() { log "ERROR: $*"; exit 1; }
trap 'fail "Unexpected error. See $LOG_FILE for details."' ERR

# Inputs and knobs
REPO_URL="${REPO_URL:-https://github.com/MISP/misp-docker}"
TARGET_DIR="${TARGET_DIR:-misp-docker}"
GIT_BRANCH="${GIT_BRANCH:-main}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-240}"
SLEEP_SECS="${SLEEP_SECS:-5}"
COMPOSE_BIN=""

# Your AI module repo and placement inside misp-modules container
AI_REPO_URL="${AI_REPO_URL:-https://github.com/haKC-ai/misp_ai_expansion_module}"
AI_WORKDIR="${AI_WORKDIR:-/opt/misp-ai-expansion}"             # inside containers
AI_MODULE_REL="modules/expansion/ai_event_analysis.py"         # relative in your repo
AI_REQS_REL="requirements.txt"

# Optional attach and clone into MISP app container
AUTO_CLONE_INSIDE_APP="${AUTO_CLONE_INSIDE_APP:-false}"
AUTO_ATTACH_APP_SHELL="${AUTO_ATTACH_APP_SHELL:-false}"
INSIDE_APP_CLONE_DIR="${INSIDE_APP_CLONE_DIR:-/opt/misp-ai-expansion}"

# Utility
install_pkg() {
  local pkg="$1"
  log "Installing missing package: $pkg"
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"
}

detect_compose() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    COMPOSE_BIN="docker compose"
    return
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_BIN="docker-compose"
    return
  fi
  fail "Docker Compose not found"
}

check_prereqs() {
  log "Checking prerequisites"
  if ! command -v git >/dev/null 2>&1; then install_pkg git; fi
  if ! command -v curl >/dev/null 2>&1; then install_pkg curl; fi
  if ! command -v gpg >/dev/null 2>&1;  then install_pkg gpg;  fi
  if ! command -v lsb_release >/dev/null 2>&1; then install_pkg lsb-release; fi

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
  if [ ! -f "template.env" ]; then
    fail "template.env not found in $(pwd)"
  fi
  if [ ! -f ".env" ]; then
    log "Creating .env from template.env"
    cp template.env .env
  else
    log ".env already exists. Leaving as is."
  fi
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
  local service="$1"
  docker ps --filter "label=com.docker.compose.service=${service}" --format '{{.ID}}' | head -n1
}

find_misp_app_container() {
  local cid
  cid="$(find_container_by_service misp)"
  if [ -z "$cid" ]; then
    cid="$(docker ps --format '{{.ID}} {{.Names}}' | awk '/misp/ && !/proxy/ {print $1}' | head -n1)"
  fi
  echo "$cid"
}

find_misp_modules_container() {
  local cid
  cid="$(find_container_by_service misp-modules)"
  if [ -z "$cid" ]; then
    cid="$(docker ps --format '{{.ID}} {{.Names}}' | awk '/modules/ && /misp/ {print $1}' | head -n1)"
  fi
  echo "$cid"
}

ensure_misp_modules_running() {
  local cid
  cid="$(find_misp_modules_container)"
  if [ -z "$cid" ]; then
    log "misp-modules container not found. Attempting to start service"
    $COMPOSE_BIN up -d misp-modules | tee -a "$LOG_FILE"
    sleep 3
    cid="$(find_misp_modules_container)"
    [ -n "$cid" ] || fail "Could not start misp-modules container"
  else
    log "misp-modules container running: $cid"
  fi

  # Try to hit the modules endpoint from the modules container itself
  log "Checking misp-modules HTTP on port 6666"
  docker exec -i "$cid" bash -lc "curl -sSf http://127.0.0.1:6666/modules | head -c 200 >/dev/null" \
    && log "misp-modules responded on 6666" \
    || log "Warning: misp-modules did not respond. Will continue after installing dependencies"
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

    # Install Python deps for the module
    if command -v pip3 >/dev/null 2>&1; then
      pip3 install -r '$AI_WORKDIR/$AI_REQS_REL'
    elif command -v pip >/dev/null 2>&1; then
      pip install -r '$AI_WORKDIR/$AI_REQS_REL'
    else
      apt-get update -qq
      DEBIAN_FRONTEND=noninteractive apt-get install -y python3-pip
      pip3 install -r '$AI_WORKDIR/$AI_REQS_REL'
    fi

    # Locate misp_modules Python package path and copy module file
    py_site=\$(python3 -c 'import site,sys; print([p for p in site.getsitepackages() if "site-packages" in p][0])')
    mod_dst=\"\$py_site/misp_modules/modules/expansion\"
    mkdir -p \"\$mod_dst\"
    cp '$AI_WORKDIR/$AI_MODULE_REL' \"\$mod_dst/\"
    echo \"Installed ai_event_analysis.py to \$mod_dst\"
  " | tee -a "$LOG_FILE"

  log "Restarting misp-modules container to load new module"
  docker restart "$cid" | tee -a "$LOG_FILE"

  log "Verifying misp-modules after restart"
  docker exec -i "$cid" bash -lc "sleep 2; curl -sSf http://127.0.0.1:6666/modules | head -c 200 >/dev/null" \
    && log "misp-modules OK" \
    || log "Warning: misp-modules still not responding. Inspect container logs."
}

enable_modules_in_misp_app() {
  local app_cid="$1"
  log "Enabling Enrichment and Import modules in MISP app container $app_cid"

  # CakePHP CLI path inside app container
  local cake="/var/www/MISP/app/Console/cake"

  docker exec -i "$app_cid" bash -lc "
    set -euo pipefail
    if [ ! -x '$cake' ]; then
      echo 'Cake console not found at $cake' >&2
      exit 1
    fi

    # Enable services and point to misp-modules on port 6666
    sudo -u www-data $cake Admin setSetting \"Plugin.Enrichment_services_enable\" true
    sudo -u www-data $cake Admin setSetting \"Plugin.Import_services_enable\" true
    sudo -u www-data $cake Admin setSetting \"Plugin.Export_services_enable\" true
    sudo -u www-data $cake Admin setSetting \"Plugin.Enrichment_services_url\" \"http://misp-modules:6666\"
    sudo -u www-data $cake Admin setSetting \"Plugin.Import_services_url\" \"http://misp-modules:6666\"
    sudo -u www-data $cake Admin setSetting \"Plugin.Export_services_url\" \"http://misp-modules:6666\"
    sudo -u www-data $cake Admin setSetting \"Plugin.Enrichment_services_timeout\" 120
    sudo -u www-data $cake Admin setSetting \"Plugin.Import_services_timeout\" 120
    sudo -u www-data $cake Admin setSetting \"Plugin.Export_services_timeout\" 120

    # Optional stricter TLS and module flags can be added if needed

    # Restart workers to ensure settings refresh
    if [ -x /usr/local/bin/redis-cli ]; then redis-cli ping >/dev/null 2>&1 || true; fi
    sudo -u www-data $cake Admin runUpdates
  " | tee -a "$LOG_FILE"

  log "MISP module settings applied. You may verify in the UI under Administration -> Server Settings -> Plugin settings."
}

attach_shell() {
  local app_cid="$1"
  log "Attaching interactive bash into app container $app_cid"
  exec docker exec -it "$app_cid" bash
}

print_access_info() {
  local host_hint="https://localhost"
  log "MISP should be reachable at $host_hint or https://<server-ip>"
  log "Default misp-docker creds are documented by the project. Change immediately."
  log "Manual container shell attach examples:"
  log "  docker exec -it \$(docker ps --filter label=com.docker.compose.service=misp --format '{{"'"'{{.ID}}'"'"}}' | head -n1) bash"
  log "  docker exec -it \$(docker ps --filter label=com.docker.compose.service=misp-modules --format '{{"'"'{{.ID}}'"'"}}' | head -n1) bash"
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
    attach_shell "$app_cid"
  fi
}

main() {
  log "Starting MISP dev environment setup"
  log "Log file: $LOG_FILE"

  check_prereqs
  clone_repo
  prepare_env
  compose_up
  wait_for_http "https://localhost"
  print_access_info

  # Containers
  local modules_cid app_cid
  modules_cid="$(ensure_misp_modules_running)"
  app_cid="$(find_misp_app_container)"
  [ -n "$app_cid" ] || fail "Could not locate MISP app container"

  # Install your AI module into misp-modules and enable modules in app
  install_ai_module_into_misp_modules "$modules_cid"
  enable_modules_in_misp_app "$app_cid"

  # Optional: clone your repo into the app container and attach
  maybe_clone_into_app_and_attach "$app_cid"

  log "All done"
}

main "$@"
