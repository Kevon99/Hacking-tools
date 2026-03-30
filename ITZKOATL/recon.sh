#!/usr/bin/env bash
# =============================================================================
#  recon.sh — Bug Bounty Recon Tool v3.0
#
#  Flujo:
#    [M1] Subdomain enum (paralelo)  → subfinder + assetfinder + amass
#    [M2] DNSX                       → validar resolución DNS
#    [M3] WAF Detection              → wafw00f → pregunta si forzar stealth
#    [M4] HTTPX                      → hosts activos + JSON detallado
#    [M5] URLs históricas (paralelo) → gau + waybackurls por dominio raíz
#    [M6] Katana                     → crawl priorizado y limitado
#    [M7] Attack Surface Scoring     → high/medium/low/idor/api/js
#    [M8] Secret Discovery           → SecretFinder + TruffleHog (filtrado)
#    [M9] Content Discovery          → ffuf/feroxbuster solo sobre high-priority
#    [M10] Filtro out_scope          → aplica a todos los outputs
#    [M11] Nuclei                    → sobre high_priority.txt (dedup)
#    [M12] Reporte JSON              → estadísticas + muestras + rutas
#
#  Uso:
#    bash recon.sh <proyecto> [targets.txt] [out_scope.txt] [--normal|--stealth|--aggressive]
# =============================================================================

set -euo pipefail

# ──────────────────────────────────────────────
# COLORES
# ──────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
RESET='\033[0m'

# ──────────────────────────────────────────────
# BANNER
# ──────────────────────────────────────────────
banner() {
  echo -e "${CYAN}${BOLD}"
  echo "  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗"
  echo "  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║"
  echo "  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║"
  echo "  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║"
  echo "  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║"
  echo "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝"
  echo -e "${RESET}${YELLOW}  Bug Bounty Recon Tool v3.0 — Full Optimized Pipeline${RESET}"
  echo -e "${CYAN}  Attack Surface Scoring · Parallel Execution · Smart Prioritization${RESET}"
  echo -e "${CYAN}  ─────────────────────────────────────────────────────────────────${RESET}"
  echo ""
}

# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────
log_info()    { echo -e "${CYAN}[*]${RESET} $1"; }
log_ok()      { echo -e "${GREEN}[✔]${RESET} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
log_skip()    { echo -e "${MAGENTA}[~]${RESET} $1 (no encontrado, saltando)"; }
log_error()   { echo -e "${RED}[✘]${RESET} $1"; exit 1; }
log_section() {
  echo -e "\n${BOLD}${YELLOW}══════════════════════════════════════════════${RESET}"
  echo -e "${BOLD}${YELLOW}  $1${RESET}"
  echo -e "${BOLD}${YELLOW}══════════════════════════════════════════════${RESET}"
}

# Filtrar un archivo contra out_scope
filter_file() {
  local target_file="$1" outscope_file="$2" backup_file="$3"
  [[ ! -s "$target_file" ]] && return
  [[ ! -f "$outscope_file" ]] && return
  local before after removed tmp
  before=$(wc -l < "$target_file")
  tmp=$(mktemp)
  cp "$target_file" "$tmp"
  while IFS= read -r oos; do
    [[ -z "$oos" ]] && continue
    local escaped
    escaped=$(printf '%s' "$oos" | sed 's/[.[\*^${}()+?|]/\\&/g')
    grep -viE "$escaped" "$tmp" > "${tmp}.new" 2>/dev/null || true
    mv "${tmp}.new" "$tmp"
  done < "$outscope_file"
  cp "$target_file" "$backup_file"
  cp "$tmp" "$target_file"
  rm -f "$tmp"
  after=$(wc -l < "$target_file")
  removed=$(( before - after ))
  log_ok "$(basename "$target_file"): -${removed} OOS → ${after} restantes"
}

# Array JSON muestreado (máx N líneas)
to_json_array() {
  local file="$1" limit="${2:-50}"
  [[ -f "$file" ]] && head -"$limit" "$file" | awk '{printf "\"%s\",", $0}' | sed 's/,$//' || echo ""
}

# Extraer dominio raíz de una URL o subdominio
extract_root_domain() {
  # example: sub.example.com → example.com, https://api.example.com/path → example.com
  echo "$1" | sed 's|https\?://||' | awk -F'/' '{print $1}' | \
    awk -F'.' '{
      n=NF
      if (n>=3 && length($(n-1))<=3) print $(n-2)"."$(n-1)"."$n
      else if (n>=2) print $(n-1)"."$n
      else print $0
    }'
}

# ──────────────────────────────────────────────
# CONFIGURACIÓN GLOBAL DE RATE/THREADS POR MODO
# ──────────────────────────────────────────────
set_mode_config() {
  case "${RECON_MODE}" in
    stealth)
      THREADS=5
      RATE=10
      KATANA_DEPTH=2
      KATANA_MAX_URLS=50
      NUCLEI_THREADS=5
      NUCLEI_RATE=10
      FFUF_THREADS=5
      FFUF_RATE=10
      DELAY=3
      RANDOM_DELAY=5
      PARALLEL_JOBS=2
      ;;
    aggressive)
      THREADS=80
      RATE=300
      KATANA_DEPTH=4
      KATANA_MAX_URLS=500
      NUCLEI_THREADS=50
      NUCLEI_RATE=500
      FFUF_THREADS=80
      FFUF_RATE=300
      DELAY=0
      RANDOM_DELAY=0
      PARALLEL_JOBS=10
      ;;
    *) # normal (default)
      THREADS=30
      RATE=50
      KATANA_DEPTH=3
      KATANA_MAX_URLS=200
      NUCLEI_THREADS=25
      NUCLEI_RATE=150
      FFUF_THREADS=40
      FFUF_RATE=100
      DELAY=0
      RANDOM_DELAY=0
      PARALLEL_JOBS=5
      ;;
  esac
  log_info "Modo: ${RECON_MODE} | threads=${THREADS} rate=${RATE} depth=${KATANA_DEPTH} parallel=${PARALLEL_JOBS}"
}

# ──────────────────────────────────────────────
# VERIFICAR DEPENDENCIAS
# ──────────────────────────────────────────────
check_deps() {
  log_section "Verificando dependencias"
  local critical=("subfinder" "dnsx" "httpx" "katana" "nuclei" "jq")
  local optional=("assetfinder" "amass" "wafw00f" "waybackurls" "gau"
                  "SecretFinder" "trufflehog" "ffuf" "feroxbuster" "parallel")
  local missing_critical=()

  echo -e "${BOLD}  Críticas:${RESET}"
  for dep in "${critical[@]}"; do
    if command -v "$dep" &>/dev/null; then
      log_ok "  $dep"
    else
      log_warn "  $dep — NO encontrado (crítico)"
      missing_critical+=("$dep")
    fi
  done

  echo -e "\n${BOLD}  Opcionales:${RESET}"
  for dep in "${optional[@]}"; do
    if command -v "$dep" &>/dev/null; then
      log_ok "  $dep"
    else
      log_warn "  $dep — NO encontrado (ese módulo se saltará)"
    fi
  done

  if [[ ${#missing_critical[@]} -gt 0 ]]; then
    echo ""
    log_warn "Críticas faltantes: ${missing_critical[*]}"
    cat <<'EOF'
  Instalar:
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    go install -v github.com/tomnomnom/assetfinder@latest
    go install -v github.com/tomnomnom/waybackurls@latest
    go install -v github.com/lc/gau/v2/cmd/gau@latest
    go install -v github.com/ffuf/ffuf/v2@latest
    go install -v github.com/trufflesecurity/trufflehog/v3@latest
    sudo apt install amass wafw00f seclists jq parallel
EOF
    echo ""
    read -rp "¿Continuar de todas formas? [s/N]: " confirm
    [[ "$confirm" =~ ^[sS]$ ]] || exit 0
  fi
}

# ──────────────────────────────────────────────
# USAGE
# ──────────────────────────────────────────────
usage() {
  echo -e "Uso: ${BOLD}bash recon.sh <proyecto> [targets.txt] [out_scope.txt] [--normal|--stealth|--aggressive] [--skip-fuzz]${RESET}"
  echo ""
  echo "  proyecto        Nombre del programa (ej: acme)"
  echo "  targets.txt     Un dominio raíz por línea. Si no se pasa, se pide interactivo"
  echo "  out_scope.txt   Dominios/URLs fuera de scope"
  echo "  --normal        Modo estándar (default)"
  echo "  --stealth       Delays, rate bajo, UA real, limita URLs a crawlear"
  echo "  --aggressive    Sin límites, máxima velocidad (solo sin WAF)"
  echo "  --skip-fuzz     Salta ffuf/feroxbuster"
  exit 1
}

# ──────────────────────────────────────────────
# ESTRUCTURA DE CARPETAS
# ──────────────────────────────────────────────
create_structure() {
  log_section "Creando estructura de carpetas"

  PROJECT_DIR="${PROJECT_NAME}"
  CONTENT_DIR="${PROJECT_DIR}/content"
  MAP_DIR="${CONTENT_DIR}/map"
  SUBFINDER_DIR="${MAP_DIR}/subfinder"
  DNSX_DIR="${MAP_DIR}/dnsx"
  WAFW00F_DIR="${MAP_DIR}/wafw00f"
  HTTPX_DIR="${MAP_DIR}/httpx"
  WAYBACK_DIR="${MAP_DIR}/wayback"
  KATANA_DIR="${MAP_DIR}/katana"
  SCORING_DIR="${MAP_DIR}/scoring"
  SECRETS_DIR="${MAP_DIR}/secrets"
  FUZZING_DIR="${MAP_DIR}/fuzzing"
  NUCLEI_DIR="${MAP_DIR}/nuclei"

  mkdir -p \
    "${PROJECT_DIR}/nmap" \
    "${PROJECT_DIR}/scripts" \
    "${SUBFINDER_DIR}" \
    "${DNSX_DIR}" \
    "${WAFW00F_DIR}" \
    "${HTTPX_DIR}" \
    "${WAYBACK_DIR}" \
    "${KATANA_DIR}" \
    "${SCORING_DIR}" \
    "${SECRETS_DIR}" \
    "${FUZZING_DIR}" \
    "${NUCLEI_DIR}"

  log_ok "Carpetas creadas en ./${PROJECT_NAME}/"
}

# ──────────────────────────────────────────────
# TARGETS
# ──────────────────────────────────────────────
collect_targets() {
  TARGETS_FILE="${CONTENT_DIR}/targets.txt"
  log_section "Configurando targets"

  if [[ -n "${INPUT_TARGETS_FILE:-}" ]]; then
    [[ ! -f "$INPUT_TARGETS_FILE" ]] && log_error "Archivo no encontrado: $INPUT_TARGETS_FILE"
    cp "$INPUT_TARGETS_FILE" "$TARGETS_FILE"
    log_ok "Targets cargados desde: $INPUT_TARGETS_FILE"
  else
    echo -e "${YELLOW}Ingresa dominios objetivo (uno por línea). ENTER vacío para terminar:${RESET}"
    echo ""
    > "$TARGETS_FILE"
    while IFS= read -rp "  dominio: " line; do
      [[ -z "$line" ]] && break
      echo "$line" >> "$TARGETS_FILE"
    done
  fi

  sed -i '/^[[:space:]]*$/d' "$TARGETS_FILE"
  local count
  count=$(wc -l < "$TARGETS_FILE")
  log_ok "$count dominio(s) → ${TARGETS_FILE}"
  while IFS= read -r d; do echo "    • $d"; done < "$TARGETS_FILE"
}

# ──────────────────────────────────────────────
# M1 — ENUMERACIÓN DE SUBDOMINIOS (PARALELO)
# Cada dominio se procesa con subfinder+assetfinder+amass en background
# Se controla el número de procesos simultáneos con PARALLEL_JOBS
# ──────────────────────────────────────────────
run_subdomain_enum() {
  log_section "M1 — Enumeración de subdominios (paralelo, jobs=${PARALLEL_JOBS})"
  local output="${SUBFINDER_DIR}/subfinder_output.txt"
  local tmp_dir
  tmp_dir=$(mktemp -d)
  local pids=()

  _enum_domain() {
    local domain="$1"
    local out="${tmp_dir}/${domain//\//_}.txt"
    > "$out"
    # subfinder (crítico)
    subfinder -d "$domain" -silent 2>/dev/null >> "$out" || true
    # assetfinder (opcional)
    if command -v assetfinder &>/dev/null; then
      assetfinder --subs-only "$domain" 2>/dev/null >> "$out" || true
    fi
    # amass (opcional)
    if command -v amass &>/dev/null; then
      amass enum -passive -d "$domain" -silent 2>/dev/null >> "$out" || true
    fi
  }
  export -f _enum_domain

  # Lanzar con GNU parallel si está disponible, sino con & y wait manual
  if command -v parallel &>/dev/null; then
    log_info "Usando GNU parallel (${PARALLEL_JOBS} jobs)"
    parallel -j "${PARALLEL_JOBS}" _enum_domain ::: $(cat "$TARGETS_FILE") 2>/dev/null || true
  else
    log_info "Usando jobs en background (sin GNU parallel)"
    while IFS= read -r domain; do
      [[ -z "$domain" ]] && continue
      log_info "  → $domain"
      _enum_domain "$domain" &
      pids+=($!)
      # Limitar procesos simultáneos
      if [[ ${#pids[@]} -ge $PARALLEL_JOBS ]]; then
        wait "${pids[0]}"
        pids=("${pids[@]:1}")
      fi
    done < "$TARGETS_FILE"
    wait
  fi

  # Merge + dedup de todos los archivos temporales
  cat "${tmp_dir}"/*.txt 2>/dev/null | sort -u > "$output" || true
  rm -rf "$tmp_dir"

  log_ok "Subdominios únicos: $(wc -l < "$output" 2>/dev/null || echo 0) → ${output}"
}

# ──────────────────────────────────────────────
# M2 — DNSX: validar resolución DNS
# ──────────────────────────────────────────────
run_dnsx() {
  log_section "M2 — DNSX (validación DNS)"
  local input="${SUBFINDER_DIR}/subfinder_output.txt"
  local output="${DNSX_DIR}/dnsx_resolved.txt"
  local output_full="${DNSX_DIR}/dnsx_full.txt"

  if [[ ! -s "$input" ]]; then
    log_warn "Sin subdominios. Copiando input vacío."
    touch "$output"; return
  fi

  log_info "Resolviendo $(wc -l < "$input") subdominios..."
  dnsx -l "$input" -resp -a -cname -silent -o "$output_full" 2>/dev/null || true
  dnsx -l "$input" -silent -o "$output" 2>/dev/null || true

  local before after
  before=$(wc -l < "$input")
  after=$(wc -l < "$output" 2>/dev/null || echo 0)
  log_ok "Resueltos: ${after}/${before} — eliminados $(( before - after )) sin DNS"

  # Actualizar subfinder_output con los validados
  cp "$output" "${SUBFINDER_DIR}/subfinder_output.txt"
}

# ──────────────────────────────────────────────
# M3 — WAFW00F: detectar WAF → preguntar si forzar stealth
# ──────────────────────────────────────────────
run_wafw00f() {
  log_section "M3 — WAF Detection (wafw00f)"

  if ! command -v wafw00f &>/dev/null; then
    log_skip "wafw00f"
    WAF_DETECTED="unknown"
    return
  fi

  local input="${SUBFINDER_DIR}/subfinder_output.txt"
  local output="${WAFW00F_DIR}/wafw00f_output.txt"
  local waf_list="${WAFW00F_DIR}/waf_detected.txt"

  [[ ! -s "$input" ]] && { WAF_DETECTED="unknown"; return; }

  log_info "Detectando WAF en $(wc -l < "$input") hosts..."
  wafw00f -i "$input" -o "$output" 2>/dev/null || true
  grep -v "No WAF detected\|Generic\|not detected" "$output" \
    > "$waf_list" 2>/dev/null || true

  local waf_count
  waf_count=$(wc -l < "$waf_list" 2>/dev/null || echo 0)

  if [[ $waf_count -gt 0 ]]; then
    WAF_DETECTED="yes"
    log_warn "WAF detectado en ${waf_count} hosts:"
    head -5 "$waf_list" | while IFS= read -r l; do log_warn "    $l"; done

    if [[ "${RECON_MODE}" != "stealth" ]]; then
      echo ""
      log_warn "Modo actual: ${RECON_MODE}. El WAF puede bloquearte."
      read -rp "  ¿Cambiar a modo STEALTH? [s/N]: " switch
      if [[ "$switch" =~ ^[sS]$ ]]; then
        RECON_MODE="stealth"
        set_mode_config
        log_ok "Modo cambiado a STEALTH"
      else
        log_warn "Continuando en modo ${RECON_MODE}. Riesgo de bloqueo."
      fi
    fi
  else
    WAF_DETECTED="no"
    log_ok "Sin WAF detectado"
  fi
}

# ──────────────────────────────────────────────
# M4 — HTTPX: probe de hosts activos + JSON detallado
# ──────────────────────────────────────────────
run_httpx() {
  log_section "M4 — HTTPX"
  local input="${SUBFINDER_DIR}/subfinder_output.txt"
  local output="${HTTPX_DIR}/httpx_output.txt"
  local output_json="${HTTPX_DIR}/httpx_output.json"

  [[ ! -s "$input" ]] && { log_warn "Sin subdominios. Saltando."; return; }

  log_info "Probando $(wc -l < "$input") hosts (threads=${THREADS})..."

  httpx \
    -l "$input" \
    -status-code -tech-detect -title -content-length -content-type \
    -follow-redirects -fc 404 \
    -timeout 10 -threads "$THREADS" \
    -silent -o "$output" \
    2>/dev/null || true

  httpx \
    -l "$input" \
    -status-code -tech-detect -title -content-length -content-type \
    -follow-redirects -fc 404 \
    -timeout 10 -threads "$THREADS" \
    -silent -json -o "$output_json" \
    2>/dev/null || true

  log_ok "Hosts activos (sin 404): $(wc -l < "$output" 2>/dev/null || echo 0)"

  # Extraer subconjuntos de interés del JSON de httpx
  _classify_httpx_hosts
}

_classify_httpx_hosts() {
  local json="${HTTPX_DIR}/httpx_output.json"
  local interesting_tech="${HTTPX_DIR}/httpx_interesting_tech.txt"
  local login_panels="${HTTPX_DIR}/httpx_login_panels.txt"
  local api_hosts="${HTTPX_DIR}/httpx_api_hosts.txt"
  local error_hosts="${HTTPX_DIR}/httpx_errors.txt"

  [[ ! -s "$json" ]] && return

  # Hosts con tecnología interesante (WordPress, .NET, PHP, etc.)
  jq -r 'select(.technologies != null) |
    select(.technologies[] | test("WordPress|Drupal|Joomla|\\.NET|ASP\\.NET|PHP|Spring|Laravel|Django|Rails|Express|Next\\.js|Strapi|Grafana|Jenkins|Jira|Confluence"; "i")) |
    .url' "$json" 2>/dev/null | sort -u > "$interesting_tech" || true

  # Paneles de login/admin
  jq -r 'select(.title != null) |
    select(.title | test("login|sign.?in|admin|dashboard|portal|authentication|panel|console"; "i")) |
    .url' "$json" 2>/dev/null | sort -u > "$login_panels" || true

  # APIs (por título, path, o tecnología)
  jq -r 'select(.url | test("/api|/v[0-9]|/graphql|swagger|openapi"; "i")) |
    .url' "$json" 2>/dev/null | sort -u > "$api_hosts" || true

  # Hosts con errores (500, 403) — más interesantes para explotar
  jq -r 'select(.status_code == 500 or .status_code == 403) | .url' \
    "$json" 2>/dev/null | sort -u > "$error_hosts" || true

  log_info "  Tech interesante: $(wc -l < "$interesting_tech" 2>/dev/null || echo 0)"
  log_info "  Login/admin panels: $(wc -l < "$login_panels" 2>/dev/null || echo 0)"
  log_info "  API hosts: $(wc -l < "$api_hosts" 2>/dev/null || echo 0)"
  log_info "  500/403 hosts: $(wc -l < "$error_hosts" 2>/dev/null || echo 0)"
}

# ──────────────────────────────────────────────
# M5 — GAU + WAYBACKURLS (por DOMINIO RAÍZ, paralelo)
# Se deduplica antes de pasar a katana
# ──────────────────────────────────────────────
run_wayback() {
  log_section "M5 — URLs Históricas (gau + waybackurls, por dominio raíz)"
  local httpx_file="${HTTPX_DIR}/httpx_output.txt"
  local output="${WAYBACK_DIR}/wayback_output.txt"
  local output_interesting="${WAYBACK_DIR}/wayback_interesting.txt"

  [[ ! -s "$httpx_file" ]] && { log_warn "httpx vacío. Saltando."; touch "$output"; return; }

  # Extraer SOLO dominios raíz únicos (evitar 50 subdominos del mismo dominio)
  local root_domains
  root_domains=$(grep -oP 'https?://[^\s\[\]]+' "$httpx_file" 2>/dev/null | \
    sed 's|https\?://||' | awk -F'/' '{print $1}' | \
    awk -F'.' '{n=NF; if(n>=3 && length($(n-1))<=3) print $(n-2)"."$(n-1)"."$n; else if(n>=2) print $(n-1)"."$n; else print $0}' | \
    sort -u)

  local root_count
  root_count=$(echo "$root_domains" | grep -c . || echo 0)
  log_info "Dominios raíz únicos: ${root_count} (de $(wc -l < "$httpx_file") hosts activos)"

  local tmp_dir
  tmp_dir=$(mktemp -d)

  _fetch_wayback() {
    local domain="$1"
    local out="${tmp_dir}/${domain//\//_}.txt"
    > "$out"
    if command -v gau &>/dev/null; then
      echo "$domain" | gau \
        --blacklist png,jpg,gif,svg,woff,ttf,eot,ico,css,mp4,mp3,zip,pdf \
        2>/dev/null >> "$out" || true
    fi
    if command -v waybackurls &>/dev/null; then
      echo "$domain" | waybackurls 2>/dev/null >> "$out" || true
    fi
  }
  export -f _fetch_wayback

  if command -v parallel &>/dev/null; then
    echo "$root_domains" | parallel -j "${PARALLEL_JOBS}" _fetch_wayback 2>/dev/null || true
  else
    local pids=()
    while IFS= read -r domain; do
      [[ -z "$domain" ]] && continue
      log_info "  → $domain"
      _fetch_wayback "$domain" &
      pids+=($!)
      if [[ ${#pids[@]} -ge $PARALLEL_JOBS ]]; then
        wait "${pids[0]}"; pids=("${pids[@]:1}")
      fi
    done <<< "$root_domains"
    wait
  fi

  # Merge + dedup global
  cat "${tmp_dir}"/*.txt 2>/dev/null | sort -u > "$output" || true
  rm -rf "$tmp_dir"

  # Filtrar extensiones sin valor antes de guardar
  local cleaned
  cleaned=$(grep -viE "\.(png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|ico|css|mp4|mp3|zip|pdf|tar|gz)(\?|$)" \
    "$output" 2>/dev/null | sort -u || true)
  echo "$cleaned" > "$output"

  # URLs interesantes
  grep -iE "\.(php|asp|aspx|jsp|json|xml|env|config|bak|sql|log|git|yaml|yml|toml)\b|\?(.*=)" \
    "$output" | sort -u > "$output_interesting" 2>/dev/null || true

  log_ok "URLs históricas (dedup, sin estáticos): $(wc -l < "$output")"
  log_ok "URLs interesantes: $(wc -l < "$output_interesting")"
}

# ──────────────────────────────────────────────
# M6 — KATANA: crawl priorizado y limitado
# Input: solo httpx_output (hosts activos) + dominios raíz de wayback
# Limita URLs en stealth, excluye estáticos
# ──────────────────────────────────────────────
run_katana() {
  log_section "M6 — Katana (modo=${RECON_MODE}, depth=${KATANA_DEPTH}, max=${KATANA_MAX_URLS})"
  local httpx_file="${HTTPX_DIR}/httpx_output.txt"
  local wayback_file="${WAYBACK_DIR}/wayback_output.txt"
  local input_file="${KATANA_DIR}/katana_input.txt"
  local output="${KATANA_DIR}/katana_output.txt"
  local output_interesting="${KATANA_DIR}/katana_interesting.txt"

  > "$input_file"

  # Priorizar: solo hosts activos de httpx
  if [[ -s "$httpx_file" ]]; then
    grep -oP 'https?://[^\s\[\]]+' "$httpx_file" 2>/dev/null >> "$input_file" || \
      awk '{print $1}' "$httpx_file" >> "$input_file"
  fi

  # Añadir dominios raíz de wayback (no todas las URLs)
  if [[ -s "$wayback_file" ]]; then
    grep -oP 'https?://[^\s/]+' "$wayback_file" 2>/dev/null | sort -u >> "$input_file" || true
  fi

  sort -u "$input_file" -o "$input_file"
  sed -i '/^[[:space:]]*$/d' "$input_file"

  # En modo stealth, limitar número de URLs de entrada
  if [[ "${RECON_MODE}" == "stealth" ]]; then
    local total
    total=$(wc -l < "$input_file")
    if [[ $total -gt $KATANA_MAX_URLS ]]; then
      log_info "Stealth: limitando input de ${total} a ${KATANA_MAX_URLS} URLs"
      head -"$KATANA_MAX_URLS" "$input_file" > "${input_file}.tmp"
      mv "${input_file}.tmp" "$input_file"
    fi
  fi

  local total_input
  total_input=$(wc -l < "$input_file")
  [[ $total_input -eq 0 ]] && { log_warn "Sin input para katana."; return; }
  log_info "URLs de entrada: ${total_input}"

  # Flags por modo
  local katana_flags=()
  if [[ "${RECON_MODE}" == "stealth" ]]; then
    katana_flags=(
      "-delay" "$DELAY" "-random-delay" "$RANDOM_DELAY"
      "-rate-limit" "$RATE" "-concurrency" "$THREADS" "-parallelism" "$THREADS"
      "-timeout" "15" "-retry" "1"
      "-headers" "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    )
  elif [[ "${RECON_MODE}" == "aggressive" ]]; then
    katana_flags=(
      "-rate-limit" "$RATE" "-concurrency" "$THREADS" "-parallelism" "$THREADS"
      "-timeout" "8" "-retry" "3"
    )
  else
    katana_flags=(
      "-rate-limit" "$RATE" "-concurrency" "$THREADS" "-parallelism" "$THREADS"
      "-timeout" "10" "-retry" "2"
    )
  fi

  # Extensiones a excluir
  local exclude_ext="png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot,ico,css,mp4,mp3,zip,pdf,tar,gz,webp"

  katana \
    -list "$input_file" \
    -depth "$KATANA_DEPTH" \
    -js-crawl \
    -known-files all \
    -form-extraction \
    -extension-filter "$exclude_ext" \
    -silent \
    -o "$output" \
    "${katana_flags[@]}" \
    2>/dev/null || true

  # Filtrar endpoints interesantes
  grep -iE \
    "(/api/|/v[0-9]+/|/graphql|/admin|/panel|/dashboard|/login|/auth|/oauth|\
/upload|/download|/export|/import|/backup|/config|/debug|/test|/internal|\
\.(php|asp|aspx|jsp|json|xml|env|yml|yaml|toml|bak|sql|log|git)\b|\
\?(.*=))" \
    "$output" > "$output_interesting" 2>/dev/null || true

  [[ -s "$output" ]] && sort -u "$output" -o "$output"
  [[ -s "$output_interesting" ]] && sort -u "$output_interesting" -o "$output_interesting"

  log_ok "Endpoints totales: $(wc -l < "$output" 2>/dev/null || echo 0)"
  log_ok "Endpoints interesantes: $(wc -l < "$output_interesting" 2>/dev/null || echo 0)"
}

# ──────────────────────────────────────────────
# M7 — ATTACK SURFACE SCORING
#
# Sistema de puntuación para priorizar endpoints:
#   +5  parámetro de ID/user/account/wallet (candidato IDOR)
#   +4  path sensible (/admin, /api, /graphql, /auth, /internal)
#   +3  extensión peligrosa (.php, .asp, .jsp, .aspx, .do)
#   +2  tech interesante (WordPress, .NET, etc.) en el host
#   +2  respuesta JSON / API
#   +1  archivo JS
#   +3  puerto no estándar
#   +2  subdominio funcional (api, auth, admin, internal, backend)
#
# Outputs:
#   scoring/all_urls.txt          — todas las URLs dedup
#   scoring/scored_urls.txt       — URL + score (tsv)
#   scoring/high_priority.txt     — score >= 10
#   scoring/medium_priority.txt   — score 5-9
#   scoring/low_priority.txt      — score < 5
#   scoring/idor_candidates.txt   — params numéricos/UUID
#   scoring/api_endpoints.txt     — paths /api, /v1, /graphql
#   scoring/js_files.txt          — .js para SecretFinder
#   scoring/new_endpoints.txt     — solo katana (no en wayback)
#   scoring/legacy_endpoints.txt  — solo wayback (históricas)
# ──────────────────────────────────────────────
run_scoring() {
  log_section "M7 — Attack Surface Scoring"

  local httpx_json="${HTTPX_DIR}/httpx_output.json"
  local katana_out="${KATANA_DIR}/katana_output.txt"
  local wayback_out="${WAYBACK_DIR}/wayback_output.txt"
  local all_urls="${SCORING_DIR}/all_urls.txt"
  local scored="${SCORING_DIR}/scored_urls.tsv"
  local high="${SCORING_DIR}/high_priority.txt"
  local medium="${SCORING_DIR}/medium_priority.txt"
  local low="${SCORING_DIR}/low_priority.txt"
  local idor="${SCORING_DIR}/idor_candidates.txt"
  local api="${SCORING_DIR}/api_endpoints.txt"
  local js="${SCORING_DIR}/js_files.txt"
  local new_ep="${SCORING_DIR}/new_endpoints.txt"
  local legacy_ep="${SCORING_DIR}/legacy_endpoints.txt"

  # ── Paso 1: Merge + normalizar + dedup ───────
  > "$all_urls"
  [[ -s "$katana_out" ]] && cat "$katana_out" >> "$all_urls"
  [[ -s "$wayback_out" ]] && cat "$wayback_out" >> "$all_urls"
  # Normalizar: quitar trailing slash, query params vacíos
  sed -i 's|/$||; s|\?$||; s|#.*$||' "$all_urls"
  sort -u "$all_urls" -o "$all_urls"

  local total_urls
  total_urls=$(wc -l < "$all_urls")
  log_info "URLs totales (dedup): ${total_urls}"

  # ── Paso 2: Construir set de hosts con tech interesante ──
  local interesting_tech_hosts="${HTTPX_DIR}/httpx_interesting_tech.txt"

  # ── Paso 3: Scoring en Python (más rápido y limpio que bash puro) ──
  python3 - <<PYEOF
import re, sys
from pathlib import Path

all_urls_path = "${all_urls}"
httpx_json_path = "${httpx_json}"
interesting_tech_path = "${interesting_tech_hosts}"
scored_path = "${scored}"
high_path = "${high}"
medium_path = "${medium}"
low_path = "${low}"
idor_path = "${idor}"
api_path = "${api}"
js_path = "${js}"

# Cargar hosts con tech interesante
interesting_hosts = set()
if Path(interesting_tech_path).exists():
    for line in Path(interesting_tech_path).read_text().splitlines():
        host = re.sub(r'https?://', '', line).split('/')[0]
        interesting_hosts.add(host)

# Cargar urls
try:
    urls = Path(all_urls_path).read_text().splitlines()
except:
    urls = []

# Regexes de scoring
IDOR_PARAMS = re.compile(
    r'[?&](id|user|user_id|account|account_id|wallet|transaction|order|order_id|'
    r'profile|basket|cart|uuid|token|uid|pid|cid|tid|ref|invoice)=[0-9a-f\-]{1,}',
    re.IGNORECASE
)
SENSITIVE_PATH = re.compile(
    r'/(api|v[0-9]+|graphql|admin|panel|dashboard|login|auth|oauth|internal|'
    r'upload|download|export|import|backup|config|debug|test|swagger|openapi|'
    r'manage|management|cms|wp-admin|wp-json|actuator|metrics|health|env)',
    re.IGNORECASE
)
DANGEROUS_EXT = re.compile(r'\.(php|asp|aspx|jsp|do|action|cfm|cgi|pl|py|rb)(\?|$)', re.IGNORECASE)
JSON_RESP = re.compile(r'\.(json|xml)(\?|$)', re.IGNORECASE)
JS_FILE = re.compile(r'\.js(\?|$)', re.IGNORECASE)
NON_STANDARD_PORT = re.compile(r':\d{4,5}/')
FUNCTIONAL_SUBDOMAIN = re.compile(
    r'(api|auth|admin|internal|backend|portal|gateway|dev|staging|test|demo|'
    r'legacy|old|beta|v[0-9]|stats|data|analytics|manage|cdn|upload|download)',
    re.IGNORECASE
)

results = []
idor_list, api_list, js_list = [], [], []

for url in urls:
    if not url.strip():
        continue
    url = url.strip()
    score = 0
    reasons = []

    # IDOR candidates (+5)
    if IDOR_PARAMS.search(url):
        score += 5
        reasons.append("idor_param")
        idor_list.append(url)

    # Sensitive path (+4)
    if SENSITIVE_PATH.search(url):
        score += 4
        reasons.append("sensitive_path")
        api_list.append(url)

    # Dangerous extension (+3)
    if DANGEROUS_EXT.search(url):
        score += 3
        reasons.append("dangerous_ext")

    # Interesting tech on host (+2)
    host = re.sub(r'https?://', '', url).split('/')[0]
    if host in interesting_hosts:
        score += 2
        reasons.append("interesting_tech")

    # JSON/API response type (+2)
    if JSON_RESP.search(url):
        score += 2
        reasons.append("json_resp")

    # JS file (+1)
    if JS_FILE.search(url):
        score += 1
        reasons.append("js_file")
        js_list.append(url)

    # Non-standard port (+3)
    if NON_STANDARD_PORT.search(url):
        score += 3
        reasons.append("non_std_port")

    # Functional subdomain (+2)
    if FUNCTIONAL_SUBDOMAIN.search(host.split('.')[0]):
        score += 2
        reasons.append("functional_subdomain")

    results.append((score, url, ','.join(reasons) if reasons else 'none'))

# Ordenar por score descendente
results.sort(key=lambda x: -x[0])

# Escribir TSV con score
with open(scored_path, 'w') as f:
    f.write("score\turl\treasons\n")
    for score, url, reasons in results:
        f.write(f"{score}\t{url}\t{reasons}\n")

# Clasificar por prioridad
with open(high_path, 'w') as fh, open(medium_path, 'w') as fm, open(low_path, 'w') as fl:
    for score, url, _ in results:
        if score >= 10:
            fh.write(url + '\n')
        elif score >= 5:
            fm.write(url + '\n')
        else:
            fl.write(url + '\n')

# Escribir listas especializadas (dedup)
Path(idor_path).write_text('\n'.join(sorted(set(idor_list))) + '\n')
Path(api_path).write_text('\n'.join(sorted(set(api_list))) + '\n')
Path(js_path).write_text('\n'.join(sorted(set(js_list))) + '\n')

print(f"Scored: {len(results)} URLs")
print(f"High priority (>=10): {sum(1 for s,_,_ in results if s>=10)}")
print(f"Medium (5-9): {sum(1 for s,_,_ in results if 5<=s<10)}")
print(f"Low (<5): {sum(1 for s,_,_ in results if s<5)}")
print(f"IDOR candidates: {len(set(idor_list))}")
print(f"API endpoints: {len(set(api_list))}")
print(f"JS files: {len(set(js_list))}")
PYEOF

  # ── Paso 4: New vs Legacy endpoints ──────────
  # New: solo en katana (probablemente activos y no revisados)
  if [[ -s "$katana_out" ]] && [[ -s "$wayback_out" ]]; then
    comm -23 <(sort "$katana_out") <(sort "$wayback_out") > "$new_ep" 2>/dev/null || true
    comm -13 <(sort "$katana_out") <(sort "$wayback_out") > "$legacy_ep" 2>/dev/null || true
    log_info "Nuevos (solo katana): $(wc -l < "$new_ep" 2>/dev/null || echo 0)"
    log_info "Legacy (solo wayback): $(wc -l < "$legacy_ep" 2>/dev/null || echo 0)"
  fi

  log_ok "Scoring completado → ${SCORING_DIR}/"
  log_ok "High priority: $(wc -l < "$high" 2>/dev/null || echo 0) endpoints"
  log_ok "IDOR candidates: $(wc -l < "$idor" 2>/dev/null || echo 0)"
}

# ──────────────────────────────────────────────
# M8 — SECRET DISCOVERY (con filtro de falsos positivos)
# ──────────────────────────────────────────────
run_secrets() {
  log_section "M8 — Secret Discovery (SecretFinder + TruffleHog)"
  local js_urls="${SCORING_DIR}/js_files.txt"
  local raw_secrets="${SECRETS_DIR}/secrets_raw.txt"
  local potential="${SECRETS_DIR}/potential_secrets.txt"
  local false_pos="${SECRETS_DIR}/false_positives.txt"
  local trufflehog_out="${SECRETS_DIR}/trufflehog_output.json"

  # Regex de falsos positivos comunes
  local FP_REGEX='example\.com|test|placeholder|changeme|yourapikey|your_key|INSERT_KEY|YOUR_TOKEN|REPLACE_ME|xxxx|1234567890|000000|aaaaaa|dummy|sample|foobar|lorem'

  # SecretFinder sobre JS files
  if command -v SecretFinder &>/dev/null && [[ -s "$js_urls" ]]; then
    local js_count
    js_count=$(wc -l < "$js_urls")
    log_info "SecretFinder sobre ${js_count} archivos JS..."
    > "$raw_secrets"
    while IFS= read -r js_url; do
      [[ -z "$js_url" ]] && continue
      python3 SecretFinder.py -i "$js_url" -o cli 2>/dev/null >> "$raw_secrets" || true
    done < "$js_urls"

    # Filtrar falsos positivos
    grep -viE "$FP_REGEX" "$raw_secrets" | sort -u > "$potential" 2>/dev/null || true
    grep -iE  "$FP_REGEX" "$raw_secrets" | sort -u > "$false_pos"  2>/dev/null || true

    log_ok "Secretos potenciales: $(wc -l < "$potential" 2>/dev/null || echo 0) → ${potential}"
    log_ok "Falsos positivos filtrados: $(wc -l < "$false_pos" 2>/dev/null || echo 0) → ${false_pos}"
  else
    log_skip "SecretFinder"
  fi

  # TruffleHog
  if command -v trufflehog &>/dev/null; then
    log_info "TruffleHog sobre outputs del proyecto..."
    trufflehog filesystem "${PROJECT_DIR}/content" \
      --json --no-update 2>/dev/null > "$trufflehog_out" || true

    # Filtrar falsos positivos del output de TruffleHog
    if [[ -s "$trufflehog_out" ]]; then
      local found
      found=$(grep -c '"DetectorName"' "$trufflehog_out" 2>/dev/null || echo 0)
      local real_secrets
      real_secrets=$(grep -viE "$FP_REGEX" "$trufflehog_out" | grep -c '"DetectorName"' 2>/dev/null || echo 0)
      log_ok "TruffleHog: ${found} hits, ~${real_secrets} tras filtro FP → ${trufflehog_out}"
    else
      log_ok "TruffleHog: sin resultados"
    fi
  else
    log_skip "trufflehog"
  fi
}

# ──────────────────────────────────────────────
# M9 — CONTENT DISCOVERY (solo sobre high-priority hosts)
# Respeta --skip-fuzz
# ──────────────────────────────────────────────
run_fuzzing() {
  log_section "M9 — Content Discovery (ffuf / feroxbuster)"

  if [[ "${SKIP_FUZZ:-false}" == "true" ]]; then
    log_info "--skip-fuzz activado. Saltando módulo."
    return
  fi

  local httpx_json="${HTTPX_DIR}/httpx_output.json"
  local interesting_tech="${HTTPX_DIR}/httpx_interesting_tech.txt"
  local login_panels="${HTTPX_DIR}/httpx_login_panels.txt"
  local api_hosts="${HTTPX_DIR}/httpx_api_hosts.txt"
  local error_hosts="${HTTPX_DIR}/httpx_errors.txt"

  # Wordlist
  local wl=""
  for candidate in \
    "/usr/share/seclists/Discovery/Web-Content/common.txt" \
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt" \
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"; do
    [[ -f "$candidate" ]] && { wl="$candidate"; break; }
  done

  if [[ -z "$wl" ]]; then
    log_warn "Sin wordlist. Instala SecLists: sudo apt install seclists"
    return
  fi
  log_info "Wordlist: $wl | threads=${FFUF_THREADS} rate=${FFUF_RATE}"

  # Construir lista de hosts a fuzzear: SOLO los más prometedores
  local fuzz_targets
  fuzz_targets=$(mktemp)
  cat "$interesting_tech" "$login_panels" "$api_hosts" "$error_hosts" \
    2>/dev/null | sort -u | head -10 > "$fuzz_targets"

  local fuzz_count
  fuzz_count=$(wc -l < "$fuzz_targets")

  if [[ $fuzz_count -eq 0 ]]; then
    log_warn "Sin hosts prometedores para fuzzear. Usando los primeros 5 activos."
    grep -oP 'https?://[^\s\[\]]+' "${HTTPX_DIR}/httpx_output.txt" 2>/dev/null | \
      head -5 > "$fuzz_targets" || true
    fuzz_count=$(wc -l < "$fuzz_targets")
  fi

  log_info "Fuzzeando ${fuzz_count} hosts (priorizados por tech/panel/API/error)"

  while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    local safe_name
    safe_name=$(echo "$host" | sed 's|https\?://||;s|/.*||;s|[^a-zA-Z0-9._-]|_|g')

    if command -v ffuf &>/dev/null; then
      local ffuf_out="${FUZZING_DIR}/ffuf_${safe_name}.json"
      log_info "  [ffuf] → $host"
      ffuf \
        -w "$wl" -u "${host}/FUZZ" \
        -mc 200,201,204,301,302,307,401,403,405,500 \
        -t "$FFUF_THREADS" -rate "$FFUF_RATE" \
        -timeout 10 -silent \
        -o "$ffuf_out" -of json \
        2>/dev/null || true

    elif command -v feroxbuster &>/dev/null; then
      local ferox_out="${FUZZING_DIR}/feroxbuster_${safe_name}.txt"
      log_info "  [feroxbuster] → $host"
      feroxbuster \
        --url "$host" --wordlist "$wl" \
        --status-codes 200,201,204,301,302,307,401,403,405,500 \
        --threads "$FFUF_THREADS" --rate-limit "$FFUF_RATE" \
        --timeout 10 --silent \
        --output "$ferox_out" --no-recursion \
        2>/dev/null || true
    else
      log_skip "ffuf / feroxbuster"
      rm -f "$fuzz_targets"
      return
    fi

  done < "$fuzz_targets"
  rm -f "$fuzz_targets"

  log_ok "Content discovery completado → ${FUZZING_DIR}/"
}

# ──────────────────────────────────────────────
# M10 — FILTRO OUT OF SCOPE
# ──────────────────────────────────────────────
filter_out_scope() {
  log_section "M10 — Filtrando Out of Scope"

  if [[ -z "${INPUT_OUTSCOPE_FILE:-}" ]] || [[ ! -f "${INPUT_OUTSCOPE_FILE:-}" ]]; then
    log_warn "Sin out_scope.txt — saltando filtro."
    return
  fi

  cp "$INPUT_OUTSCOPE_FILE" "${CONTENT_DIR}/out_scope.txt"
  local oos="${CONTENT_DIR}/out_scope.txt"
  sed -i '/^[[:space:]]*$/d' "$oos"
  log_info "$(wc -l < "$oos") entradas OOS"

  filter_file "${SUBFINDER_DIR}/subfinder_output.txt"     "$oos" "${SUBFINDER_DIR}/subfinder_output_unfiltered.txt"
  filter_file "${HTTPX_DIR}/httpx_output.txt"             "$oos" "${HTTPX_DIR}/httpx_output_unfiltered.txt"
  filter_file "${WAYBACK_DIR}/wayback_output.txt"         "$oos" "${WAYBACK_DIR}/wayback_output_unfiltered.txt"
  filter_file "${KATANA_DIR}/katana_output.txt"           "$oos" "${KATANA_DIR}/katana_output_unfiltered.txt"
  filter_file "${SCORING_DIR}/high_priority.txt"          "$oos" "${SCORING_DIR}/high_priority_unfiltered.txt"
  filter_file "${SCORING_DIR}/idor_candidates.txt"        "$oos" "${SCORING_DIR}/idor_candidates_unfiltered.txt"
  filter_file "${SCORING_DIR}/api_endpoints.txt"          "$oos" "${SCORING_DIR}/api_endpoints_unfiltered.txt"

  log_ok "Filtro OOS completado"
}

# ──────────────────────────────────────────────
# M11 — NUCLEI (sobre high_priority.txt, dedup)
# En stealth: máximo 200 URLs
# ──────────────────────────────────────────────
run_nuclei() {
  log_section "M11 — Nuclei (sobre high_priority + hosts activos)"
  local high_priority="${SCORING_DIR}/high_priority.txt"
  local httpx_file="${HTTPX_DIR}/httpx_output.txt"
  local nuclei_input="${NUCLEI_DIR}/nuclei_input.txt"
  local output="${NUCLEI_DIR}/nuclei_output.txt"
  local output_json="${NUCLEI_DIR}/nuclei_output.json"

  # Construir input: high_priority + hosts activos de httpx (dedup)
  > "$nuclei_input"
  [[ -s "$high_priority" ]] && cat "$high_priority" >> "$nuclei_input"
  if [[ -s "$httpx_file" ]]; then
    grep -oP 'https?://[^\s\[\]]+' "$httpx_file" 2>/dev/null >> "$nuclei_input" || \
      awk '{print $1}' "$httpx_file" >> "$nuclei_input" 2>/dev/null || true
  fi

  # Normalizar + dedup
  sed -i 's|/$||; s|\?$||; s|#.*$||' "$nuclei_input"
  sort -u "$nuclei_input" -o "$nuclei_input"
  sed -i '/^[[:space:]]*$/d' "$nuclei_input"

  local total_input
  total_input=$(wc -l < "$nuclei_input")

  # En stealth limitar a 200 URLs
  if [[ "${RECON_MODE}" == "stealth" ]] && [[ $total_input -gt 200 ]]; then
    log_info "Stealth: limitando nuclei input a 200 URLs (de ${total_input})"
    head -200 "$nuclei_input" > "${nuclei_input}.tmp"
    mv "${nuclei_input}.tmp" "$nuclei_input"
    total_input=200
  fi

  [[ $total_input -eq 0 ]] && { log_warn "Sin URLs para nuclei."; return; }
  log_info "Escaneando ${total_input} URLs (threads=${NUCLEI_THREADS} rate=${NUCLEI_RATE})..."

  nuclei \
    -l "$nuclei_input" \
    -tags "misconfig,exposure,cve,takeover,default-login,info,token" \
    -severity "info,low,medium,high,critical" \
    -c "$NUCLEI_THREADS" -rate-limit "$NUCLEI_RATE" \
    -timeout 10 -silent \
    -o "$output" -json-export "$output_json" \
    2>/dev/null || true

  local findings
  findings=$(wc -l < "$output" 2>/dev/null || echo 0)

  if [[ $findings -gt 0 ]]; then
    log_warn "Nuclei: ${findings} findings → ${output}"
    for sev in critical high medium low info; do
      local count
      count=$(grep -ic "\[${sev}\]" "$output" 2>/dev/null || echo 0)
      [[ $count -gt 0 ]] && log_warn "    [${sev}]: ${count}"
    done
  else
    log_ok "Nuclei: sin findings"
  fi
}

# ──────────────────────────────────────────────
# M12 — REPORTE JSON (estadísticas + muestras + rutas)
# Sin arrays completos — solo muestras de 20-50 items
# ──────────────────────────────────────────────
generate_report() {
  log_section "M12 — Generando reporte JSON"
  local report="${CONTENT_DIR}/recon_report.json"

  # Conteos
  local c_subdomains c_resolved c_active_hosts
  local c_wayback c_wayback_interesting
  local c_katana c_katana_interesting
  local c_high c_medium c_low c_idor c_api c_js c_new c_legacy
  local c_nuclei c_secrets

  c_subdomains=$(wc -l < "${SUBFINDER_DIR}/subfinder_output.txt"   2>/dev/null || echo 0)
  c_resolved=$(wc -l   < "${DNSX_DIR}/dnsx_resolved.txt"           2>/dev/null || echo 0)
  c_active_hosts=$(wc -l < "${HTTPX_DIR}/httpx_output.txt"         2>/dev/null || echo 0)
  c_wayback=$(wc -l    < "${WAYBACK_DIR}/wayback_output.txt"        2>/dev/null || echo 0)
  c_wayback_interesting=$(wc -l < "${WAYBACK_DIR}/wayback_interesting.txt" 2>/dev/null || echo 0)
  c_katana=$(wc -l     < "${KATANA_DIR}/katana_output.txt"          2>/dev/null || echo 0)
  c_katana_interesting=$(wc -l < "${KATANA_DIR}/katana_interesting.txt"   2>/dev/null || echo 0)
  c_high=$(wc -l       < "${SCORING_DIR}/high_priority.txt"         2>/dev/null || echo 0)
  c_medium=$(wc -l     < "${SCORING_DIR}/medium_priority.txt"       2>/dev/null || echo 0)
  c_low=$(wc -l        < "${SCORING_DIR}/low_priority.txt"          2>/dev/null || echo 0)
  c_idor=$(wc -l       < "${SCORING_DIR}/idor_candidates.txt"       2>/dev/null || echo 0)
  c_api=$(wc -l        < "${SCORING_DIR}/api_endpoints.txt"         2>/dev/null || echo 0)
  c_js=$(wc -l         < "${SCORING_DIR}/js_files.txt"              2>/dev/null || echo 0)
  c_new=$(wc -l        < "${SCORING_DIR}/new_endpoints.txt"         2>/dev/null || echo 0)
  c_legacy=$(wc -l     < "${SCORING_DIR}/legacy_endpoints.txt"      2>/dev/null || echo 0)
  c_nuclei=$(wc -l     < "${NUCLEI_DIR}/nuclei_output.txt"          2>/dev/null || echo 0)
  c_secrets=$(wc -l    < "${SECRETS_DIR}/potential_secrets.txt"     2>/dev/null || echo 0)

  # Targets + OOS JSON
  local targets_json outscope_json="null" outscope_applied="false"
  targets_json=$(awk '{printf "\"%s\",", $0}' "$TARGETS_FILE" | sed 's/,$//')
  if [[ -f "${CONTENT_DIR}/out_scope.txt" ]]; then
    outscope_applied="true"
    outscope_json="[$(awk '{printf "\"%s\",", $0}' "${CONTENT_DIR}/out_scope.txt" | sed 's/,$//')]"
  fi

  # Muestras (máx 20 cada una para mantener el JSON ligero)
  local s_high;   s_high=$(to_json_array   "${SCORING_DIR}/high_priority.txt" 20)
  local s_idor;   s_idor=$(to_json_array   "${SCORING_DIR}/idor_candidates.txt" 20)
  local s_api;    s_api=$(to_json_array    "${SCORING_DIR}/api_endpoints.txt" 20)
  local s_new;    s_new=$(to_json_array    "${SCORING_DIR}/new_endpoints.txt" 20)
  local s_nuclei; s_nuclei=$(to_json_array "${NUCLEI_DIR}/nuclei_output.txt" 20)
  local s_hosts;  s_hosts=$(to_json_array  "${HTTPX_DIR}/httpx_output.txt" 20)

  cat > "$report" <<EOF
{
  "project": "${PROJECT_NAME}",
  "date": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "recon_mode": "${RECON_MODE}",
  "waf_detected": "${WAF_DETECTED:-unknown}",
  "scope": {
    "targets": [${targets_json}],
    "out_of_scope_applied": ${outscope_applied},
    "out_of_scope": ${outscope_json}
  },
  "summary": {
    "subdomains_enumerated":     ${c_subdomains},
    "subdomains_dns_resolved":   ${c_resolved},
    "active_hosts":              ${c_active_hosts},
    "wayback_total":             ${c_wayback},
    "wayback_interesting":       ${c_wayback_interesting},
    "katana_endpoints":          ${c_katana},
    "katana_interesting":        ${c_katana_interesting},
    "attack_surface_scoring": {
      "high_priority":           ${c_high},
      "medium_priority":         ${c_medium},
      "low_priority":            ${c_low},
      "idor_candidates":         ${c_idor},
      "api_endpoints":           ${c_api},
      "js_files":                ${c_js},
      "new_endpoints":           ${c_new},
      "legacy_endpoints":        ${c_legacy}
    },
    "nuclei_findings":           ${c_nuclei},
    "potential_secrets":         ${c_secrets}
  },
  "samples": {
    "note": "Primeras 20 entradas de cada categoría. Ver archivos completos en /files.",
    "active_hosts":       [${s_hosts}],
    "high_priority":      [${s_high}],
    "idor_candidates":    [${s_idor}],
    "api_endpoints":      [${s_api}],
    "new_endpoints":      [${s_new}],
    "nuclei_findings":    [${s_nuclei}]
  },
  "files": {
    "targets":                "${TARGETS_FILE}",
    "out_scope":              "${CONTENT_DIR}/out_scope.txt",
    "subfinder_output":       "${SUBFINDER_DIR}/subfinder_output.txt",
    "dnsx_resolved":          "${DNSX_DIR}/dnsx_resolved.txt",
    "dnsx_full":              "${DNSX_DIR}/dnsx_full.txt",
    "wafw00f_output":         "${WAFW00F_DIR}/wafw00f_output.txt",
    "httpx_output":           "${HTTPX_DIR}/httpx_output.txt",
    "httpx_output_json":      "${HTTPX_DIR}/httpx_output.json",
    "httpx_interesting_tech": "${HTTPX_DIR}/httpx_interesting_tech.txt",
    "httpx_login_panels":     "${HTTPX_DIR}/httpx_login_panels.txt",
    "httpx_api_hosts":        "${HTTPX_DIR}/httpx_api_hosts.txt",
    "httpx_errors":           "${HTTPX_DIR}/httpx_errors.txt",
    "wayback_output":         "${WAYBACK_DIR}/wayback_output.txt",
    "wayback_interesting":    "${WAYBACK_DIR}/wayback_interesting.txt",
    "katana_input":           "${KATANA_DIR}/katana_input.txt",
    "katana_output":          "${KATANA_DIR}/katana_output.txt",
    "katana_interesting":     "${KATANA_DIR}/katana_interesting.txt",
    "scoring_all_urls":       "${SCORING_DIR}/all_urls.txt",
    "scoring_scored_tsv":     "${SCORING_DIR}/scored_urls.tsv",
    "high_priority":          "${SCORING_DIR}/high_priority.txt",
    "medium_priority":        "${SCORING_DIR}/medium_priority.txt",
    "low_priority":           "${SCORING_DIR}/low_priority.txt",
    "idor_candidates":        "${SCORING_DIR}/idor_candidates.txt",
    "api_endpoints":          "${SCORING_DIR}/api_endpoints.txt",
    "js_files":               "${SCORING_DIR}/js_files.txt",
    "new_endpoints":          "${SCORING_DIR}/new_endpoints.txt",
    "legacy_endpoints":       "${SCORING_DIR}/legacy_endpoints.txt",
    "potential_secrets":      "${SECRETS_DIR}/potential_secrets.txt",
    "false_positives":        "${SECRETS_DIR}/false_positives.txt",
    "trufflehog_output":      "${SECRETS_DIR}/trufflehog_output.json",
    "fuzzing_dir":            "${FUZZING_DIR}/",
    "nuclei_input":           "${NUCLEI_DIR}/nuclei_input.txt",
    "nuclei_output":          "${NUCLEI_DIR}/nuclei_output.txt",
    "nuclei_output_json":     "${NUCLEI_DIR}/nuclei_output.json"
  }
}
EOF

  if command -v jq &>/dev/null; then
    jq . "$report" > "${report}.tmp" && mv "${report}.tmp" "$report"
  fi

  log_ok "Reporte → ${report}"
}

# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────
main() {
  banner

  [[ $# -lt 1 ]] && usage

  PROJECT_NAME="$1"
  INPUT_TARGETS_FILE="${2:-}"
  INPUT_OUTSCOPE_FILE="${3:-}"
  RECON_MODE="normal"
  SKIP_FUZZ="false"
  WAF_DETECTED="unknown"

  # Parsear flags desde cualquier posición
  for arg in "$@"; do
    case "$arg" in
      --stealth)    RECON_MODE="stealth" ;;
      --normal)     RECON_MODE="normal" ;;
      --aggressive) RECON_MODE="aggressive" ;;
      --skip-fuzz)  SKIP_FUZZ="true" ;;
    esac
  done

  # Limpiar si 2do/3er arg son flags
  [[ "${INPUT_TARGETS_FILE:-}" =~ ^-- ]] && INPUT_TARGETS_FILE=""
  [[ "${INPUT_OUTSCOPE_FILE:-}" =~ ^-- ]] && INPUT_OUTSCOPE_FILE=""

  set_mode_config

  # ── Pipeline ────────────────────────────────
  check_deps
  create_structure
  collect_targets

  run_subdomain_enum    # M1 — subfinder+assetfinder+amass (paralelo)
  run_dnsx              # M2 — validar DNS
  run_wafw00f           # M3 — detectar WAF → preguntar si cambiar modo
  run_httpx             # M4 — hosts activos + clasificación
  run_wayback           # M5 — gau+waybackurls por dominio raíz (paralelo)
  run_katana            # M6 — crawl priorizado y limitado

  run_scoring           # M7 — attack surface scoring (Python)

  run_secrets           # M8 — SecretFinder+TruffleHog (filtro FP)
  run_fuzzing           # M9 — ffuf/feroxbuster solo high-priority

  filter_out_scope      # M10 — filtrar OOS de todos los outputs

  run_nuclei            # M11 — nuclei sobre high_priority (dedup, limitado en stealth)
  generate_report       # M12 — reporte JSON ligero
  # ────────────────────────────────────────────

  log_section "✅  Recon completado"
  log_ok "Proyecto:  ${PROJECT_NAME}"
  log_ok "Modo:      ${RECON_MODE}"
  log_ok "WAF:       ${WAF_DETECTED}"
  echo ""
  log_info "Empieza por aquí:"
  echo "    cat ${SCORING_DIR}/high_priority.txt     # Top endpoints"
  echo "    cat ${SCORING_DIR}/idor_candidates.txt   # Candidatos IDOR"
  echo "    cat ${SCORING_DIR}/scored_urls.tsv       # Todos con score"
  echo "    cat ${NUCLEI_DIR}/nuclei_output.txt      # Findings nuclei"
  echo "    cat ${SECRETS_DIR}/potential_secrets.txt # Secrets potenciales"
  echo ""
}

main "$@"
