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
#    [M13] IP Discovery & Port Scanning  → extrae IPs + escanea puertos
#
#  Uso:
#    bash recon.sh <proyecto> [targets.txt] [out_scope.txt] [--normal|--stealth|--aggressive]
# =============================================================================

set -uo pipefail
# Nota: eliminamos -e intencionalmente para que Ctrl+C no mate
# subprocesos en mitad de una escritura y deje archivos de 0 bytes.
# Cada función maneja sus propios errores con || true.

# ──────────────────────────────────────────────
# TRAP SIGINT — Ctrl+C guarda lo que hay y sale limpio
# ──────────────────────────────────────────────
_INTERRUPTED=0
_TMP_DIRS=()   # registro global de tmpdir para limpiar en trap

_cleanup_and_exit() {
  # Evitar doble ejecución si el trap se dispara varias veces
  [[ $_INTERRUPTED -eq 1 ]] && return
  _INTERRUPTED=1

  echo ""
  echo -e "\n${YELLOW}[!]${RESET} Interrupción detectada — guardando progreso y saliendo limpio..."

  # Matar procesos hijos incluyendo katana que puede quedar zombie
  local child_pids
  child_pids=$(jobs -p 2>/dev/null || true)
  [[ -n "$child_pids" ]] && kill -TERM $child_pids 2>/dev/null || true
  
  # Matar específicamente procesos katana que pueden quedar zombie
  pkill -f katana 2>/dev/null || true
  pkill -f "timeout.*katana" 2>/dev/null || true
  
  # Esperar un momento para que los procesos terminen limpiamente
  sleep 2
  
  # Forzar kill si aún hay procesos restantes
  child_pids=$(jobs -p 2>/dev/null || true)
  [[ -n "$child_pids" ]] && kill -KILL $child_pids 2>/dev/null || true

  # Limpiar tmpdirs registrados (nunca dejan archivos de 0 bytes en el proyecto)
  for d in "${_TMP_DIRS[@]:-}"; do
    [[ -d "$d" ]] && rm -rf "$d"
  done

  # Consolidar lo que ya se escribió en los tmpdir de M1/M5
  # (la función _flush_partial_results la llamamos antes de salir)
  _flush_partial_results 2>/dev/null || true

  # Mostrar lo que se salvó
  if [[ -n "${SUBFINDER_DIR:-}" && -s "${SUBFINDER_DIR:-}/subfinder_output.txt" ]]; then
    local saved; saved=$(wc -l < "${SUBFINDER_DIR:-}/subfinder_output.txt")
    echo -e "${GREEN}[✔]${RESET} Subdominios guardados hasta ahora: ${saved} → ${SUBFINDER_DIR:-}/subfinder_output.txt"
  fi
  # Repetir para HTTPX_DIR
  if [[ -n "${HTTPX_DIR:-}" && -s "${HTTPX_DIR:-}/httpx_output.txt" ]]; then
    local saved; saved=$(wc -l < "${HTTPX_DIR:-}/httpx_output.txt")
    echo -e "${GREEN}[✔]${RESET} Hosts activos guardados: ${saved} → ${HTTPX_DIR:-}/httpx_output.txt"
  fi

  echo -e "${CYAN}[*]${RESET} Puedes reanudar el pipeline manualmente desde donde quedó."
  exit 130  # convención: 128 + SIGINT(2)
}

trap '_cleanup_and_exit' INT TERM

# Hook para consolidar archivos temporales parciales en M1/M5
# Se llama tanto al final normal como en el trap
_flush_partial_results() {
  # M1: si hay tmpdir activo de enum, merge lo que haya
  if [[ -n "${_M1_TMPDIR:-}" && -d "${_M1_TMPDIR:-}" ]]; then
    local out="${SUBFINDER_DIR}/subfinder_output.txt"
    cat "${_M1_TMPDIR}"/*.txt 2>/dev/null | sort -u >> "$out" || true
    sort -u "$out" -o "$out" 2>/dev/null || true
  fi
  # M5: si hay tmpdir activo de wayback, merge lo que haya
  if [[ -n "${_M5_TMPDIR:-}" && -d "${_M5_TMPDIR:-}" ]]; then
    local out="${WAYBACK_DIR}/wayback_output.txt"
    cat "${_M5_TMPDIR}"/*.txt 2>/dev/null | sort -u >> "$out" || true
    sort -u "$out" -o "$out" 2>/dev/null || true
  fi
}

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

PURPLE='\033[0;35m'           # Morado oscuro
BRIGHT_MAGENTA='\033[1;35m'   # Morado brillante
BRIGHT_RED='\033[1;31m'       # Rojo brillante
DARK_RED='\033[0;31m'         # Rojo oscuro
NEON_PURPLE='\033[38;5;135m'  # Morado neón (256 colors)
NEON_RED='\033[38;5;196m'     # Rojo neón (256 colors)
HACKER_PRIMARY='\033[38;5;135m'     # Morado oscuro neón
HACKER_SECONDARY='\033[38;5;196m'   # Rojo brillante neón

# ──────────────────────────────────────────────
# BANNER 
# ──────────────────────────────────────────────
banner() {
  echo -e "${HACKER_PRIMARY}${BOLD}"
  echo "  ██╗████████╗███████╗██╗  ██╗ ██████╗  █████╗ ████████╗██╗     "
  echo "  ██║╚══██╔══╝╚══███╔╝██║ ██╔╝██╔═══██╗██╔══██╗╚══██╔══╝██║     "
  echo "  ██║   ██║     ███╔╝ █████╔╝ ██║   ██║███████║   ██║   ██║     "
  echo "  ██║   ██║    ███╔╝  ██╔═██╗ ██║   ██║██╔══██║   ██║   ██║     "
  echo "  ██║   ██║   ███████╗██║  ██╗╚██████╔╝██║  ██║   ██║   ███████╗"
  echo "  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝"
  echo -e "${RESET}${BRIGHT_RED}${BOLD}              Made By Deiv_Blazk / Kevon99 ${RESET}"
  echo -e "${HACKER_SECONDARY}  <https://github.com/Kevon99/Hacking-tools/tree/master/ITZKOATL>${RESET}"
  echo -e "${HACKER_PRIMARY}  ─────────────────────────────────────────────────────────────────${RESET}"
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

# FIX 1: Filtrar un archivo contra out_scope (ROBUSTO)
filter_file() {
    local file="$1"
    [[ ! -f "$file" ]] && return
    [[ ! -f "$INPUT_OUTSCOPE_FILE" ]] && return
    
    local tmp_filter
    tmp_filter=$(mktemp)
    
    # grep -vFf siempre escribe en tmp_filter, incluso si el resultado está vacío
    # El || true evita que el script falle si grep no encuentra coincidencias
    grep -vFf "$INPUT_OUTSCOPE_FILE" "$file" > "$tmp_filter" 2>/dev/null || true
    
    # Mover siempre el resultado (vacío o no) al archivo original
    mv "$tmp_filter" "$file"
}

# FIX 2: JSON Array Seguro (Sin Injection, Sin 1-byte files)
to_json_array() {
  local file="$1" limit="${2:-50}"
  
  # Si el archivo no existe o está vacío, retornar array JSON vacío
  if [[ ! -f "$file" ]] || [[ ! -s "$file" ]]; then
    echo "[]"
    return
  fi
  
  # Usar jq para escapar caracteres especiales (", \, etc.) de forma segura
  # -R: lee líneas como strings raw
  # -s: slurp para convertir a array JSON
  head -"$limit" "$file" 2>/dev/null | jq -R . 2>/dev/null | jq -s . 2>/dev/null || echo "[]"
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
      NUCLEI_THREADS=15
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
                "SecretFinder" "trufflehog" "ffuf" "feroxbuster" "parallel" "rg" "gf")
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
  IP_DISCOVER_DIR="${MAP_DIR}/ip_discover"

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
    "${NUCLEI_DIR}" \
    "${IP_DISCOVER_DIR}"

  log_ok "Carpetas creadas en ./${PROJECT_NAME}/"
}

# ──────────────────────────────────────────────
# M1 — ENUMERACIÓN DE SUBDOMINIOS (PARALELO)
# - subfinder + assetfinder con timeout por herramienta
# - amass SOLO en modo --aggressive (demasiado lento para uso diario)
# - GNU parallel con --bar para visibilidad
# - Sin parallel: logs en tiempo real por dominio
# - Registra _M1_TMPDIR para el trap de SIGINT
# ──────────────────────────────────────────────
run_subdomain_enum() {
  log_section "M1 — Enumeración de subdominios (paralelo, jobs=${PARALLEL_JOBS})"
  local output="${SUBFINDER_DIR}/subfinder_output.txt"
  _M1_TMPDIR=$(mktemp -d)
  _TMP_DIRS+=("$_M1_TMPDIR")
  export _M1_TMPDIR

  # Timeouts por herramienta (en segundos)
  local T_SUBFINDER=120   # 2 min máx por dominio
  local T_ASSETFINDER=60  # 1 min máx
  local T_AMASS=300       # 5 min máx (solo aggressive)

  _enum_domain() {
    local domain="$1"
    local out="${_M1_TMPDIR}/${domain//\//_}.txt"
    > "$out"

    # Subfinder: rápido y efectivo (3 min máximo)
    timeout 3m subfinder -d "$domain" -all -silent 2>/dev/null >> "$out" || true
    
    # Assetfinder: casi instantáneo
    if command -v assetfinder &>/dev/null; then
      assetfinder --subs-only "$domain" 2>/dev/null >> "$out" || true
    fi

    # AMASS: Solo si el modo es AGGRESSIVE, si no, se salta (es el que traba todo)
    if [[ "${RECON_MODE}" == "aggressive" ]]; then
      if command -v amass &>/dev/null; then
        timeout 7m amass enum -passive -d "$domain" -silent 2>/dev/null >> "$out" || true
      fi
    fi
  }
  export -f _enum_domain
  export RECON_MODE T_SUBFINDER T_ASSETFINDER T_AMASS

  if command -v parallel &>/dev/null; then
    log_info "GNU parallel --bar (${PARALLEL_JOBS} jobs)${RECON_MODE:+ | modo: $RECON_MODE}"
    # --bar: barra de progreso interactiva en terminal
    # --line-buffer: los logs de cada herramienta aparecen en tiempo real
    parallel --bar --line-buffer -j "${PARALLEL_JOBS}" _enum_domain :::: "${TARGETS_FILE}" 2>&1 || true
  else
    log_info "Modo background manual (${PARALLEL_JOBS} jobs max)"
    local pids=() domain_names=()
    while IFS= read -r domain; do
      [[ -z "$domain" ]] && continue
      log_info "  ▶ ${domain} (subfinder+assetfinder${RECON_MODE:+, amass en aggressive})"
      _enum_domain "$domain" &
      pids+=($!)
      domain_names+=("$domain")

      if [[ ${#pids[@]} -ge $PARALLEL_JOBS ]]; then
        # Esperar el slot más antiguo y loguear cuándo termina
        wait "${pids[0]}" 2>/dev/null || true
        log_ok "  ✔ ${domain_names[0]} completado"
        pids=("${pids[@]:1}")
        domain_names=("${domain_names[@]:1}")
      fi
    done < "$TARGETS_FILE"
    # Esperar todos los restantes
    for i in "${!pids[@]}"; do
      wait "${pids[$i]}" 2>/dev/null || true
      log_ok "  ✔ ${domain_names[$i]} completado"
    done
  fi

  # Merge + dedup
  cat "${_M1_TMPDIR}"/*.txt 2>/dev/null | sort -u > "$output" || true
  rm -rf "$_M1_TMPDIR"
  _M1_TMPDIR=""

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
  log_section "M3 — Detección de WAF (Muestreo)"

  if ! command -v wafw00f &>/dev/null; then
    log_skip "wafw00f"
    WAF_DETECTED="unknown"
    return
  fi

  local output="${WAFW00F_DIR}/waf_report.txt"

  [[ ! -s "$TARGETS_FILE" ]] && { WAF_DETECTED="unknown"; return; }

  log_info "Detectando WAF en dominios principales..."
  # Probamos solo los dominios principales, no todos los subdominios
  wafw00f -i "${TARGETS_FILE}" -o "$output" > /dev/null 2>&1

  if grep -qi "is behind" "$output" 2>/dev/null; then
      WAF_DETECTED="yes"
      log_warn "WAF detectado en los dominios principales."

      if [[ "${RECON_MODE}" != "stealth" ]]; then
        if [[ -t 0 ]]; then
          read -rp "  ¿Cambiar a modo STEALTH? [s/N]: " switch
          [[ "$switch" =~ ^[sS]$ ]] && { RECON_MODE="stealth"; set_mode_config; log_ok "Modo cambiado a STEALTH"; }
        else
          log_warn "Entorno no interactivo. Forzando STEALTH por detección de WAF."
          RECON_MODE="stealth"; set_mode_config
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
# - Límite de URLs por dominio para evitar GB de datos en e-commerce
# - Timeout por herramienta para evitar bloqueos infinitos
# - GNU parallel con --bar para visibilidad
# - Registra _M5_TMPDIR para el trap de SIGINT
# ──────────────────────────────────────────────
run_wayback() {
  log_section "M5 — URLs Históricas (gau + waybackurls, por dominio raíz)"
  local httpx_file="${HTTPX_DIR}/httpx_output.txt"
  local output="${WAYBACK_DIR}/wayback_output.txt"
  local output_interesting="${WAYBACK_DIR}/wayback_interesting.txt"

  [[ ! -s "$httpx_file" ]] && { log_warn "httpx vacío. Saltando."; touch "$output"; return; }

  # Extraer SOLO dominios raíz únicos
  local root_domains
  root_domains=$(grep -oP 'https?://[^\s\[\]]+' "$httpx_file" 2>/dev/null | \
    sed 's|https\?://||' | awk -F'/' '{print $1}' | \
    awk -F'.' '{n=NF; if(n>=3 && length($(n-1))<=3) print $(n-2)"."$(n-1)"."$n; else if(n>=2) print $(n-1)"."$n; else print $0}' | \
    sort -u)

  local root_count
  root_count=$(echo "$root_domains" | grep -c . 2>/dev/null || echo 0)
  log_info "Dominios raíz únicos: ${root_count} (de $(wc -l < "$httpx_file") hosts activos)"

  _M5_TMPDIR=$(mktemp -d)
  _TMP_DIRS+=("$_M5_TMPDIR")
  export _M5_TMPDIR

  # Límites según modo para evitar descarga de GBs en e-commerce gigantes
  local GAU_LIMIT WAYBACK_LIMIT T_GAU T_WAYBACK
  case "${RECON_MODE}" in
    stealth)
      GAU_LIMIT=2000;   WAYBACK_LIMIT=2000
      T_GAU=60;         T_WAYBACK=60   ;;
    aggressive)
      GAU_LIMIT=50000;  WAYBACK_LIMIT=50000
      T_GAU=300;        T_WAYBACK=300  ;;
    *)
      GAU_LIMIT=10000;  WAYBACK_LIMIT=10000
      T_GAU=120;        T_WAYBACK=120  ;;
  esac
  export GAU_LIMIT WAYBACK_LIMIT T_GAU T_WAYBACK

  _fetch_wayback() {
    local domain="$1"
    local out="${_M5_TMPDIR}/${domain//\//_}.txt"
    
    # Máximo 5 minutos por dominio para traer URLs históricas
    if command -v gau &>/dev/null; then
      echo "$domain" | timeout 5m gau --subs --threads 10 2>/dev/null >> "$out" || true

    fi
    
    if command -v waybackurls &>/dev/null; then
      echo "$domain" | timeout 5m waybackurls 2>/dev/null >> "$out" || true
    fi
  }
  export -f _fetch_wayback

  if command -v parallel &>/dev/null; then
    log_info "GNU parallel --bar | límite: gau=${GAU_LIMIT} wayback=${WAYBACK_LIMIT} URLs/dominio"
    echo "$root_domains" | \
      parallel --bar --line-buffer -j "${PARALLEL_JOBS}" \
      _fetch_wayback 2>&1 || true
  else
    log_info "Background manual | límite: gau=${GAU_LIMIT} wayback=${WAYBACK_LIMIT} URLs/dominio"
    local pids=() domain_names=()
    while IFS= read -r domain; do
      [[ -z "$domain" ]] && continue
      log_info "  ▶ ${domain}"
      _fetch_wayback "$domain" &
      pids+=($!)
      domain_names+=("$domain")
      if [[ ${#pids[@]} -ge $PARALLEL_JOBS ]]; then
        wait "${pids[0]}" 2>/dev/null || true
        log_ok "  ✔ ${domain_names[0]} completado"
        pids=("${pids[@]:1}")
        domain_names=("${domain_names[@]:1}")
      fi
    done <<< "$root_domains"
    for i in "${!pids[@]}"; do
      wait "${pids[$i]}" 2>/dev/null || true
      log_ok "  ✔ ${domain_names[$i]} completado"
    done
  fi

  # Merge + dedup global
  cat "${_M5_TMPDIR}"/*.txt 2>/dev/null | sort -u > "$output" || true
  rm -rf "$_M5_TMPDIR"
  _M5_TMPDIR=""

  # Filtrar extensiones sin valor
  grep -viE "\.(png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|ico|css|mp4|mp3|zip|pdf|tar|gz)(\?|$)" \
    "$output" 2>/dev/null | sort -u > "${output}.clean" && mv "${output}.clean" "$output" || true

  # URLs interesantes
  grep -iE "\.(php|asp|aspx|jsp|json|xml|env|config|bak|sql|log|git|yaml|yml|toml)\b|\?(.*=)" \
    "$output" | sort -u > "$output_interesting" 2>/dev/null || true

  log_ok "URLs históricas (dedup, sin estáticos): $(wc -l < "$output" 2>/dev/null || echo 0)"
  log_ok "URLs interesantes: $(wc -l < "$output_interesting" 2>/dev/null || echo 0)"
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

  # Timeout global para katana según modo
  local T_KATANA
  case "${RECON_MODE}" in
    stealth)    T_KATANA=600  ;;   # 10 min máx
    aggressive) T_KATANA=3600 ;;   # 1 hora
    *)          T_KATANA=1200 ;;   # 20 min
  esac
  log_info "Timeout katana: ${T_KATANA}s"

  timeout "${T_KATANA}" katana \
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
    r'profile|basket|cart|uuid|token|uid|pid|cid|tid|key|ref|invoice)=[0-9a-f\-]{1,}',
    re.IGNORECASE
)
SENSITIVE_PATH = re.compile(
    r'/(api|v[0-9]+|graphql|admin|panel|dashboard|login|auth|oauth|internal|'
    r'upload|download|export|import|backup|config|debug|test|swagger|openapi|'
    r'manage|management|cms|wp-admin|cms|api|v1|v2|v3|console|docker|wp-json|actuator|metrics|health|env)',
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

# FIX 3a: Escribir listas especializadas (evitar archivos de 1 byte con solo '\n')
idor_text = '\n'.join(sorted(set(idor_list))) + '\n' if idor_list else ''
Path(idor_path).write_text(idor_text)

api_text = '\n'.join(sorted(set(api_list))) + '\n' if api_list else ''
Path(api_path).write_text(api_text)

js_text = '\n'.join(sorted(set(js_list))) + '\n' if js_list else ''
Path(js_path).write_text(js_text)

print(f"Scored: {len(results)} URLs")
print(f"High priority (>=10): {sum(1 for s,_,_ in results if s>=10)}")
print(f"Medium (5-9): {sum(1 for s,_,_ in results if 5<=s<10)}")
print(f"Low (<5): {sum(1 for s,_,_ in results if s<5)}")
print(f"IDOR candidates: {len(set(idor_list))}")
print(f"API endpoints: {len(set(api_list))}")
print(f"JS files: {len(set(js_list))}")
PYEOF

  # ── Paso 4: New vs Legacy endpoints ──────────
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
# M8 — SECRET DISCOVERY 
# Combinación de múltiples técnicas:
#   1. gf patterns (rápido, patrones conocidos)
#   2. TruffleHog sobre URLs descargadas
#   3. Análisis de responses HTTP (headers + body)
#   4. strings + ripgrep en archivos JS
#   5. Filtro avanzado de falsos positivos
# ──────────────────────────────────────────────

run_secrets() {
  log_section "M8 — Secret Discovery (Multi-técnica, Ultra-Eficiente)"
  
  local js_urls="${SCORING_DIR}/js_files.txt"
  local api_urls="${SCORING_DIR}/api_endpoints.txt"
  local interesting_urls="${SCORING_DIR}/high_priority.txt"
  
  local secrets_dir="${SECRETS_DIR}"
  local gf_secrets="${secrets_dir}/gf_patterns_output.txt"
  local httpx_secrets="${secrets_dir}/httpx_responses_secrets.txt"
  local trufflehog_out="${secrets_dir}/trufflehog_findings.json"
  local ripgrep_secrets="${secrets_dir}/ripgrep_patterns.txt"
  local potential="${secrets_dir}/potential_secrets.txt"
  local false_pos="${secrets_dir}/false_positives.txt"
  local final_report="${secrets_dir}/secrets_summary.txt"
  
  > "$potential"
  > "$false_pos"
  
  # ── TÉCNICA 1: GF PATTERNS (Si disponible) ──────────────────
  if command -v gf &>/dev/null; then
    log_info "Técnica 1/4: GF Patterns (búsqueda de URLs sospechosas)..."
    
    _scan_with_gf() {
      local urls_file="$1"
      local pattern="$2"
      local out="$3"
      
      [[ ! -s "$urls_file" ]] && return
      
      # gf busca en URLs directamente
      while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        gf "$pattern" <<< "$url" 2>/dev/null
      done < "$urls_file" >> "$out" 2>/dev/null || true
    }
    
    # Patterns críticos: API Keys, AWS, Tokens, etc.
    for pattern in api aws slack firebase github shodan twilio; do
      [[ -s "$api_urls" ]] && _scan_with_gf "$api_urls" "$pattern" "$gf_secrets"
    done
    
    # Dedup + limpiar
    [[ -s "$gf_secrets" ]] && sort -u "$gf_secrets" -o "$gf_secrets"
    local gf_count=$(wc -l < "$gf_secrets" 2>/dev/null || echo 0)
    [[ $gf_count -gt 0 ]] && log_ok "  GF: ${gf_count} hallazgos potenciales"
  else
    log_skip "gf (patrones de grep-filter)"
  fi
  
  # ── TÉCNICA 2: ANÁLISIS DE RESPONSES HTTP (HEADERS + BODY) ────
  log_info "Técnica 2/4: Extrayendo secretos de responses HTTP..."
  
  _extract_http_secrets() {
    local urls_file="$1"
    local out="$2"
    
    [[ ! -s "$urls_file" ]] && return
    
    local total=$(wc -l < "$urls_file")
    [[ $total -eq 0 ]] && return
    
    # Limitar a 50 URLs para no abrumar la red
    local url_count=50
    if [[ $total -gt $url_count ]]; then
      head -"$url_count" "$urls_file" > "${urls_file}.sample"
      urls_file="${urls_file}.sample"
    fi
    
    # Descargar responses con httpx + jq
    # Capturar: headers (Authorization, X-API-Key, etc.) + body (strings sospechosas)
    httpx \
      -l "$urls_file" \
      -status-code -header "Authorization" -header "X-API-Key" \
      -timeout 8 -threads 15 -silent \
      -json 2>/dev/null | \
      jq -r '
        [
          (.headers.Authorization // empty),
          (.headers["X-API-Key"] // empty),
          (.headers["X-Access-Token"] // empty),
          (.headers["X-Auth-Token"] // empty),
          (.headers["Cf-Ray"] // empty),
          (.body // empty | strings)
        ] | 
        .[] | 
        select(length > 0)
      ' >> "$out" 2>/dev/null || true
    
    rm -f "${urls_file}.sample"
  }
  
  _extract_http_secrets "$interesting_urls" "$httpx_secrets"
  _extract_http_secrets "$api_urls" "$httpx_secrets"
  
  [[ -s "$httpx_secrets" ]] && sort -u "$httpx_secrets" -o "$httpx_secrets"
  local http_count=$(wc -l < "$httpx_secrets" 2>/dev/null || echo 0)
  [[ $http_count -gt 0 ]] && log_ok "  HTTP: ${http_count} valores extraídos"
  
  # ── TÉCNICA 3: RIPGREP (Búsqueda rápida en archivos JS descargados) ──
  log_info "Técnica 3/4: Ripgrep en archivos JS (patrones de secretos)..."
  
  _download_and_scan_js() {
    local urls_file="$1"
    local out="$2"
    
    [[ ! -s "$urls_file" ]] && return
    
    local js_cache="${SECRETS_DIR}/.js_cache"
    mkdir -p "$js_cache"
    
    local count=0
    while IFS= read -r js_url; do
      [[ -z "$js_url" ]] && continue
      [[ $count -ge 30 ]] && break  # Máximo 30 archivos JS
      
      local js_file
      js_file=$(echo "$js_url" | md5sum | awk '{print $1}')
      js_file="${js_cache}/${js_file}.js"
      
      # Descargar con timeout
      timeout 10s curl -s "$js_url" > "$js_file" 2>/dev/null || continue
      
      [[ ! -s "$js_file" ]] && continue
      
      # Ripgrep patterns: API keys, tokens, private keys, etc.
      rg -i '(api[_-]?key|secret[_-]?key|access[_-]?token|refresh[_-]?token|bearer\s+[a-zA-Z0-9\.\-_]+|password\s*=|private[_-]?key|aws[_-]?secret|mongodb[_-]?uri|firebase[_-]?key|slack[_-]?token|github[_-]?token|stripe[_-]?(secret|publishable)|shopify[_-]?token)' \
        "$js_file" >> "$out" 2>/dev/null || true
      
      ((count++))
    done < "$urls_file"
    
    rm -rf "$js_cache"
  }
  
  _download_and_scan_js "$js_urls" "$ripgrep_secrets"
  
  [[ -s "$ripgrep_secrets" ]] && sort -u "$ripgrep_secrets" -o "$ripgrep_secrets"
  local rg_count=$(wc -l < "$ripgrep_secrets" 2>/dev/null || echo 0)
  [[ $rg_count -gt 0 ]] && log_ok "  Ripgrep: ${rg_count} coincidencias en JS"
  
  # ── TÉCNICA 4: TRUFFLEHOG (Sobre URLs descargadas + archivos JS) ────
  if command -v trufflehog &>/dev/null; then
    log_info "Técnica 4/4: TruffleHog en archivos descargados..."
    
    # Crear directorio temporal con archivos de entrada
    local th_scan_dir="${SECRETS_DIR}/.trufflehog_scan"
    mkdir -p "$th_scan_dir"
    
    # Copiar outputs del recon como "archivos" para TruffleHog
    [[ -s "$api_urls" ]] && cp "$api_urls" "${th_scan_dir}/api_urls.txt"
    [[ -s "$gf_secrets" ]] && cp "$gf_secrets" "${th_scan_dir}/gf_output.txt"
    [[ -s "$httpx_secrets" ]] && cp "$httpx_secrets" "${th_scan_dir}/http_responses.txt"
    [[ -s "$ripgrep_secrets" ]] && cp "$ripgrep_secrets" "${th_scan_dir}/js_patterns.txt"
    
    # Ejecutar TruffleHog
    timeout 5m trufflehog filesystem "$th_scan_dir" \
      --json --no-update 2>/dev/null > "$trufflehog_out" || true
    
    rm -rf "$th_scan_dir"
    
    local th_count=$(grep -c '"DetectorName"' "$trufflehog_out" 2>/dev/null || echo 0)
    [[ $th_count -gt 0 ]] && log_ok "  TruffleHog: ${th_count} secretos detectados"
  else
    log_skip "trufflehog"
    > "$trufflehog_out"
  fi
  
  # ── CONSOLIDACIÓN: Merge + Filtrado Avanzado ─────────────────────
  log_info "Consolidando resultados (filtrado de falsos positivos)..."
  
  > "$potential"
  
  # Merge de todas las técnicas
  cat "$gf_secrets" "$httpx_secrets" "$ripgrep_secrets" 2>/dev/null | \
    sort -u >> "$potential" || true
  
  # Agregar hallazgos de TruffleHog (si existen)
  if [[ -s "$trufflehog_out" ]]; then
    while IFS= read -r line; do
      echo "$line" | jq -r '.Raw // empty' 2>/dev/null
    done < "$trufflehog_out" >> "$potential"
  fi
  
  # ── FILTRO AVANZADO DE FALSOS POSITIVOS ───────────────────────────
  local fp_file="${SECRETS_DIR}/.fp_patterns"
  cat > "$fp_file" <<'FPEOF'
# Falsos positivos comunes a eliminar
(?i)^(example|test|placeholder|changeme|yourapikey|your_key|INSERT_KEY|YOUR_TOKEN|REPLACE_ME)
(?i)^(xxxx|1234567890|000000|aaaaaa|dummy|sample|foobar|lorem|ipsum|donottrust)
(?i)^(user|password|admin|root|test123|password123|12345|qwerty)
(?i)^(https?://(example|test|localhost|127\.0\.0\.1|192\.168|10\.0|172\.16))
(?i)(librer|framework|analytics|cdn|static|jquery|react|bootstrap|angular|vue)
^$
^\s+$
FPEOF
  
  # Filtrar falsos positivos con ripgrep (si disponible)
  if command -v rg &>/dev/null; then
    rg -v -f "$fp_file" "$potential" > "${potential}.clean" 2>/dev/null || cp "$potential" "${potential}.clean"
  else
    grep -vEif <(sed 's/^[[:space:]]*//; s/[[:space:]]*$//' "$fp_file" | grep -v '^#' | grep -v '^$') "$potential" > "${potential}.clean" 2>/dev/null || cp "$potential" "${potential}.clean"
  fi
  
  mv "${potential}.clean" "$potential"
  
  # Separar FP confirmados
  if [[ -s "$potential" ]]; then
    if command -v rg &>/dev/null; then
      rg -f "$fp_file" "$potential" > "$false_pos" 2>/dev/null || true
    else
      grep -Eif <(sed 's/^[[:space:]]*//; s/[[:space:]]*$//' "$fp_file" | grep -v '^#' | grep -v '^$') "$potential" > "$false_pos" 2>/dev/null || true
    fi
  fi
  
  rm -f "$fp_file"
  
  # ── RANKING Y REPORTE FINAL ──────────────────────────────────────
  local total_raw total_fp total_clean
  total_raw=$(wc -l < "$potential" 2>/dev/null || echo 0)
  total_fp=$(wc -l < "$false_pos" 2>/dev/null || echo 0)
  total_clean=$(( total_raw - total_fp ))
  
  # Generar summary visual
  cat > "$final_report" <<EOF
╔════════════════════════════════════════════════════════════════╗
║           SECRET DISCOVERY — RESUMEN DE HALLAZGOS              ║
╚════════════════════════════════════════════════════════════════╝

 TÉCNICAS UTILIZADAS:
   ✓ GF Patterns          (URLs con patterns sospechosos)
   ✓ HTTP Responses       (Headers + Body de respuestas)
   ✓ Ripgrep en JS        (Patrones en archivos JavaScript)
   ✓ TruffleHog           (Detectores de entropía)

 ESTADÍSTICAS:
   Total valores extraídos:    ${total_raw}
   Falsos positivos filtrados: ${total_fp}
   Secretos potenciales:       ${total_clean}

 ARCHIVOS GENERADOS:
   → ${potential}              (Secretos potenciales)
   → ${false_pos}              (Falsos positivos)
   → ${gf_secrets}             (GF Patterns)
   → ${httpx_secrets}          (HTTP Headers/Body)
   → ${ripgrep_secrets}        (JS Patterns)
   → ${trufflehog_out}         (TruffleHog JSON)

  PRÓXIMOS PASOS:
   1. Revisar: cat ${potential} | head -20
   2. Validar credenciales encontradas
   3. Reportar secretos expuestos responsablemente
EOF

  log_ok "Secret Discovery completado"
  log_ok "═══════════════════════════════════════════════════════"
  cat "$final_report"
  log_ok "═══════════════════════════════════════════════════════"
}

# ──────────────────────────────────────────────
# M9 — CONTENT DISCOVERY (Smart Fuzzing Local)
# Respeta --skip-fuzz
# ──────────────────────────────────────────────
run_fuzzing() {
  log_section "M9 — Content Discovery (ffuf / feroxbuster)"

  if [[ "${SKIP_FUZZ:-false}" == "true" ]]; then
    log_info "--skip-fuzz activado. Saltando módulo."
    return
  fi

  local fuzz_targets="${FUZZING_DIR}/fuzz_targets.txt"
  
  # 1. Construir lista de hosts a fuzzear: SOLO los más prometedores (Max 15)
  cat "${HTTPX_DIR}/httpx_interesting_tech.txt" \
      "${HTTPX_DIR}/httpx_login_panels.txt" \
      "${HTTPX_DIR}/httpx_api_hosts.txt" \
      "${HTTPX_DIR}/httpx_errors.txt" 2>/dev/null | sort -u | head -15 > "$fuzz_targets"

  local fuzz_count
  fuzz_count=$(wc -l < "$fuzz_targets" 2>/dev/null || echo 0)

  if [[ $fuzz_count -eq 0 ]]; then
    log_warn "Sin hosts prioritarios. Usando top 5 activos..."
    grep -oP 'https?://[^\s\[\]]+' "${HTTPX_DIR}/httpx_output.txt" 2>/dev/null | \
      head -5 > "$fuzz_targets" || true
    fuzz_count=$(wc -l < "$fuzz_targets" 2>/dev/null || echo 0)
  fi

  [[ $fuzz_count -eq 0 ]] && return

  # 2. Selección de Wordlist
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
  log_info "Wordlist: $(basename "$wl") | targets=${fuzz_count} | threads=${FFUF_THREADS}"

  # 3. Sub-función blindada para Fuzzing
  _fuzz_host() {
    local host="$1"
    local wordlist="$2"
    local safe_name
    safe_name=$(echo "$host" | sed 's|https\?://||;s|/.*||;s|[^a-zA-Z0-9._-]|_|g')

    if command -v ffuf &>/dev/null; then
      local ffuf_out="${FUZZING_DIR}/ffuf_${safe_name}.json"
      # -ac: Auto-calibración (Ignora catch-alls)
      # -sa: Stop on errors (Si el WAF bloquea, aborta)
      # timeout 15m: El seguro anti-zombis global
      timeout 15m ffuf \
        -w "$wordlist" -u "${host}/FUZZ" \
        -mc 200,204,301,302,307,401,403,405,500 \
        -t "$FFUF_THREADS" -rate "$FFUF_RATE" \
        -ac -sa -timeout 10 -silent \
        -o "$ffuf_out" -of json 2>/dev/null || true

    elif command -v feroxbuster &>/dev/null; then
      local ferox_out="${FUZZING_DIR}/feroxbuster_${safe_name}.txt"
      # --auto-tune y --auto-bail hacen lo mismo que -ac y -sa en ffuf
      timeout 15m feroxbuster \
        --url "$host" --wordlist "$wordlist" \
        --status-codes 200,204,301,302,307,401,403,405,500 \
        --threads "$FFUF_THREADS" --rate-limit "$FFUF_RATE" \
        --auto-tune --auto-bail --no-recursion --silent \
        --output "$ferox_out" 2>/dev/null || true
    fi
  }
  
  # Exportar variables necesarias para sub-procesos de parallel
  export -f _fuzz_host
  export FFUF_THREADS FFUF_RATE FUZZING_DIR

  # 4. Ejecución Paralela Controlada (Max 2 hosts al mismo tiempo para no ahogar la red local)
  if command -v parallel &>/dev/null; then
    parallel --bar -j 2 _fuzz_host {} "$wl" :::: "$fuzz_targets" 2>/dev/null || true
  else
    while IFS= read -r host; do
      [[ -z "$host" ]] && continue
      _fuzz_host "$host" "$wl"
    done < "$fuzz_targets"
  fi

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

  filter_file "${SUBFINDER_DIR}/subfinder_output.txt"
  filter_file "${HTTPX_DIR}/httpx_output.txt"
  filter_file "${WAYBACK_DIR}/wayback_output.txt"
  filter_file "${KATANA_DIR}/katana_output.txt"
  filter_file "${SCORING_DIR}/high_priority.txt"
  filter_file "${SCORING_DIR}/idor_candidates.txt"
  filter_file "${SCORING_DIR}/api_endpoints.txt"

  log_ok "Filtro OOS completado"
}

# ──────────────────────────────────────────────
# M11 — NUCLEI (ULTRA-OPTIMIZADO: Smart Filtering + Fast Execution)
# ──────────────────────────────────────────────
run_nuclei() {
    log_section "M11 — Nuclei (Smart-Filtered, Ultra-Rápido)"
    
    local high_priority="${SCORING_DIR}/high_priority.txt"
    local api_endpoints="${SCORING_DIR}/api_endpoints.txt"
    local httpx_json="${HTTPX_DIR}/httpx_output.json"
    local nuclei_input="${NUCLEI_DIR}/nuclei_input.txt"
    local nuclei_analysis="${NUCLEI_DIR}/nuclei_tech_analysis.json"
    local output="${NUCLEI_DIR}/nuclei_output.txt"
    local output_json="${NUCLEI_DIR}/nuclei_output.json"
    local template_map="${NUCLEI_DIR}/.template_mapping.txt"

    [[ ! -s "$high_priority" ]] && { log_warn "Sin high priority endpoints."; return; }

    # ── FASE 1: Análisis Inteligente de Tecnologías ────────────────────
    log_info "Analizando tecnologías y patrones (PHASE 1/3)..."
    
    python3 - <<PYEOF
import json
from pathlib import Path
from collections import defaultdict

httpx_json = "${httpx_json}"
nuclei_analysis = "${nuclei_analysis}"
high_priority = "${high_priority}"

# Mapeo tech → templates de nuclei más efectivos
tech_to_templates = {
    "wordpress":     ["wordpress-version-detection", "wordpress-user-enumeration", "wordpress-rce"],
    "drupal":        ["drupal-version-detection", "drupal-rce", "drupal-cve"],
    "joomla":        ["joomla-version-detection", "joomla-rce"],
    "php":           ["php-info-disclosure", "php-rce", "php-object-injection"],
    "asp.net":       ["aspx-rce", "asp-net-cve", "aspx-info-disclosure"],
    "nodejs":        ["node-rce", "express-cve", "nodejs-path-traversal"],
    "java":          ["java-rce", "spring-cve", "spring-actuator"],
    "python":        ["python-rce", "django-cve", "flask-debug"],
    "nginx":         ["nginx-version", "nginx-cve", "nginx-path-traversal"],
    "apache":        ["apache-version", "apache-cve", "apache-modules"],
    "jenkins":       ["jenkins-rce", "jenkins-cve", "jenkins-api-access"],
    "jira":          ["jira-cve", "jira-auth-bypass", "jira-rce"],
    "grafana":       ["grafana-cve", "grafana-auth-bypass", "grafana-rce"],
    "docker":        ["docker-api", "docker-rce", "docker-registry"],
    "kubernetes":    ["k8s-api", "k8s-rbac"],
    "graphql":       ["graphql-introspection", "graphql-injection", "graphql-auth-bypass"],
    "swagger":       ["swagger-exposure", "api-key-exposure"],
    "elasticsearch": ["elasticsearch-rce", "elasticsearch-injection"],
    "mongodb":       ["mongodb-injection", "mongodb-auth-bypass"],
    "redis":         ["redis-rce", "redis-injection"],
}

# Patrones simples para detectar tech por respuesta
tech_patterns = {
    "wordpress":  ["wp-content", "wp-json", "/wp-admin/", "WordPress"],
    "drupal":     ["/sites/default/", "drupal", "/admin/", "Drupal"],
    "joomla":     ["/components/", "/modules/", "Joomla"],
    "php":        [".php", "PHP/"],
    "asp.net":    [".aspx", ".asp", "ASP.NET"],
    "nodejs":     ["Express", "Node", "npm"],
    "java":       ["Spring", "Tomcat", "JAVA"],
    "nginx":      ["nginx"],
    "apache":     ["Apache"],
    "jenkins":    ["Jenkins"],
    "jira":       ["Jira"],
    "grafana":    ["Grafana"],
    "docker":     ["docker"],
    "graphql":    ["/graphql"],
    "swagger":    ["/swagger", "/api-docs"],
    "elasticsearch": ["elasticsearch"],
}

analysis = {
    "technologies": defaultdict(lambda: {"count": 0, "urls": [], "templates": []}),
    "url_count": 0,
    "high_risk_patterns": [],
}

# Parse httpx JSON + correlacionar con high_priority
try:
    high_priority_urls = set()
    if Path(high_priority).exists():
        high_priority_urls = set(Path(high_priority).read_text().splitlines())
    
    with open(httpx_json) as f:
        for line in f:
            if not line.strip(): continue
            try:
                entry = json.loads(line)
                url = entry.get("url", "")
                
                # Solo procesar URLs en high priority
                if url not in high_priority_urls: continue
                
                analysis["url_count"] += 1
                body = (entry.get("body") or "").lower()
                headers = json.dumps(entry.get("headers", {})).lower()
                tech_detect = (entry.get("technologies") or [])
                
                # Detectar tech por body/headers
                detected_tech = set()
                for tech, patterns in tech_patterns.items():
                    if any(p.lower() in body or p.lower() in headers for p in patterns):
                        detected_tech.add(tech)
                
                # Agregar tech detectadas por httpx
                for t in tech_detect:
                    t_lower = str(t).lower()
                    if any(tech in t_lower for tech in tech_patterns.keys()):
                        for tech in tech_patterns.keys():
                            if tech in t_lower:
                                detected_tech.add(tech)
                
                # Registrar análisis
                for tech in detected_tech:
                    analysis["technologies"][tech]["count"] += 1
                    analysis["technologies"][tech]["urls"].append(url)
                    if tech in tech_to_templates:
                        analysis["technologies"][tech]["templates"] = tech_to_templates[tech]
                
                # Pattern de alto riesgo: paths sospechosos
                if any(p in url for p in ["/admin", "/internal", "/.env", "/.git", "/config"]):
                    analysis["high_risk_patterns"].append(url)
                    
            except: continue
except Exception as e:
    print(f"[!] Parse error: {e}")

# Guardar análisis
Path(nuclei_analysis).write_text(json.dumps(analysis, indent=2, default=str))
print(f"[✓] Análisis: {analysis['url_count']} URLs | {len(analysis['technologies'])} techs detectadas")
for tech, info in sorted(analysis["technologies"].items(), key=lambda x: -x[1]["count"]):
    print(f"    {tech}: {info['count']} hosts → {len(info['templates'])} templates")
PYEOF

    # ── FASE 2: Construcción Smart del Input ────────────────────────────
    log_info "Construyendo input inteligente (PHASE 2/3)..."
    
    > "$nuclei_input"
    > "$template_map"
    
    python3 - <<PYEOF
import json
from pathlib import Path

nuclei_analysis = "${nuclei_analysis}"
nuclei_input = "${nuclei_input}"
template_map = "${template_map}"
api_endpoints = "${api_endpoints}"
high_priority = "${high_priority}"

# ESTRATEGIA DE SELECCIÓN:
# 1. URLs de alto riesgo (SIEMPRE): admin, .env, .git
# 2. URLs con tech detectada: máx 20 por tech
# 3. APIs: seleccionar solo las con parámetros (potential vulns)
# 4. Limitar total a 50-100 URLs según modo

analysis = json.loads(Path(nuclei_analysis).read_text())
selected_urls = set()
template_selections = {}

# Paso 1: Agregar URLs de alto riesgo
for url in analysis.get("high_risk_patterns", [])[:10]:
    selected_urls.add(url)

# Paso 2: Seleccionar por tech detectada (inteligente)
for tech, info in analysis["technologies"].items():
    if not info["templates"]: continue
    
    # Priorizar: primeras URLs con más parámetros/params
    urls_with_params = sorted(
        info["urls"],
        key=lambda u: u.count("?") + u.count("&"),
        reverse=True
    )[:15]  # Max 15 por tech
    
    for url in urls_with_params:
        selected_urls.add(url)
        template_selections[url] = info["templates"][:3]  # Max 3 templates por URL

# Paso 3: Agregar APIs con parámetros (interesantes)
if Path(api_endpoints).exists():
    api_urls = Path(api_endpoints).read_text().splitlines()
    api_with_params = [u for u in api_urls if "?" in u or "&" in u][:10]
    for url in api_with_params:
        selected_urls.add(url)
        template_selections[url] = ["api-key-exposure", "graphql-introspection", "swagger-exposure"]

# Paso 4: Limitar total
mode = "${RECON_MODE}"
max_urls = {"stealth": 20, "aggressive": 100, "normal": 50}.get(mode, 50)

selected_urls = sorted(selected_urls)[:max_urls]

# Escribir input (FIX: No escribir si vacío)
if selected_urls:
    with open(nuclei_input, "w") as f:
        for url in selected_urls:
            f.write(url + "\n")
    
    # Escribir mapeo de templates
    with open(template_map, "w") as f:
        for url in selected_urls:
            templates = template_selections.get(url, ["default-login", "exposure", "misconfig"])
            f.write(f"{url}\t{','.join(templates)}\n")
    print(f"[✓] Input: {len(selected_urls)} URLs seleccionadas inteligentemente")
else:
    # Crear archivos vacíos correctamente (sin \n solitario)
    Path(nuclei_input).write_text("")
    Path(template_map).write_text("")
    print(f"[!] Sin URLs seleccionadas para nuclei")
PYEOF

    local selected_count=$(wc -l < "$nuclei_input" 2>/dev/null || echo 0)
    [[ $selected_count -eq 0 ]] && { log_warn "Sin URLs para nuclei."; return; }
    log_ok "URLs seleccionadas: ${selected_count} (inteligente, no brute-force)"

    # ── FASE 3: Nuclei Execution (ULTRA-OPTIMIZADO) ─────────────────────
    log_info "Ejecutando nuclei (PHASE 3/3, timeout adaptativo)..."

    local nuclei_timeout
    case "${RECON_MODE}" in
        stealth)    nuclei_timeout=300; NUCLEI_THREADS=3; NUCLEI_RATE=5 ;;
        aggressive) nuclei_timeout=1800; NUCLEI_THREADS=50; NUCLEI_RATE=500 ;;
        *)          nuclei_timeout=600; NUCLEI_THREADS=10; NUCLEI_RATE=100 ;; # normal
    esac

    # TRICK: Usar -template-list si está disponible (más rápido que -tags)
    local nuclei_flags=(
        "-list" "$nuclei_input"
        "-c" "$NUCLEI_THREADS"
        "-rate-limit" "$NUCLEI_RATE"
        "-timeout" "5"
        "-retries" "0"
        "-no-httpx"
        "-severity" "medium,high,critical"
        "-bulk-size" "10"
        "-silent"
        "-o" "$output"
        "-json-export" "$output_json"
        "-stats" # Mostrar estadísticas al final
    )

    # Ejecutar con timeout global + fallback robusto
    timeout "${nuclei_timeout}" nuclei "${nuclei_flags[@]}" 2>/dev/null || {
        log_warn "Nuclei timeout (${nuclei_timeout}s). Recopilando resultados parciales..."
    }

    # ── POST-PROCESAMIENTO: Análisis de Resultados ──────────────────────
    if [[ -s "$output_json" ]]; then
        log_info "Post-procesando findings de nuclei..."
        
        python3 - <<PYEOF
import json, sys
from pathlib import Path
from collections import defaultdict

output_json = "${output_json}"
output_txt = "${output}"

# Contar por severidad y deduplicar
findings = defaultdict(lambda: {"urls": set(), "count": 0})

try:
    with open(output_json) as f:
        for line in f:
            if not line.strip(): continue
            finding = json.loads(line)
            sev = finding.get("info", {}).get("severity", "info").lower()
            findings[sev]["count"] += 1
            findings[sev]["urls"].add(finding.get("matched-at", ""))
except Exception as e:
    print(f"[!] Error: {e}", file=sys.stderr)

# Output limpio + estadísticas
if Path(output_txt).exists():
    lines = Path(output_txt).read_text().splitlines()
    print(f"[✓] Nuclei: {len(lines)} findings totales")
    for sev in ["critical", "high", "medium", "low"]:
        if findings[sev]["count"] > 0:
            print(f"    [{sev.upper()}]: {findings[sev]['count']}")
PYEOF
    fi

    log_ok "Nuclei completado (smart-filtered, optimizado)"
}

# ──────────────────────────────────────────────
# M13 — IP DISCOVERY & SMART PORT SCANNING (REDESIGNED)
# ──────────────────────────────────────────────
run_ip_discovery() {
    log_section "M13 — IP Discovery & Smart Port Scanning (REDESIGNED)"
    
    local httpx_json="${HTTPX_DIR}/httpx_output.json"
    local ip_dir="${IP_DISCOVER_DIR}"
    local analysis="${ip_dir}/ip_analysis.json"
    local direct_ips="${ip_dir}/direct_ips.txt"
    local naabu_output="${ip_dir}/naabu_output.txt"
    local nmap_targets="${ip_dir}/nmap_targets.txt"
    local nmap_output="${ip_dir}/nmap_services.txt"
    local service_map="${ip_dir}/service_technology_mapping.tsv"
    local report="${ip_dir}/ip_discovery_report.txt"

    [[ ! -s "$httpx_json" ]] && { log_warn "httpx JSON vacío."; return; }

    # ── FASE 1: Extracción y Filtrado CDN/WAF ──────────────────────────
    log_info "Analizando IPs y filtrando CDN/WAF (PHASE 1/3)..."
    
    python3 - <<PYEOF
import json
from pathlib import Path
from collections import defaultdict

httpx_json = "${httpx_json}"
analysis_file = "${analysis}"
direct_ips_file = "${direct_ips}"

# FINGERPRINTS CDN/WAF: Si detecta esto, la IP NO se escanea
cdn_waf_signatures = {
    "cloudflare": ["1.1.1.", "104.16.", "104.17.", "104.18.", "104.19.", "104.20."],
    "akamai": ["23.3.", "23.4.", "23.5.", "95.100.", "95.101."],
    "cloudfront": ["54.", "52.", "13.", "35.", "76."],
    "fastly": ["151.101.", "23.235."],
    "azure": ["13.64.", "13.65.", "13.104.", "13.107.", "40."],
    "imperva": ["199.83.", "198.143.", "198.51.", "202.123."],
    "sucuri": ["192.88.", "185.215."],
}

analysis = {
    "total_ips": 0,
    "cdn_waf_ips": [],
    "direct_ips": [],
    "ip_to_hosts": defaultdict(list),
    "ip_to_tech": defaultdict(list),
    "cdn_waf_count": 0,
}

direct_ips_set = set()

try:
    with open(httpx_json) as f:
        for line in f:
            if not line.strip(): continue
            entry = json.loads(line)
            
            ip = entry.get("host_ip", "N/A")
            url = entry.get("url", "")
            host = url.split("//")[1].split("/")[0] if "://" in url else ""
            tech = entry.get("technologies", []) or []
            
            if ip == "N/A" or not ip: continue
            
            analysis["total_ips"] += 1
            analysis["ip_to_hosts"][ip].append(host)
            analysis["ip_to_tech"][ip].extend([t.lower() for t in tech])
            
            # Detectar si IP está detrás de CDN/WAF
            is_cdn = False
            for cdn_name, ip_ranges in cdn_waf_signatures.items():
                if any(ip.startswith(r) for r in ip_ranges):
                    is_cdn = True
                    analysis["cdn_waf_ips"].append({
                        "ip": ip,
                        "provider": cdn_name,
                        "hosts": [host]
                    })
                    analysis["cdn_waf_count"] += 1
                    break
            
            # Si NO está detrás de CDN/WAF, es directo
            if not is_cdn:
                direct_ips_set.add(ip)
                analysis["direct_ips"].append(ip)
                
except Exception as e:
    print(f"[!] Parse error: {e}")

# Dedup directas
analysis["direct_ips"] = sorted(list(set(analysis["direct_ips"])))
direct_ips_set = set(analysis["direct_ips"])

# Guardar análisis
Path(analysis_file).write_text(json.dumps(analysis, indent=2, default=str))

# FIX 3b: Escribir IPs directas (evitar archivo de 1 byte con solo '\n')
direct_ips_text = '\n'.join(sorted(direct_ips_set)) + '\n' if direct_ips_set else ''
Path(direct_ips_file).write_text(direct_ips_text)

print(f"[✓] Análisis completado:")
print(f"    Total IPs: {analysis['total_ips']}")
print(f"    Detrás CDN/WAF: {analysis['cdn_waf_count']}")
print(f"    IPs Directas (escaneables): {len(direct_ips_set)}")
PYEOF

    local direct_count=$(wc -l < "$direct_ips" 2>/dev/null || echo 0)
    
    if [[ $direct_count -eq 0 ]]; then
        log_warn "Sin IPs directas (todas detrás de CDN/WAF). IP Discovery abortado."
        _generate_ip_report "skip"
        return
    fi

    log_ok "IPs directas disponibles: ${direct_count}"

    # ── FASE 2: Naabu Port Scanning (ADAPTATIVO) ────────────────────────
    log_info "Escaneando puertos con naabu (PHASE 2/3)..."
    
    if ! command -v naabu &>/dev/null; then
        log_skip "naabu"
        > "$naabu_output"
    else
        # Rate limiter adaptativo: evitar abrumar la red
        local naabu_rate naabu_timeout
        case "${RECON_MODE}" in
            stealth)    naabu_rate=100; naabu_timeout=300 ;;
            aggressive) naabu_rate=1000; naabu_timeout=600 ;;
            *)          naabu_rate=300; naabu_timeout=450 ;; # normal
        esac

        # TRUCO: Solo top 1000 puertos en stealth, 5000 en normal, full en aggressive
        local port_range
        case "${RECON_MODE}" in
            stealth)    port_range="1-1000" ;;
            aggressive) port_range="1-65535" ;;
            *)          port_range="1-5000" ;; # normal
        esac

        # Naabu con fallbacks robusto
        timeout "${naabu_timeout}" naabu \
            -l "$direct_ips" \
            -p "$port_range" \
            -rate "$naabu_rate" \
            -timeout 1000 \
            -retries 0 \
            -verify \
            -silent \
            -o "$naabu_output" \
            2>/dev/null || {
                log_warn "Naabu timeout. Resultados parciales guardados."
                [[ ! -f "$naabu_output" ]] && touch "$naabu_output"
            }
    fi

    local ports_found=$(wc -l < "$naabu_output" 2>/dev/null || echo 0)
    [[ $ports_found -eq 0 ]] && {
        log_warn "Sin puertos abiertos encontrados."
        _generate_ip_report "no_ports"
        return
    }
    log_ok "Puertos abiertos: ${ports_found}"

    # ── FASE 3: Nmap Service Detection (SOLO PUERTOS ABIERTOS) ─────────
    log_info "Detectando servicios con nmap (PHASE 3/3)..."
    
    if ! command -v nmap &>/dev/null; then
        log_skip "nmap"
    else
        # Extraer IPs y puertos únicos del output de naabu
        cut -d':' -f1 "$naabu_output" | sort -u > "$nmap_targets"
        local target_ips=$(wc -l < "$nmap_targets")

        # FIX CRÍTICO: Limitar puertos a 500 máximo para evitar ARG_MAX
        local ports_str
        ports_str=$(cut -d':' -f2 "$naabu_output" | \
            sort | uniq -c | sort -rn | head -500 | \
            awk '{print $2}' | tr '\n' ',' | sed 's/,$//')

        local total_ports=$(echo "$ports_str" | tr ',' '\n' | wc -l)
        log_info "Nmap: ${target_ips} IPs x ${total_ports} puertos (limitado a 500)"

        # Nmap ULTRA-OPTIMIZADO: Solo detección, rápido, output limpio
        local nmap_opts="-sV -sC --script=http-title,http-server-header --version-intensity 4 -T4"
        nmap_opts="${nmap_opts} --open --max-retries 1 --host-timeout 10s --min-rate 200"

        timeout 600 nmap \
            $nmap_opts \
            -iL "$nmap_targets" \
            -p "$ports_str" \
            -oN "$nmap_output" \
            2>/dev/null || {
                log_warn "Nmap timeout. Resultados parciales guardados."
                [[ ! -f "$nmap_output" ]] && touch "$nmap_output"
            }
    fi

    # ── POST-PROCESAMIENTO: Correlacionar con Tecnologías M4 ────────────
    log_info "Correlacionando con tecnologías de M4..."
    
    python3 - <<PYEOF
import json
import re
from pathlib import Path
from collections import defaultdict

analysis_file = "${analysis}"
naabu_output = "${naabu_output}"
nmap_output = "${nmap_output}"
service_map = "${service_map}"

# Cargar análisis previo
analysis = json.loads(Path(analysis_file).read_text())

# Mapeo manual: patrón nmap → tecnología probable
service_tech_map = {
    "Apache": "apache",
    "nginx": "nginx",
    "IIS": "asp.net",
    "Tomcat": "java",
    "Jetty": "java",
    "Node.js": "nodejs",
    "Express": "nodejs",
    "Gunicorn": "python",
    "uWSGI": "python",
    "Passenger": "ruby",
    "Puma": "ruby",
    "Unicorn": "ruby",
    "Kestrel": "dotnet",
    "Docker": "docker",
    "Kubernetes": "kubernetes",
    "Jenkins": "jenkins",
    "Jira": "jira",
    "Grafana": "grafana",
    "Elasticsearch": "elasticsearch",
    "MongoDB": "mongodb",
    "Redis": "redis",
    "MySQL": "mysql",
    "PostgreSQL": "postgresql",
    "MariaDB": "mysql",
    "Oracle": "oracle",
    "SSH": "ssh",
}

# Parsear nmap output y correlacionar
service_lines = []
if Path(nmap_output).exists():
    nmap_content = Path(nmap_output).read_text()
    
    # Simple regex para extraer info: IP, puerto, estado, servicio
    # Formato nmap -oN: "22/tcp  open  ssh        OpenSSH 7.4"
    port_pattern = re.compile(r'(\d+)/tcp\s+(open|closed|filtered)\s+(\S+)\s+(.*)')
    
    for line in nmap_content.splitlines():
        match = port_pattern.search(line)
        if match:
            port, state, service, version = match.groups()
            if state == "open":
                # Intentar mapear a tech conocida
                tech = "unknown"
                for sig, t in service_tech_map.items():
                    if sig.lower() in (service + " " + version).lower():
                        tech = t
                        break
                
                service_lines.append(f"{port}\t{service}\t{version}\t{tech}")

# FIX 3c: Escribir mapeo (evitar archivo de 1 byte con solo '\n')
if service_lines:
    with open(service_map, "w") as f:
        f.write("Port\tService\tVersion\tTechnology\n")
        for line in service_lines:
            f.write(line + "\n")
    print(f"[✓] Correlación: {len(service_lines)} servicios mapeados")
else:
    Path(service_map).write_text("")
    print(f"[!] Sin servicios detectados en nmap")
PYEOF

    # ── Generar Reporte Final IP Discovery ──────────────────────────────
    _generate_ip_report "complete"
    log_ok "IP Discovery & Port Scanning completado (optimizado, no bloqueante)"
}

# ──────────────────────────────────────────────
# M12 — REPORTE JSON (ACTUALIZADO PARA INCLUIR M11, M13)
# ──────────────────────────────────────────────
generate_report() {
  log_section "M12 — Generando Reporte Final (Integración M11, M13)"
  local report="${CONTENT_DIR}/recon_report.json"

  safe_wc() { [[ -f "$1" ]] && wc -l < "$1" || echo 0; }

  # Conteos estándar
  local c_subdomains c_resolved c_active_hosts
  local c_wayback c_wayback_interesting
  local c_katana c_katana_interesting
  local c_high c_medium c_low c_idor c_api c_js c_new c_legacy
  local c_nuclei c_secrets
  local c_direct_ips c_ports_found c_services c_cdn_waf

  c_subdomains=$(safe_wc "${SUBFINDER_DIR}/subfinder_output.txt")
  c_resolved=$(safe_wc "${DNSX_DIR}/dnsx_resolved.txt")
  c_active_hosts=$(safe_wc "${HTTPX_DIR}/httpx_output.txt")
  c_wayback=$(safe_wc "${WAYBACK_DIR}/wayback_output.txt")
  c_wayback_interesting=$(safe_wc "${WAYBACK_DIR}/wayback_interesting.txt")
  c_katana=$(safe_wc "${KATANA_DIR}/katana_output.txt")
  c_katana_interesting=$(safe_wc "${KATANA_DIR}/katana_interesting.txt")
  c_high=$(safe_wc "${SCORING_DIR}/high_priority.txt")
  c_medium=$(safe_wc "${SCORING_DIR}/medium_priority.txt")
  c_low=$(safe_wc "${SCORING_DIR}/low_priority.txt")
  c_idor=$(safe_wc "${SCORING_DIR}/idor_candidates.txt")
  c_api=$(safe_wc "${SCORING_DIR}/api_endpoints.txt")
  c_js=$(safe_wc "${SCORING_DIR}/js_files.txt")
  c_new=$(safe_wc "${SCORING_DIR}/new_endpoints.txt")
  c_legacy=$(safe_wc "${SCORING_DIR}/legacy_endpoints.txt")
  c_nuclei=$(safe_wc "${NUCLEI_DIR}/nuclei_output.txt")
  c_secrets=$(safe_wc "${SECRETS_DIR}/potential_secrets.txt")
  
  # NUEVOS: M13 - IP Discovery
  local ip_analysis="${IP_DISCOVER_DIR}/ip_analysis.json"
  if [[ -f "$ip_analysis" ]]; then
    c_direct_ips=$(python3 -c "import json; d=json.load(open('$ip_analysis')); print(len(d.get('direct_ips', [])))" 2>/dev/null || echo 0)
    c_cdn_waf=$(python3 -c "import json; d=json.load(open('$ip_analysis')); print(d.get('cdn_waf_count', 0))" 2>/dev/null || echo 0)
  else
    c_direct_ips=0
    c_cdn_waf=0
  fi
  c_ports_found=$(safe_wc "${IP_DISCOVER_DIR}/naabu_output.txt")
  c_services=$(safe_wc "${IP_DISCOVER_DIR}/nmap_services.txt")

  # Targets + OOS (FIX: Usar jq para escapar caracteres)
  local targets_json outscope_json="[]" outscope_applied="false"
  
  # Construir targets JSON de forma segura
  if [[ -f "$TARGETS_FILE" ]]; then
    targets_json=$(jq -R . "$TARGETS_FILE" | jq -s . 2>/dev/null || echo "[]")
  else
    targets_json="[]"
  fi
  
  if [[ -f "${CONTENT_DIR}/out_scope.txt" ]]; then
    outscope_applied="true"
    outscope_json=$(jq -R . "${CONTENT_DIR}/out_scope.txt" | jq -s . 2>/dev/null || echo "[]")
  fi

  # Muestras (máx 20 cada una)
  local s_high;   s_high=$(to_json_array   "${SCORING_DIR}/high_priority.txt" 20)
  local s_idor;   s_idor=$(to_json_array   "${SCORING_DIR}/idor_candidates.txt" 20)
  local s_api;    s_api=$(to_json_array    "${SCORING_DIR}/api_endpoints.txt" 20)
  local s_new;    s_new=$(to_json_array    "${SCORING_DIR}/new_endpoints.txt" 20)
  local s_nuclei; s_nuclei=$(to_json_array "${NUCLEI_DIR}/nuclei_output.txt" 20)
  local s_hosts;  s_hosts=$(to_json_array  "${HTTPX_DIR}/httpx_output.txt" 20)

  cat > "$report" <<EOFREPORT
{
  "metadata": {
    "project": "${PROJECT_NAME}",
    "date": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "recon_mode": "${RECON_MODE}",
    "waf_detected": "${WAF_DETECTED:-unknown}",
    "tool_version": "ITZKOATL v3.0"
  },
  "scope": {
    "targets": ${targets_json},
    "out_of_scope_applied": ${outscope_applied},
    "out_of_scope": ${outscope_json}
  },
  "summary": {
    "reconnaissance": {
      "subdomains_enumerated":     ${c_subdomains},
      "subdomains_dns_resolved":   ${c_resolved},
      "active_hosts":              ${c_active_hosts}
    },
    "url_discovery": {
      "wayback_total":             ${c_wayback},
      "wayback_interesting":       ${c_wayback_interesting},
      "katana_endpoints":          ${c_katana},
      "katana_interesting":        ${c_katana_interesting}
    },
    "attack_surface_scoring": {
      "high_priority":             ${c_high},
      "medium_priority":           ${c_medium},
      "low_priority":              ${c_low},
      "idor_candidates":           ${c_idor},
      "api_endpoints":             ${c_api},
      "js_files":                  ${c_js},
      "new_endpoints":             ${c_new},
      "legacy_endpoints":          ${c_legacy}
    },
    "vulnerability_scanning": {
      "nuclei_findings":           ${c_nuclei},
      "potential_secrets":         ${c_secrets}
    },
    "infrastructure": {
      "total_ips":                 ${c_direct_ips},
      "ips_behind_cdn_waf":        ${c_cdn_waf},
      "direct_ips_scanned":        ${c_direct_ips},
      "ports_open":                ${c_ports_found},
      "services_detected":         ${c_services}
    }
  },
  "samples": {
    "_note": "Primeras 20 entradas. Ver archivos completos en /files",
    "active_hosts":       ${s_hosts},
    "high_priority":      ${s_high},
    "idor_candidates":    ${s_idor},
    "api_endpoints":      ${s_api},
    "new_endpoints":      ${s_new},
    "nuclei_findings":    ${s_nuclei}
  },
  "files": {
    "reconnaissance": {
      "targets":                "${TARGETS_FILE}",
      "out_scope":              "${CONTENT_DIR}/out_scope.txt",
      "subfinder_output":       "${SUBFINDER_DIR}/subfinder_output.txt",
      "dnsx_resolved":          "${DNSX_DIR}/dnsx_resolved.txt"
    },
    "url_discovery": {
      "wayback_output":         "${WAYBACK_DIR}/wayback_output.txt",
      "wayback_interesting":    "${WAYBACK_DIR}/wayback_interesting.txt",
      "katana_output":          "${KATANA_DIR}/katana_output.txt",
      "katana_interesting":     "${KATANA_DIR}/katana_interesting.txt"
    },
    "attack_surface": {
      "all_urls":               "${SCORING_DIR}/all_urls.txt",
      "scored_tsv":             "${SCORING_DIR}/scored_urls.tsv",
      "high_priority":          "${SCORING_DIR}/high_priority.txt",
      "medium_priority":        "${SCORING_DIR}/medium_priority.txt",
      "idor_candidates":        "${SCORING_DIR}/idor_candidates.txt",
      "api_endpoints":          "${SCORING_DIR}/api_endpoints.txt",
      "js_files":               "${SCORING_DIR}/js_files.txt"
    },
    "vulnerability_scanning": {
      "nuclei_input":           "${NUCLEI_DIR}/nuclei_input.txt",
      "nuclei_output":          "${NUCLEI_DIR}/nuclei_output.txt",
      "nuclei_json":            "${NUCLEI_DIR}/nuclei_output.json",
      "nuclei_analysis":        "${NUCLEI_DIR}/nuclei_tech_analysis.json",
      "potential_secrets":      "${SECRETS_DIR}/potential_secrets.txt"
    },
    "infrastructure": {
      "ip_analysis":            "${IP_DISCOVER_DIR}/ip_analysis.json",
      "direct_ips":             "${IP_DISCOVER_DIR}/direct_ips.txt",
      "naabu_output":           "${IP_DISCOVER_DIR}/naabu_output.txt",
      "nmap_services":          "${IP_DISCOVER_DIR}/nmap_services.txt",
      "service_mapping":        "${IP_DISCOVER_DIR}/service_technology_mapping.tsv",
      "ip_report":              "${IP_DISCOVER_DIR}/ip_discovery_report.txt"
    }
  },
  "recommendations": {
    "priority_1": "Revisar high_priority.txt para endpoints críticos",
    "priority_2": "Correlacionar IDOR candidates con BOLA (M7 + M11 findings)",
    "priority_3": "Validar secretos encontrados en M8 (potential_secrets.txt)",
    "priority_4": "Analizar servicios en IPs directas (nmap_services.txt)",
    "priority_5": "Fusionar resultados nuclei con puntuación de M7 para priorización"
  }
}
EOFREPORT

  if command -v jq &>/dev/null; then
    jq . "$report" > "${report}.tmp" 2>/dev/null && mv "${report}.tmp" "$report" || {
      log_warn "JSON validation failed. Reporte puede contener caracteres especiales no escapados."
    }
  fi

  log_ok "Reporte final generado → ${report}"
  log_ok "═══════════════════════════════════════════════════════════════"
  echo ""
  echo -e "${BOLD}PRÓXIMOS PASOS POR PRIORIDAD:${RESET}"
  echo ""
  echo -e "  ${BRIGHT_RED}[P1]${RESET} High Priority Endpoints (Máxima criticidad):"
  echo -e "      ${CYAN}cat${RESET} ${SCORING_DIR}/high_priority.txt | head -10"
  echo ""
  echo -e "  ${BRIGHT_RED}[P2]${RESET} IDOR Candidates (Lógica de negocio):"
  echo -e "      ${CYAN}cat${RESET} ${SCORING_DIR}/idor_candidates.txt | head -10"
  echo ""
  echo -e "  ${YELLOW}[P3]${RESET} API Endpoints & Secrets:"
  echo -e "      ${CYAN}cat${RESET} ${SCORING_DIR}/api_endpoints.txt | head -5"
  echo -e "      ${CYAN}cat${RESET} ${SECRETS_DIR}/potential_secrets.txt | head -5"
  echo ""
  echo -e "  ${YELLOW}[P4]${RESET} Findings de Nuclei (Vulnerabilidades):"
  echo -e "      ${CYAN}cat${RESET} ${NUCLEI_DIR}/nuclei_output.txt | head -10"
  echo ""
  echo -e "  ${GREEN}[P5]${RESET} Infraestructura (IPs & Servicios):"
  echo -e "      ${CYAN}cat${RESET} ${IP_DISCOVER_DIR}/service_technology_mapping.tsv"
  echo ""
  echo -e "  ${BOLD}Reporte JSON Completo:${RESET}"
  echo -e "      ${CYAN}jq .${RESET} ${report} | less"
  echo ""
  log_ok "═══════════════════════════════════════════════════════════════"
}
