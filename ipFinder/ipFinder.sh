#!/usr/bin/env bash
#===============================================================================
# ORIGIN HUNTER v2.0 — Bug Bounty Recon: Real IP Discovery Behind CDN/WAF
# Autor: Senior SecEng workflow, optimizado para cobertura máxima + ESTABILIDAD
#
# REQUISITO: Ejecutar como usuario NORMAL (SIN sudo)
# 
# Uso:
#   ./ipFinder.sh <domain> [threads]
#   ./ipFinder.sh target.com 50
#
# Requiere: subfinder, dnsx, httpx, amass, assetfinder, curl, jq, openssl, dig
# Opcional: shodan CLI, nmap (sin permisos), nuclei
#
#===============================================================================

set -uo pipefail
IFS=$' \t\n'

# ─── COLORS & LOGGING ─────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()      { echo -e "${GREEN}[✔]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[!]${NC}    $*"; }
log_error()   { echo -e "${RED}[✗]${NC}    $*"; }
log_match()   { echo -e "${BOLD}${GREEN}[★ MATCH]${NC} $*"; }
log_phase()   { echo -e "\n${CYAN}${BOLD}════════════════════════════════════${NC}"; \
echo -e "${CYAN}${BOLD}  $*${NC}"; \
echo -e "${CYAN}${BOLD}════════════════════════════════════${NC}"; }

# ─── VALIDACIÓN DE PERMISOS ───────────────────────────────────────────────────
if [[ $EUID -eq 0 ]]; then
    log_error "Este script NO debe ejecutarse como root. Ejecuta como usuario normal:"
    log_error "  $0 $*"
    exit 1
fi

# ─── VALIDACIÓN INICIAL DE ARGUMENTOS ─────────────────────────────────────────
if [[ "$1" == -* ]] || [ $# -eq 0 ]; then
    log_error "Uso: $0 <archivo_targets.txt|dominio> [threads]"
    log_info "Ejemplos:"
    log_info "  $0 example.com"
    log_info "  $0 example.com 50"
    log_info "  $0 targets.txt 100"
    exit 1
fi

TARGETS_INPUT="${1:?Uso: $0 <archivo_targets.txt|dominio> [threads]}"
THREADS="${2:-40}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
API_KEYS_FILE="${API_KEYS_FILE:-$HOME/.api_keys}"

# ─── TIMEOUTS (AUMENTADOS PARA ESTABILIDAD) ────────────────────────────────────
TIMEOUT_CURL=10
TIMEOUT_SSL=6
TIMEOUT_DIG=5
HTTP_PORTS="80 443 8080 8443"
SCORE_THRESHOLD=3

# ─── PREPARACIÓN DE TARGETS ───────────────────────────────────────────────────
TARGETS_FILE="/tmp/oh_targets_${TIMESTAMP}.txt"
if [ -f "$TARGETS_INPUT" ]; then
    cp "$TARGETS_INPUT" "$TARGETS_FILE" 2>/dev/null || {
        log_error "No se puede leer archivo: $TARGETS_INPUT"
        exit 1
    }
    TARGETS_COUNT=$(wc -l < "$TARGETS_FILE" 2>/dev/null || echo 0)
    TARGETS_COUNT=$(echo "$TARGETS_COUNT" | grep -oE '[0-9]+' || echo 0)
else
    echo "$TARGETS_INPUT" > "$TARGETS_FILE"
    TARGETS_COUNT=1
fi

# Validar que no esté vacío
if [ "$TARGETS_COUNT" -eq 0 ] || [ ! -s "$TARGETS_FILE" ]; then
    log_error "Archivo de targets vacío o no válido"
    exit 1
fi

OUTPUT_DIR="origin_hunter_${TIMESTAMP}"

# ─── HELPERS ──────────────────────────────────────────────────────────────────
get_key()      { grep -s "^${1}=" "$API_KEYS_FILE" 2>/dev/null | cut -d'=' -f2- || echo ""; }
has_key()      { [ -n "$(get_key "$1")" ]; }
has_cmd()      { command -v "$1" &>/dev/null; }
count_lines()  { [ -f "$1" ] && wc -l < "$1" 2>/dev/null || echo 0; }

# Append único de forma segura
append_unique() {
    local src="$1" dst="$2"
    if [ -f "$src" ] && [ -s "$src" ]; then
        cat "$src" >> "$dst" 2>/dev/null || true
        sort -u "$dst" -o "$dst" 2>/dev/null || true
    fi
}

# IP en CIDR (bash puro)
ip_in_cidr() {
    local ip="$1" cidr="$2"
    local net="${cidr%/*}" bits="${cidr#*/}"
    local ip_dec net_dec mask a b c d
    
    IFS='.' read -r a b c d <<< "$ip" 2>/dev/null || return 1
    ip_dec=$(( (a<<24)|(b<<16)|(c<<8)|d ))
    
    IFS='.' read -r a b c d <<< "$net" 2>/dev/null || return 1
    net_dec=$(( (a<<24)|(b<<16)|(c<<8)|d ))
    
    mask=$(( 0xFFFFFFFF << (32-bits) & 0xFFFFFFFF ))
    [[ $(( ip_dec & mask )) -eq $(( net_dec & mask )) ]]
}

# Validar si IP es CDN (con manejo de errores)
is_cdn_ip() {
    local ip="$1"
    [ -z "$ip" ] && return 1
    [ ! -f "$OUTPUT_DIR/cdn_ranges.txt" ] && return 1
    
    while IFS= read -r cidr; do
        [[ "$cidr" =~ ^#|^$ ]] && continue
        ip_in_cidr "$ip" "$cidr" 2>/dev/null && return 0
    done < "$OUTPUT_DIR/cdn_ranges.txt"
    return 1
}

# ─── FASE 0: SETUP ────────────────────────────────────────────────────────────
phase0_setup() {
    log_phase "FASE 0: Preparación y Validación"

    local critical=("curl" "jq" "openssl" "sort" "grep" "sed" "dig")
    local missing_critical=()

    for dep in "${critical[@]}"; do
        if ! has_cmd "$dep"; then
            missing_critical+=("$dep")
        fi
    done

    if [ ${#missing_critical[@]} -gt 0 ]; then
        log_error "Dependencias críticas faltantes: ${missing_critical[*]}"
        log_info "Instala con: apt-get install ${missing_critical[*]}"
        exit 1
    fi

    # Crear estructura
    mkdir -p "$OUTPUT_DIR"/{01_osint,02_enumeration,03_fingerprinting,04_verification,reports,targets}

    # CDN ranges (sin cambios)
    cat > "$OUTPUT_DIR/cdn_ranges.txt" << 'CDNEOF'
# Cloudflare
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
# CloudFront / AWS
13.32.0.0/15
13.35.0.0/16
52.46.0.0/18
52.84.0.0/15
52.124.128.0/17
54.182.0.0/16
54.192.0.0/16
54.230.0.0/16
54.239.128.0/18
205.251.192.0/19
204.246.160.0/19
216.137.32.0/19
99.84.0.0/16
# Akamai
23.0.0.0/12
23.32.0.0/11
23.64.0.0/14
23.192.0.0/11
104.64.0.0/10
# Fastly
23.235.32.0/20
43.249.72.0/22
103.244.50.0/24
103.245.222.0/23
151.101.0.0/16
199.27.72.0/21
199.232.0.0/16
# Sucuri WAF
192.88.134.0/23
185.93.228.0/22
# Incapsula / Imperva
199.83.128.0/21
198.143.32.0/21
149.126.72.0/21
103.28.248.0/22
45.64.64.0/22
185.11.124.0/22
# Azure
13.107.42.0/24
13.107.43.0/24
CDNEOF

    cat > "$OUTPUT_DIR/reports/run_info.txt" << EOF
Targets: $TARGETS_COUNT dominios
Fecha: $(date)
Threads: $THREADS
Usuario: $(whoami)
APIs disponibles: $(for k in SHODAN SECURITY_TRAILS CHAOS VIRUSTOTAL; do has_key "$k" && printf "$k "; done || echo "ninguna")
Herramientas disponibles: $(for t in subfinder dnsx httpx amass shodan; do has_cmd "$t" && printf "$t "; done)
EOF

    log_ok "Workspace: $OUTPUT_DIR"
    log_ok "Targets a procesar: $TARGETS_COUNT"
}

# ─── FASE 1: OSINT PASIVO (POR TARGET) ────────────────────────────────────────
phase1_osint_target() {
    local target_dir="$1"
    local target="$2"
    local osint_ips="${target_dir}/01_osint/all_osint_ips.txt"
    
    mkdir -p "${target_dir}/01_osint" 2>/dev/null || return
    touch "$osint_ips"

    log_info "[1.1] Certificate Transparency — $target"
    local crt_domains="${target_dir}/01_osint/crt_domains.txt"
    local crt_ips="${target_dir}/01_osint/crt_ips.txt"

    {
        timeout "$TIMEOUT_CURL" curl -s --retry 2 "https://crt.sh/?q=%25.${target}&output=json" 2>/dev/null || true
        timeout "$TIMEOUT_CURL" curl -s --retry 2 "https://crt.sh/?q=${target}&output=json" 2>/dev/null || true
    } | jq -r '.[].name_value // empty' 2>/dev/null \
        | sed 's/\*\.//g' | tr ',' '\n' \
        | grep -iE "^[a-z0-9._-]+\.${target}$|^${target}$" \
        | sort -u > "$crt_domains" 2>/dev/null || touch "$crt_domains"

    grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' "$crt_domains" 2>/dev/null | sort -u > "$crt_ips" || touch "$crt_ips"
    append_unique "$crt_ips" "$osint_ips"
    log_ok "  crt.sh: $(count_lines "$crt_domains") dominios, $(count_lines "$crt_ips") IPs"

    # 1.2 SecurityTrails
    log_info "[1.2] SecurityTrails — $target"
    local st_ips="${target_dir}/01_osint/securitytrails_ips.txt"
    touch "$st_ips"
    if has_key "SECURITY_TRAILS"; then
        local ST_KEY; ST_KEY=$(get_key "SECURITY_TRAILS")
        timeout "$TIMEOUT_CURL" curl -s "https://api.securitytrails.com/v1/domain/${target}/history/a" \
            -H "APIKEY: $ST_KEY" 2>/dev/null \
            | jq -r '.records[].values[]?.ip // empty' 2>/dev/null \
            | sort -u > "$st_ips" || true
        append_unique "$st_ips" "$osint_ips"
        log_ok "  SecurityTrails: $(count_lines "$st_ips") IPs"
    else
        log_warn "  SecurityTrails: sin API key"
    fi

    # 1.3 VirusTotal
    log_info "[1.3] VirusTotal — $target"
    local vt_ips="${target_dir}/01_osint/virustotal_ips.txt"
    touch "$vt_ips"
    if has_key "VIRUSTOTAL"; then
        local VT_KEY; VT_KEY=$(get_key "VIRUSTOTAL")
        timeout "$TIMEOUT_CURL" curl -s "https://www.virustotal.com/api/v3/domains/${target}/resolutions?limit=40" \
            -H "x-apikey: $VT_KEY" 2>/dev/null \
            | jq -r '.data[].attributes.ip_address // empty' 2>/dev/null \
            | sort -u > "$vt_ips" || true
        append_unique "$vt_ips" "$osint_ips"
        log_ok "  VirusTotal: $(count_lines "$vt_ips") IPs"
    else
        log_warn "  VirusTotal: sin API key"
    fi

    # 1.4 Wayback Machine
    log_info "[1.4] Wayback Machine — $target"
    local wb_ips="${target_dir}/01_osint/wayback_ips.txt"
    timeout 40 curl -s \
        "http://web.archive.org/cdx/search/cdx?url=*.${target}/*&output=text&fl=original&collapse=urlkey&limit=10000" \
        2>/dev/null \
        | grep -oE 'https?://[0-9]{1,3}(\.[0-9]{1,3}){3}' \
        | sed 's|https\?://||' \
        | sort -u > "$wb_ips" 2>/dev/null || touch "$wb_ips"
    append_unique "$wb_ips" "$osint_ips"
    log_ok "  Wayback: $(count_lines "$wb_ips") IPs"

    # 1.5 DNS Records (MX, SPF, etc)
    log_info "[1.5] DNS Records (MX, TXT, SPF) — $target"
    local dns_leak="${target_dir}/01_osint/dns_leak_ips.txt"
    {
        timeout "$TIMEOUT_DIG" dig +short MX "$target" 2>/dev/null | awk '{print $2}' | sed 's/\.$//' || true
        timeout "$TIMEOUT_DIG" dig +short TXT "$target" 2>/dev/null | grep -oE 'ip4:[0-9.]+' | cut -d: -f2 || true
        for sub in mail smtp api backend admin staging; do
            timeout "$TIMEOUT_DIG" dig +short A "${sub}.${target}" 2>/dev/null || true
        done
    } | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sort -u > "$dns_leak" 2>/dev/null || touch "$dns_leak"
    append_unique "$dns_leak" "$osint_ips"
    log_ok "  DNS Leak: $(count_lines "$dns_leak") IPs"

    log_ok "OSINT total para $target: $(count_lines "$osint_ips") IPs"
}

# ─── FASE 2: ENUMERACIÓN ACTIVA (POR TARGET) ──────────────────────────────────
phase2_enumeration_target() {
    local target_dir="$1"
    local target="$2"
    
    mkdir -p "${target_dir}/02_enumeration" 2>/dev/null || return
    
    log_info "[2.1] Enumeración de subdominios — $target"
    local subs_file="${target_dir}/02_enumeration/all_subs.txt"
    touch "$subs_file"

    if has_cmd subfinder; then
        timeout 120 subfinder -d "$target" -silent -recursive -all \
            -o "${target_dir}/02_enumeration/subfinder.txt" 2>/dev/null || true
        append_unique "${target_dir}/02_enumeration/subfinder.txt" "$subs_file"
    fi

    if has_cmd amass; then
        timeout 120 amass enum -passive -norecursive -d "$target" \
            -o "${target_dir}/02_enumeration/amass.txt" 2>/dev/null || true
        append_unique "${target_dir}/02_enumeration/amass.txt" "$subs_file"
    fi

    # CRITICAL FIX: Inyectar dominios de crt.sh
    if [ -f "${target_dir}/01_osint/crt_domains.txt" ] && [ -s "${target_dir}/01_osint/crt_domains.txt" ]; then
        cat "${target_dir}/01_osint/crt_domains.txt" >> "$subs_file"
    fi

    sort -u "$subs_file" -o "$subs_file" 2>/dev/null || true
    log_ok "  Subdominios: $(count_lines "$subs_file")"

    # 2.2 Resolución DNS
    log_info "[2.2] Resolución DNS — $target"
    local resolved_file="${target_dir}/02_enumeration/resolved_all.txt"
    local all_ips_raw="${target_dir}/02_enumeration/all_ips_raw.txt"

    if has_cmd dnsx; then
        timeout 180 dnsx -l "$subs_file" -resp -a -cname \
            -silent -t "$THREADS" \
            -o "$resolved_file" 2>/dev/null || touch "$resolved_file"
    else
        # Fallback: dig manual
        while IFS= read -r sub; do
            [ -z "$sub" ] && continue
            timeout "$TIMEOUT_DIG" dig +short A "$sub" 2>/dev/null || true
        done < "$subs_file" > "$resolved_file" 2>/dev/null || true
    fi

    grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' "$resolved_file" 2>/dev/null | sort -u > "$all_ips_raw" || touch "$all_ips_raw"
    log_ok "  IPs resueltas: $(count_lines "$all_ips_raw")"

    # 2.3 Filtrar CDN
    log_info "[2.3] Filtrando rangos CDN — $target"
    local non_cdn_ips="${target_dir}/02_enumeration/non_cdn_ips.txt"
    touch "$non_cdn_ips"

    while IFS= read -r ip; do
        [ -z "$ip" ] && continue
        if ! is_cdn_ip "$ip" 2>/dev/null; then
            echo "$ip" >> "$non_cdn_ips"
        fi
    done < "$all_ips_raw"

    sort -u "$non_cdn_ips" -o "$non_cdn_ips" 2>/dev/null || true
    log_ok "  IPs no-CDN: $(count_lines "$non_cdn_ips")"
}

# ─── FASE 3: FINGERPRINTING (POR TARGET) ──────────────────────────────────────
phase3_fingerprinting_target() {
    local target_dir="$1"
    local target="$2"

    mkdir -p "${target_dir}/03_fingerprinting" 2>/dev/null || return

    local candidates="${target_dir}/02_enumeration/non_cdn_ips.txt"
    [ ! -f "$candidates" ] || [ ! -s "$candidates" ] && return

    log_info "[3.1] SSL Certificate Matching — $target"
    local ssl_matches="${target_dir}/03_fingerprinting/ssl_matches.txt"
    touch "$ssl_matches"

    local main_fp main_cn
    main_fp=$(echo Q | timeout "$TIMEOUT_SSL" openssl s_client -connect "${target}:443" \
        -servername "$target" 2>/dev/null \
        | openssl x509 -fingerprint -sha256 -noout 2>/dev/null \
        | cut -d'=' -f2 || echo "")

    if [ -z "$main_fp" ]; then
        log_warn "  No se pudo obtener cert del target"
        return
    fi

    main_cn=$(echo Q | timeout "$TIMEOUT_SSL" openssl s_client -connect "${target}:443" \
        -servername "$target" 2>/dev/null \
        | openssl x509 -noout -subject 2>/dev/null \
        | grep -oE 'CN=([^,/]+)' | cut -d'=' -f2 || echo "")

    log_info "  Referencia: FP=${main_fp:0:20}... CN=$main_cn"

    local count=0
    while IFS= read -r ip; do
        [ -z "$ip" ] && continue
        
        local fp
        fp=$(echo Q | timeout "$TIMEOUT_SSL" openssl s_client -connect "${ip}:443" \
            -servername "$target" 2>/dev/null \
            | openssl x509 -fingerprint -sha256 -noout 2>/dev/null \
            | cut -d'=' -f2 || echo "")

        if [ -n "$fp" ] && [ "$fp" = "$main_fp" ]; then
            echo "$ip" >> "$ssl_matches"
            count=$((count + 1))
        fi
    done < "$candidates"

    log_ok "  SSL matches: $count"
}

# ─── FASE 4: VERIFICACIÓN (POR TARGET) ────────────────────────────────────────
phase4_verification_target() {
    local target_dir="$1"
    local target="$2"

    mkdir -p "${target_dir}/04_verification" 2>/dev/null || return

    local consolidated="${target_dir}/04_verification/candidates_consolidated.txt"
    
    if [ -f "${target_dir}/03_fingerprinting/ssl_matches.txt" ] && [ -s "${target_dir}/03_fingerprinting/ssl_matches.txt" ]; then
        cp "${target_dir}/03_fingerprinting/ssl_matches.txt" "$consolidated"
    else
        cp "${target_dir}/02_enumeration/non_cdn_ips.txt" "$consolidated" 2>/dev/null || touch "$consolidated"
    fi

    [ ! -s "$consolidated" ] && {
        log_warn "Sin candidatos para verificar en $target"
        touch "${target_dir}/04_verification/verified_origins.txt"
        return
    }

    log_info "[4.1] Verificación multi-criterio — $target"
    local verified="${target_dir}/04_verification/verified_origins.txt"
    touch "$verified"

    local verified_count=0
    while IFS= read -r ip; do
        [ -z "$ip" ] && continue

        local score=0 evidence=""

        # Criterio 1: HTTP status válido
        local status
        status=$(timeout "$TIMEOUT_CURL" curl -sk -I \
            -H "Host: $target" \
            "https://$ip" 2>/dev/null | grep -oE 'HTTP/[0-9.]+ [0-9]+' | awk '{print $2}' || echo "000")
        
        if [[ "$status" =~ ^(200|301|302|304|307|308)$ ]]; then
            score=$((score + 1))
            evidence="${evidence}HTTP:$status "
        fi

        # Criterio 2: CN válido
        local cn
        cn=$(echo Q | timeout "$TIMEOUT_SSL" openssl s_client -connect "${ip}:443" \
            -servername "$target" 2>/dev/null \
            | openssl x509 -noout -subject 2>/dev/null \
            | grep -oE 'CN=([^,/]+)' | cut -d'=' -f2 || echo "")
        
        if [ -n "$cn" ] && echo "$cn" | grep -qi "${target}$"; then
            score=$((score + 1))
            evidence="${evidence}CN:OK "
        fi

        # Criterio 3: Contenido contiene dominio
        local body
        body=$(timeout "$TIMEOUT_CURL" curl -sk \
            -H "Host: $target" "https://$ip" 2>/dev/null | head -c 5000)
        
        if echo "$body" | grep -qi "$target"; then
            score=$((score + 1))
            evidence="${evidence}CONTENT_MATCH "
        fi

        # Criterio 4: NO redirige a CDN
        local location
        location=$(timeout "$TIMEOUT_CURL" curl -sk -I \
            -H "Host: $target" "https://$ip" 2>/dev/null \
            | grep -i "^location:" || echo "")
        
        if ! echo "$location" | grep -qi "cloudflare\|cloudfront\|akamai\|fastly"; then
            score=$((score + 1))
            evidence="${evidence}NO_CDN_REDIR "
        fi

        # Resultado
        if [ "$score" -ge "$SCORE_THRESHOLD" ]; then
            echo "$ip | score=$score/4 | ${evidence}" >> "$verified"
            verified_count=$((verified_count + 1))
            log_match "ORIGEN: $ip (score $score/4)"
        fi

    done < "$consolidated"

    log_ok "Orígenes verificados para $target: $verified_count"
}

# ─── PROCESAMIENTO MULTI-TARGET ───────────────────────────────────────────────
process_multiple_targets() {
    local target_num=0
    local results_summary="$OUTPUT_DIR/reports/summary_all_targets.txt"
    
    > "$results_summary"  # Clear file

    while IFS= read -r TARGET; do
        [[ -z "$TARGET" || "$TARGET" =~ ^#.*$ ]] && continue
        TARGET=$(echo "$TARGET" | xargs)
        [ -z "$TARGET" ] && continue

        target_num=$((target_num + 1))
        log_phase "[$target_num/$TARGETS_COUNT] Procesando: $TARGET"

        local target_dir="$OUTPUT_DIR/targets/${TARGET}"
        mkdir -p "${target_dir}"/{01_osint,02_enumeration,03_fingerprinting,04_verification}

        # Ejecutar fases
        phase1_osint_target "$target_dir" "$TARGET" || log_warn "OSINT falló para $TARGET"
        phase2_enumeration_target "$target_dir" "$TARGET" || log_warn "Enumeración falló para $TARGET"
        phase3_fingerprinting_target "$target_dir" "$TARGET" || log_warn "Fingerprinting falló para $TARGET"
        phase4_verification_target "$target_dir" "$TARGET" || log_warn "Verificación falló para $TARGET"

        # Summary
        local verified_count=$(count_lines "${target_dir}/04_verification/verified_origins.txt")
        echo "$TARGET | Orígenes encontrados: $verified_count" >> "$results_summary"

    done < "$TARGETS_FILE"

    log_ok "Procesamiento completado"
}

# ─── REPORTE FINAL ────────────────────────────────────────────────────────────
phase5_report() {
    log_phase "FASE 5: Reporte Final"

    local report="$OUTPUT_DIR/reports/RESULTADOS_FINALES.md"

    cat > "$report" << 'REPEOF'
# Origin Hunter v2.0 — Reporte Final

| Campo | Valor |
|-------|-------|
| Herramienta | Origin Hunter v2.0 |
| Fecha | $(date) |
| Targets procesados | $(count_lines "$TARGETS_FILE") |

---

## Resumen por Target

REPEOF

    while IFS= read -r TARGET; do
        [[ -z "$TARGET" || "$TARGET" =~ ^#.*$ ]] && continue
        TARGET=$(echo "$TARGET" | xargs)
        [ -z "$TARGET" ] && continue

        local target_dir="$OUTPUT_DIR/targets/${TARGET}"
        local verified="${target_dir}/04_verification/verified_origins.txt"

        local count=$(count_lines "$verified")
        echo "" >> "$report"
        echo "### $TARGET (Orígenes: $count)" >> "$report"
        echo "" >> "$report"

        if [ "$count" -gt 0 ]; then
            echo '
```
