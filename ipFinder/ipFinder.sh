#!/usr/bin/env bash
#===============================================================================
# ORIGIN HUNTER v2.0 — Bug Bounty Recon: Real IP Discovery Behind CDN/WAF
# Autor: Senior SecEng workflow, optimizado para cobertura máxima
#
# Uso:
#   ./ipFinder.sh <domain> [threads]
#   ./ipFinder.sh target.com 50
#
# Requiere: subfinder, dnsx, httpx, amass, assetfinder, curl, jq, openssl, nmap
# Opcional: shodan CLI, chaos, nuclei
# API Keys: ~/.api_keys (ver formato abajo)
#
# Formato ~/.api_keys:
#   SHODAN=tu_api_key
#   SECURITY_TRAILS=tu_api_key
#   CHAOS=tu_api_key
#   CENSYS_ID=tu_api_id
#   CENSYS_SECRET=tu_api_secret
#   VIRUSTOTAL=tu_api_key
#   BINARYEDGE=tu_api_key
#===============================================================================

set -uo pipefail
IFS=$' \t\n'  # ← FIX: Formato estándar para evitar saltos de línea accidentales


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

# ─── CONFIGURACIÓN ────────────────────────────────────────────────────────────
if [[ "$1" == -* ]]; then
  log_error "Uso: $0 <archivo_targets.txt|dominio> [threads]"
  exit 1
fi

TARGETS_INPUT="${1:?Uso: $0 <archivo_targets.txt|dominio> [threads]}"
THREADS="${2:-40}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
API_KEYS_FILE="${API_KEYS_FILE:-$HOME/.api_keys}"
TIMEOUT_CURL=8
TIMEOUT_SSL=4
HTTP_PORTS="80 443 8080 8443 8888 4443 3000 8000 8008 9443"
SCORE_THRESHOLD=3   # Mínimo para considerar IP como origen probable

# Determinar si es archivo o dominio único
TARGETS_FILE="/tmp/oh_targets_${TIMESTAMP}.txt"
if [ -f "$TARGETS_INPUT" ]; then
    # Es un archivo
    cp "$TARGETS_INPUT" "$TARGETS_FILE"
    TARGETS_COUNT=$(wc -l < "$TARGETS_FILE")
    log_info "Archivo de targets cargado: $TARGETS_COUNT dominios"
else
    # Es un dominio único
    echo "$TARGETS_INPUT" > "$TARGETS_FILE"
    TARGETS_COUNT=1
fi

# Validar que no esté vacío
if [ "$TARGETS_COUNT" -eq 0 ]; then
    log_error "Archivo de targets vacío"
    exit 1
fi

OUTPUT_DIR="origin_hunter_${TIMESTAMP}"



# ─── HELPERS ──────────────────────────────────────────────────────────────────
get_key() { grep -s "^${1}=" "$API_KEYS_FILE" 2>/dev/null | cut -d'=' -f2- || echo ""; }
has_key() { [ -n "$(get_key "$1")" ]; }
has_cmd() { command -v "$1" &>/dev/null; }
count_lines() { wc -l < "$1" 2>/dev/null || echo 0; }
append_unique() { cat "$1" >> "$2" 2>/dev/null; sort -u "$2" -o "$2"; }

# Merge y deduplicar múltiples archivos en uno
merge_files() {
    local out="$1"; shift
    cat "$@" 2>/dev/null | sort -u > "$out"
}

# Verificar si una IP pertenece a un rango CIDR (pure bash, sin ipcalc)
ip_in_cidr() {
    local ip="$1" cidr="$2"
    local net="${cidr%/*}" bits="${cidr#*/}"
    local ip_dec net_dec mask
    IFS='.' read -r a b c d <<< "$ip";     ip_dec=$(( (a<<24)|(b<<16)|(c<<8)|d ))
    IFS='.' read -r a b c d <<< "$net";    net_dec=$(( (a<<24)|(b<<16)|(c<<8)|d ))
    mask=$(( 0xFFFFFFFF << (32-bits) & 0xFFFFFFFF ))
    [[ $(( ip_dec & mask )) -eq $(( net_dec & mask )) ]]
}

# Determinar si una IP es CDN usando la lista de rangos
is_cdn_ip() {
    local ip="$1"
    while IFS= read -r cidr; do
        [[ "$cidr" =~ ^#|^$ ]] && continue
        ip_in_cidr "$ip" "$cidr" 2>/dev/null && return 0
    done < "$OUTPUT_DIR/cdn_ranges.txt"
    return 1
}

# ─── FASE 0: PREPARACIÓN ──────────────────────────────────────────────────────
phase0_setup() {
    log_phase "FASE 0: Preparación y Configuración"

    # Verificar dependencias críticas
    local critical=("curl" "jq" "openssl" "sort" "grep")
    local recommended=("subfinder" "dnsx" "httpx" "amass" "assetfinder" "nmap")
    local missing_critical=() missing_rec=()

    for dep in "${critical[@]}"; do
        has_cmd "$dep" || missing_critical+=("$dep")
    done
    for dep in "${recommended[@]}"; do
        has_cmd "$dep" || missing_rec+=("$dep")
    done

    if [ ${#missing_critical[@]} -gt 0 ]; then
        log_error "Dependencias críticas faltantes: ${missing_critical[*]}"
        exit 1
    fi
    [ ${#missing_rec[@]} -gt 0 ] && log_warn "Herramientas recomendadas faltantes: ${missing_rec[*]}"

    # Estructura de directorios
    mkdir -p "$OUTPUT_DIR"/{01_osint,02_enumeration,03_fingerprinting,04_verification,reports}

    # ── Rangos CDN/WAF (actualizados, con CIDR correcto) ──────────────────────
    cat > "$OUTPUT_DIR/cdn_ranges.txt" << 'CDNEOF'
# Cloudflare (fuente oficial: https://www.cloudflare.com/ips-v4)
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
131.0.72.0/22
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
# Akamai (principales)
23.0.0.0/12
23.32.0.0/11
23.64.0.0/14
23.192.0.0/11
104.64.0.0/10
2.16.0.0/13
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
# Azure Front Door / CDN
13.107.42.0/24
13.107.43.0/24
CDNEOF

    # Registrar metadata del run
    cat > "$OUTPUT_DIR/reports/run_info.txt" << EOF
Targets: $TARGETS_COUNT dominios
Targets listados en: $TARGETS_FILE
Fecha: $(date)
Threads: $THREADS
APIs disponibles: $(for k in SHODAN SECURITY_TRAILS CHAOS CENSYS_ID VIRUSTOTAL BINARYEDGE; do has_key "$k" && printf "$k "; done || echo "ninguna")
Herramientas: $(for t in subfinder dnsx httpx amass assetfinder nmap shodan; do has_cmd "$t" && printf "$t "; done)
EOF

    log_ok "Workspace: $OUTPUT_DIR"
    log_ok "CDN ranges cargados"
    log_ok "Targets a procesar: $TARGETS_COUNT"
}

# ─── FASE 1: OSINT PASIVO ─────────────────────────────────────────────────────
phase1_osint() {
    log_phase "FASE 1: OSINT Pasivo (Sin tocar el objetivo)"
    local osint_ips="$OUTPUT_DIR/01_osint/all_osint_ips.txt"
    touch "$osint_ips"

    # 1.1 — Certificate Transparency (crt.sh) ─────────────────────────────────
    log_info "[1.1] Certificate Transparency (crt.sh)..."
    local crt_raw="$OUTPUT_DIR/01_osint/crt_raw.json"
    local crt_domains="$OUTPUT_DIR/01_osint/crt_domains.txt"
    local crt_ips="$OUTPUT_DIR/01_osint/crt_ips.txt"

    # Dos queries: wildcard y exact match
    {
        curl -s --retry 3 --retry-delay 2 "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null
        curl -s --retry 3 --retry-delay 2 "https://crt.sh/?q=$TARGET&output=json" 2>/dev/null
    } | jq -r '.[].name_value' 2>/dev/null \
        | sed 's/\*\.//g' | tr ',' '\n' \
        | grep -iE "^[a-z0-9._-]+\.$TARGET$|^$TARGET$" \
        | sort -u > "$crt_domains" || true

    # Extraer IPs directas si aparecen en SAN
    grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' "$crt_domains" 2>/dev/null | sort -u > "$crt_ips" || touch "$crt_ips"
    append_unique "$crt_ips" "$osint_ips"
    log_ok "crt.sh: $(count_lines "$crt_domains") dominios | $(count_lines "$crt_ips") IPs directas"

    # 1.2 — DNS History: SecurityTrails ───────────────────────────────────────
    log_info "[1.2] DNS History: SecurityTrails..."
    local st_ips="$OUTPUT_DIR/01_osint/securitytrails_ips.txt"
    touch "$st_ips"
    if has_key "SECURITY_TRAILS"; then
        local ST_KEY; ST_KEY=$(get_key "SECURITY_TRAILS")
        # Historial de registros A
        curl -s --retry 2 "https://api.securitytrails.com/v1/domain/$TARGET/history/a" \
            -H "APIKEY: $ST_KEY" 2>/dev/null \
            | jq -r '.records[].values[]?.ip // empty' 2>/dev/null \
            | sort -u > "$st_ips" || true
        # Subdominios vía ST
        curl -s "https://api.securitytrails.com/v1/domain/$TARGET/subdomains?children_only=false" \
            -H "APIKEY: $ST_KEY" 2>/dev/null \
            | jq -r '.subdomains[]' 2>/dev/null \
            | sed "s/$/.${TARGET}/" >> "$OUTPUT_DIR/01_osint/st_subs.txt" || true
        append_unique "$st_ips" "$osint_ips"
        log_ok "SecurityTrails: $(count_lines "$st_ips") IPs históricas"
    else
        log_warn "SecurityTrails: sin API key"
    fi

    # 1.3 — DNS History: VirusTotal ───────────────────────────────────────────
    log_info "[1.3] DNS History: VirusTotal..."
    local vt_ips="$OUTPUT_DIR/01_osint/virustotal_ips.txt"
    touch "$vt_ips"
    if has_key "VIRUSTOTAL"; then
        local VT_KEY; VT_KEY=$(get_key "VIRUSTOTAL")
        # Resoluciones históricas
        curl -s "https://www.virustotal.com/api/v3/domains/${TARGET}/resolutions?limit=40" \
            -H "x-apikey: $VT_KEY" 2>/dev/null \
            | jq -r '.data[].attributes.ip_address // empty' 2>/dev/null \
            | sort -u > "$vt_ips" || true
        append_unique "$vt_ips" "$osint_ips"
        log_ok "VirusTotal: $(count_lines "$vt_ips") IPs históricas"
    else
        log_warn "VirusTotal: sin API key"
    fi

    # 1.4 — Wayback Machine: IPs embebidas en URLs históricas ─────────────────
    log_info "[1.4] Wayback Machine (IPs históricas en URLs)..."
    local wb_ips="$OUTPUT_DIR/01_osint/wayback_ips.txt"
    curl -s --max-time 30 \
        "http://web.archive.org/cdx/search/cdx?url=*.${TARGET}/*&output=text&fl=original&collapse=urlkey&limit=50000" \
        2>/dev/null \
        | grep -oE 'https?://[0-9]{1,3}(\.[0-9]{1,3}){3}' \
        | sed 's|https\?://||' \
        | sort -u > "$wb_ips" || touch "$wb_ips"
    append_unique "$wb_ips" "$osint_ips"
    log_ok "Wayback Machine: $(count_lines "$wb_ips") IPs en URLs históricas"

    # 1.5 — Shodan: hostname + SSL cert + http.title ──────────────────────────
    log_info "[1.5] Shodan..."
    local shodan_ips="$OUTPUT_DIR/01_osint/shodan_ips.txt"
    touch "$shodan_ips"
    if has_key "SHODAN" && has_cmd "shodan"; then
        local SHODAN_KEY; SHODAN_KEY=$(get_key "SHODAN")
        shodan init "$SHODAN_KEY" &>/dev/null || true
        for query in \
            "hostname:$TARGET" \
            "ssl.cert.subject.cn:$TARGET" \
            "ssl.cert.subject.cn:*.$TARGET" \
            "http.host:$TARGET" \
            "http.html:\"$TARGET\""; do
            shodan search "$query" --fields ip_str --separator $'\n' 2>/dev/null >> "$shodan_ips" || true
        done
        sort -u "$shodan_ips" -o "$shodan_ips"
        append_unique "$shodan_ips" "$osint_ips"
        log_ok "Shodan: $(count_lines "$shodan_ips") IPs"
    else
        log_warn "Shodan: sin API key o CLI no instalada"
    fi

    # 1.6 — Censys ─────────────────────────────────────────────────────────────
    log_info "[1.6] Censys..."
    local censys_ips="$OUTPUT_DIR/01_osint/censys_ips.txt"
    touch "$censys_ips"
    if has_key "CENSYS_ID" && has_key "CENSYS_SECRET"; then
        local CID; CID=$(get_key "CENSYS_ID")
        local CSEC; CSEC=$(get_key "CENSYS_SECRET")
        local query='{"query":"services.tls.certificates.leaf_data.names: '"$TARGET"'","fields":["ip"],"per_page":100}'
        curl -s -u "${CID}:${CSEC}" \
            -X POST "https://search.censys.io/api/v2/hosts/search" \
            -H "Content-Type: application/json" \
            -d "$query" 2>/dev/null \
            | jq -r '.result.hits[].ip // empty' 2>/dev/null \
            >> "$censys_ips" || true
        sort -u "$censys_ips" -o "$censys_ips"
        append_unique "$censys_ips" "$osint_ips"
        log_ok "Censys: $(count_lines "$censys_ips") IPs"
    else
        log_warn "Censys: sin credenciales"
    fi

    # 1.7 — BinaryEdge ─────────────────────────────────────────────────────────
    log_info "[1.7] BinaryEdge..."
    local be_ips="$OUTPUT_DIR/01_osint/binaryedge_ips.txt"
    touch "$be_ips"
    if has_key "BINARYEDGE"; then
        local BE_KEY; BE_KEY=$(get_key "BINARYEDGE")
        curl -s "https://api.binaryedge.io/v2/query/domains/subdomain/$TARGET" \
            -H "X-Key: $BE_KEY" 2>/dev/null \
            | jq -r '.events[]' 2>/dev/null | sort -u > "$OUTPUT_DIR/01_osint/be_subs.txt" || true
        curl -s "https://api.binaryedge.io/v2/query/search?query=ssl.subject.cn:$TARGET" \
            -H "X-Key: $BE_KEY" 2>/dev/null \
            | jq -r '.events[].origin.ip // empty' 2>/dev/null \
            | sort -u > "$be_ips" || true
        append_unique "$be_ips" "$osint_ips"
        log_ok "BinaryEdge: $(count_lines "$be_ips") IPs"
    else
        log_warn "BinaryEdge: sin API key"
    fi

    # 1.8 — MX / SPF / TXT Records (mail infra puede revelar origen real) ──────
    log_info "[1.8] Análisis de DNS Records (MX, TXT, SPF)..."
    local dns_leak_ips="$OUTPUT_DIR/01_osint/dns_leak_ips.txt"
    {
        # MX records
        dig +short MX "$TARGET" 2>/dev/null | awk '{print $2}' | sed 's/\.$//'
        # SPF puede contener IPs de origen
        dig +short TXT "$TARGET" 2>/dev/null | grep -i "spf\|include\|ip4" | \
            grep -oE 'ip4:[0-9./]+' | cut -d: -f2
        # DMARC
        dig +short TXT "_dmarc.$TARGET" 2>/dev/null
        # Subdomains frecuentes de infra interna
        for sub in mail smtp imap pop pop3 webmail autodiscover autoconfig ftp sftp \
                   api api2 backend admin panel dev staging test preprod uat; do
            dig +short A "${sub}.${TARGET}" 2>/dev/null
        done
    } | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sort -u > "$dns_leak_ips" || touch "$dns_leak_ips"
    append_unique "$dns_leak_ips" "$osint_ips"
    log_ok "DNS Leak Records: $(count_lines "$dns_leak_ips") IPs"

    # 1.9 — DNSDumpster (scraping sin auth) ────────────────────────────────────
    log_info "[1.9] DNSDumpster..."
    local dd_ips="$OUTPUT_DIR/01_osint/dnsdumpster_ips.txt"
    local csrf_token
    csrf_token=$(curl -s -c /tmp/oh_cookies "https://dnsdumpster.com/" 2>/dev/null | \
        grep -oE 'csrfmiddlewaretoken" value="[^"]+' | cut -d'"' -f3 || echo "")
    if [ -n "$csrf_token" ]; then
        curl -s -b /tmp/oh_cookies \
            -d "csrfmiddlewaretoken=${csrf_token}&targetip=${TARGET}&user=free" \
            -H "Referer: https://dnsdumpster.com/" \
            "https://dnsdumpster.com/" 2>/dev/null \
            | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' \
            | sort -u > "$dd_ips" || touch "$dd_ips"
        rm -f /tmp/oh_cookies
    else
        touch "$dd_ips"
    fi
    append_unique "$dd_ips" "$osint_ips"
    log_ok "DNSDumpster: $(count_lines "$dd_ips") IPs"

    log_ok "OSINT total: $(count_lines "$osint_ips") IPs únicas pre-filtrado"
}

# ─── FASE 2: ENUMERACIÓN ACTIVA ───────────────────────────────────────────────
phase2_enumeration_target() {
    local target_dir="$1"
    local target="$2"
    log_info "[2.1] Enumeración de subdominios — $target..."
    local subs_file="${target_dir}/02_enumeration/all_subs.txt"
    touch "$subs_file"

    # 1. Activos (Subfinder/Amass)
    if has_cmd subfinder; then
        subfinder -d "$target" -silent -recursive -all \
        -o "${target_dir}/02_enumeration/subfinder.txt" 2>/dev/null || true
        append_unique "${target_dir}/02_enumeration/subfinder.txt" "$subs_file"
    fi
    if has_cmd amass; then
        timeout 120 amass enum -passive -norecursive -d "$target" \
        -o "${target_dir}/02_enumeration/amass.txt" 2>/dev/null || true
        append_unique "${target_dir}/02_enumeration/amass.txt" "$subs_file"
    fi

    # 2.  FIX CRÍTICO: Inyectar dominios de OSINT (crt.sh) si subfinder falló
    if [ -f "${target_dir}/01_osint/crt_domains.txt" ]; then
        cat "${target_dir}/01_osint/crt_domains.txt" >> "$subs_file"
    fi

    # Deduplicar
    sort -u "$subs_file" -o "$subs_file"
    log_ok "  Subdominios totales (OSINT + Activos): $(count_lines "$subs_file")"

    log_info "[2.2] Resolución DNS — $target..."
    local resolved_file="${target_dir}/02_enumeration/resolved_all.txt"
    local all_ips_raw="${target_dir}/02_enumeration/all_ips_raw.txt"
    if has_cmd dnsx; then
        dnsx -l "$subs_file" -resp -a -aaaa -cname \
        -silent -t "$THREADS" \
        -o "$resolved_file" 2>/dev/null || true
    else
        while IFS= read -r sub; do
            local r; r=$(dig +short A "$sub" 2>/dev/null)
            [ -n "$r" ] && echo "$sub [$r]"
        done < "$subs_file" > "$resolved_file" || true
    fi
    grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' "$resolved_file" 2>/dev/null | sort -u > "$all_ips_raw" || touch "$all_ips_raw"
    log_ok "  IPs resueltas: $(count_lines "$all_ips_raw")"
    
    log_info "[2.3] Filtrando rangos CDN — $target..."
    local non_cdn_ips="${target_dir}/02_enumeration/non_cdn_ips.txt"
    touch "$non_cdn_ips"
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        if is_cdn_ip "$ip"; then
            : # Ignorar CDN
        else
            echo "$ip" >> "$non_cdn_ips"
        fi
    done < "$all_ips_raw"
    sort -u "$non_cdn_ips" -o "$non_cdn_ips"
    log_ok "  IPs no-CDN: $(count_lines "$non_cdn_ips")"
}

# ─── FASE 3: FINGERPRINTING AVANZADO ─────────────────────────────────────────
phase3_fingerprinting() {
    log_phase "FASE 3: Correlación y Fingerprinting Avanzado"

    local candidates="$OUTPUT_DIR/02_enumeration/web_open_ips.txt"
    [ ! -s "$candidates" ] && candidates="$OUTPUT_DIR/02_enumeration/non_cdn_ips.txt"

    if [ ! -s "$candidates" ]; then
        log_warn "Sin candidatos para fingerprinting"
        return
    fi

    # 3.1 — SSL Certificate Matching (multi-puerto) ───────────────────────────
    log_info "[3.1] SSL Certificate Matching (multi-puerto)..."
    local ssl_matches="$OUTPUT_DIR/03_fingerprinting/ssl_matches.txt"
    touch "$ssl_matches"

    # Obtener fingerprint de referencia (por el CDN está bien, la cert del origen viaja igual)
    local main_fp main_serial main_cn
    main_fp=$(echo Q | openssl s_client -connect "${TARGET}:443" \
        -servername "$TARGET" -timeout "$TIMEOUT_SSL" 2>/dev/null \
        | openssl x509 -fingerprint -sha256 -noout 2>/dev/null \
        | cut -d'=' -f2 || echo "")
    main_serial=$(echo Q | openssl s_client -connect "${TARGET}:443" \
        -servername "$TARGET" -timeout "$TIMEOUT_SSL" 2>/dev/null \
        | openssl x509 -serial -noout 2>/dev/null \
        | cut -d'=' -f2 || echo "")
    main_cn=$(echo Q | openssl s_client -connect "${TARGET}:443" \
        -servername "$TARGET" -timeout "$TIMEOUT_SSL" 2>/dev/null \
        | openssl x509 -noout -subject 2>/dev/null \
        | grep -oE 'CN=[^,/]+' | cut -d'=' -f2 || echo "")

    log_info "  Cert referencia — FP: ${main_fp:0:20}... CN: $main_cn Serial: $main_serial"

    compare_ssl() {
        local ip="$1" port="$2"
        local fp serial
        fp=$(echo Q | openssl s_client -connect "${ip}:${port}" \
            -servername "$TARGET" -timeout "$TIMEOUT_SSL" 2>/dev/null \
            | openssl x509 -fingerprint -sha256 -noout 2>/dev/null \
            | cut -d'=' -f2 || echo "")
        serial=$(echo Q | openssl s_client -connect "${ip}:${port}" \
            -servername "$TARGET" -timeout "$TIMEOUT_SSL" 2>/dev/null \
            | openssl x509 -serial -noout 2>/dev/null \
            | cut -d'=' -f2 || echo "")

        [ -z "$fp" ] && return

        if [ -n "$main_fp" ] && [ "$fp" = "$main_fp" ]; then
            log_match "SSL FP EXACTO: ${ip}:${port}" | tee -a "$ssl_matches"
        elif [ -n "$main_serial" ] && [ "$serial" = "$main_serial" ]; then
            log_match "SSL SERIAL MATCH: ${ip}:${port}" | tee -a "$ssl_matches"
        fi
    }

    while IFS= read -r ip; do
        for port in 443 8443 4443; do
            compare_ssl "$ip" "$port"
        done
    done < "$candidates"
    log_ok "SSL matches: $(count_lines "$ssl_matches")"

    # 3.2 — HTTP Fingerprinting con httpx ─────────────────────────────────────
    log_info "[3.2] HTTP Fingerprinting (httpx)..."
    if has_cmd httpx; then
        # Preparar lista de URLs con host header
        while IFS= read -r ip; do
            for port in 80 443 8080 8443; do
                local proto="http"; [[ "$port" == *"443"* ]] && proto="https"
                echo "${proto}://${ip}:${port}"
            done
        done < "$candidates" > /tmp/oh_httpx_targets.txt

        httpx -l /tmp/oh_httpx_targets.txt \
            -H "Host: $TARGET" \
            -title -tech-detect -status-code \
            -content-length \
            -hash mmh3 \
            -jarm \
            -follow-redirects=false \
            -silent -timeout 8 \
            -threads "$THREADS" \
            -json \
            -o "$OUTPUT_DIR/03_fingerprinting/httpx_results.json" 2>/dev/null || true

        log_ok "httpx scan completado: $(count_lines "$OUTPUT_DIR/03_fingerprinting/httpx_results.json") resultados"
        rm -f /tmp/oh_httpx_targets.txt
    else
        log_warn "httpx no disponible, usando curl para HTTP probe"
        while IFS= read -r ip; do
            for port in 80 443 8080 8443; do
                local proto="http"; [[ "$port" == *"443"* ]] && proto="https"
                local resp
                resp=$(curl -sk -m "$TIMEOUT_CURL" -I \
                    -H "Host: $TARGET" \
                    "${proto}://${ip}:${port}" 2>/dev/null | head -5)
                [ -n "$resp" ] && echo "${ip}:${port} | ${resp}" \
                    >> "$OUTPUT_DIR/03_fingerprinting/curl_http.txt"
            done
        done < "$candidates"
    fi

    # 3.3 — JARM Hash Correlation ─────────────────────────────────────────────
    log_info "[3.3] JARM Correlation..."
    if [ -s "$OUTPUT_DIR/03_fingerprinting/httpx_results.json" ]; then
        local main_jarm
        main_jarm=$(jq -r 'select(.jarm != null and .jarm != "") | .jarm' \
            "$OUTPUT_DIR/03_fingerprinting/httpx_results.json" 2>/dev/null \
            | sort | uniq -c | sort -rn | head -1 | awk '{print $2}' || echo "")

        if [ -n "$main_jarm" ]; then
            log_info "  JARM referencia: $main_jarm"
            jq -r "select(.jarm == \"$main_jarm\") | \"\\(.host // .ip):  jarm=\\(.jarm) status=\\(.status_code)\"" \
                "$OUTPUT_DIR/03_fingerprinting/httpx_results.json" 2>/dev/null \
                | tee "$OUTPUT_DIR/03_fingerprinting/jarm_matches.txt" || true
            log_ok "JARM matches: $(count_lines "$OUTPUT_DIR/03_fingerprinting/jarm_matches.txt")"

            # Buscar en Shodan por JARM
            if has_key "SHODAN" && has_cmd shodan; then
                shodan search "jarm:$main_jarm" \
                    --fields ip_str,port,hostnames --separator "|" 2>/dev/null \
                    | grep -v "$TARGET" \
                    >> "$OUTPUT_DIR/03_fingerprinting/shodan_jarm.txt" || true
                log_ok "Shodan JARM: $(count_lines "$OUTPUT_DIR/03_fingerprinting/shodan_jarm.txt") resultados"
            fi
        fi
    fi

    # 3.4 — Content Hash Comparison (MMH3 / MD5 fallback) ────────────────────
    log_info "[3.4] Content Hash Comparison..."
    local main_hash
    main_hash=$(curl -skL -m 10 "https://$TARGET" 2>/dev/null | md5sum | cut -d' ' -f1)
    local content_matches="$OUTPUT_DIR/03_fingerprinting/content_matches.txt"
    touch "$content_matches"

    if [ -n "$main_hash" ]; then
        log_info "  Hash referencia (md5): $main_hash"
        while IFS= read -r ip; do
            for port in 80 443 8080 8443; do
                local proto="http"; [[ "$port" == *"443"* ]] && proto="https"
                local h
                h=$(curl -sk -m "$TIMEOUT_CURL" \
                    -H "Host: $TARGET" \
                    "${proto}://${ip}:${port}" 2>/dev/null | md5sum | cut -d' ' -f1)
                if [ -n "$h" ] && [ "$h" = "$main_hash" ]; then
                    log_match "CONTENT HASH: ${proto}://${ip}:${port}" | tee -a "$content_matches"
                fi
            done
        done < "$candidates"
    fi

    # 3.5 — HTTP Response Header Fingerprint ──────────────────────────────────
    log_info "[3.5] HTTP Response Header Fingerprinting..."
    # Obtener headers del sitio real como referencia
    local ref_headers="$OUTPUT_DIR/03_fingerprinting/ref_headers.txt"
    curl -skI -m 10 "https://$TARGET" 2>/dev/null | grep -iE \
        "^Server:|^X-Powered-By:|^X-Generator:|^X-App|^X-Frame|^Strict-Transport|^X-Content" \
        | sort > "$ref_headers" || touch "$ref_headers"

    local header_matches="$OUTPUT_DIR/03_fingerprinting/header_matches.txt"
    touch "$header_matches"

    while IFS= read -r ip; do
        local cand_headers
        cand_headers=$(curl -skI -m "$TIMEOUT_CURL" \
            -H "Host: $TARGET" "https://$ip" 2>/dev/null \
            | grep -iE "^Server:|^X-Powered-By:|^X-Generator:|^X-App" | sort)
        if [ -n "$cand_headers" ] && [ "$cand_headers" = "$(cat "$ref_headers")" ]; then
            log_match "HEADERS MATCH: $ip" | tee -a "$header_matches"
        fi
    done < "$candidates"
}

# ─── FASE 4: VERIFICACIÓN Y VALIDACIÓN ───────────────────────────────────────
phase4_verification() {
    log_phase "FASE 4: Verificación y Validación"

    # Construir lista de candidatos consolidada de todas las fases
    local consolidated="$OUTPUT_DIR/04_verification/candidates_consolidated.txt"
    {
        cat "$OUTPUT_DIR/03_fingerprinting/ssl_matches.txt" 2>/dev/null
        cat "$OUTPUT_DIR/03_fingerprinting/content_matches.txt" 2>/dev/null
        cat "$OUTPUT_DIR/03_fingerprinting/header_matches.txt" 2>/dev/null
        cat "$OUTPUT_DIR/03_fingerprinting/jarm_matches.txt" 2>/dev/null
    } | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sort -u > "$consolidated"

    # Si no hay candidatos de fingerprinting, usar todas las no-CDN
    if [ ! -s "$consolidated" ]; then
        log_warn "Sin candidatos de fingerprinting, expandiendo a todas las IPs no-CDN"
        cp "$OUTPUT_DIR/02_enumeration/non_cdn_ips.txt" "$consolidated" 2>/dev/null || true
    fi

    log_info "Candidatos consolidados para verificación: $(count_lines "$consolidated")"

    local verified="$OUTPUT_DIR/04_verification/verified_origins.txt"
    touch "$verified"

    # 4.1 — Scoring system ────────────────────────────────────────────────────
    log_info "[4.1] Sistema de scoring multi-criterio..."

    verify_ip() {
        local ip="$1"
        local score=0
        local evidence=()

        # ── Criterio 1: HTTP 200/30x con Host header correcto ──
        local status
        status=$(curl -sk -m "$TIMEOUT_CURL" \
            -H "Host: $TARGET" \
            -o /dev/null -w "%{http_code}" \
            "https://$ip" 2>/dev/null || echo "000")
        if [[ "$status" =~ ^(200|301|302|304|307|308)$ ]]; then
            ((score++)); evidence+=("HTTP:$status")
        fi

        # ── Criterio 2: Certificado SSL válido para el dominio ──
        local cn
        cn=$(echo Q | openssl s_client -connect "${ip}:443" \
            -servername "$TARGET" -timeout "$TIMEOUT_SSL" 2>/dev/null \
            | openssl x509 -noout -subject 2>/dev/null \
            | grep -oE 'CN=[^,/]+' | cut -d'=' -f2 || echo "")
        if echo "$cn" | grep -qi "${TARGET}$"; then
            ((score++)); evidence+=("SSL_CN:$cn")
        fi

        # ── Criterio 3: Contenido HTML contiene dominio o título ──
        local body
        body=$(curl -sk -m "$TIMEOUT_CURL" \
            -H "Host: $TARGET" "https://$ip" 2>/dev/null)
        if echo "$body" | grep -qi "$TARGET"; then
            ((score++)); evidence+=("CONTENT_MATCH")
        fi

        # ── Criterio 4: NO redirige al CDN ──
        local location
        location=$(curl -sk -m "$TIMEOUT_CURL" -I \
            -H "Host: $TARGET" "https://$ip" 2>/dev/null \
            | grep -i "^location:" | tr -d '\r')
        if ! echo "$location" | grep -qi "cloudflare\|cloudfront\|akamai\|fastly\|sucuri\|incapsula"; then
            ((score++)); evidence+=("NO_CDN_REDIRECT")
        fi

        # ── Criterio 5: Server header NO es CDN edge ──
        local server_hdr
        server_hdr=$(curl -sk -m "$TIMEOUT_CURL" -I \
            -H "Host: $TARGET" "https://$ip" 2>/dev/null \
            | grep -i "^server:" | tr -d '\r')
        if [ -n "$server_hdr" ] && ! echo "$server_hdr" | grep -qi "cloudflare\|CloudFront\|AkamaiGHost\|Sucuri"; then
            ((score++)); evidence+=("SERVER:$(echo "$server_hdr" | awk '{print $2}')")
        fi

        # ── Criterio 6: SSL fingerprint idéntico al de referencia ──
        if grep -qF "$ip" "$OUTPUT_DIR/03_fingerprinting/ssl_matches.txt" 2>/dev/null; then
            ((score++)); evidence+=("SSL_FP_MATCH")
        fi

        # ── Criterio 7: Content hash idéntico ──
        if grep -qF "$ip" "$OUTPUT_DIR/03_fingerprinting/content_matches.txt" 2>/dev/null; then
            ((score++)); evidence+=("CONTENT_HASH_MATCH")
        fi

        # ── Resultado ──
        local ev_str; ev_str=$(IFS=','; echo "${evidence[*]}")
        if [ "$score" -ge "$SCORE_THRESHOLD" ]; then
            echo "$ip | score=$score/7 | $ev_str"
            echo "$ip | score=$score/7 | $ev_str" >> "$verified"
            log_match "ORIGEN CONFIRMADO (score $score/7): $ip ← $ev_str"
        elif [ "$score" -ge 2 ]; then
            echo "$ip | score=$score/7 | $ev_str (investigar manualmente)" \
                >> "$OUTPUT_DIR/04_verification/low_score.txt"
            log_warn "Posible origen bajo confidence (score $score/7): $ip"
        fi
    }

    while IFS= read -r ip; do
        verify_ip "$ip"
    done < "$consolidated"

    log_ok "IPs verificadas como origen: $(count_lines "$verified")"
}

# ─── FASE 5: REPORTE ──────────────────────────────────────────────────────────
phase5_report() {
    log_phase "FASE 5: Reporte Final"

    local report="$OUTPUT_DIR/reports/origin_hunter_report.md"

    cat > "$report" << REPEOF
#  Origin Hunter Report

| Campo | Valor |
|-------|-------|
| **Target** | $TARGET |
| **Fecha** | $(date) |
| **Herramienta** | Origin Hunter v2.0 |

---

##  Estadísticas

| Métrica | Cantidad |
|---------|----------|
| Subdominios encontrados | $(count_lines "$OUTPUT_DIR/02_enumeration/all_subs.txt") |
| IPs resueltas (total) | $(count_lines "$OUTPUT_DIR/02_enumeration/all_ips_raw.txt") |
| IPs identificadas como CDN | $(count_lines "$OUTPUT_DIR/02_enumeration/cdn_ips.txt") |
| IPs candidatas (no CDN) | $(count_lines "$OUTPUT_DIR/02_enumeration/non_cdn_ips.txt") |
| Matches SSL | $(count_lines "$OUTPUT_DIR/03_fingerprinting/ssl_matches.txt") |
| Matches Content | $(count_lines "$OUTPUT_DIR/03_fingerprinting/content_matches.txt") |
| **IPs Origen Verificadas** | **$(count_lines "$OUTPUT_DIR/04_verification/verified_origins.txt")** |

---

##  IPs de Origen Confirmadas

REPEOF

    if [ -s "$OUTPUT_DIR/04_verification/verified_origins.txt" ]; then
        echo '```' >> "$report"
        cat "$OUTPUT_DIR/04_verification/verified_origins.txt" >> "$report"
        echo '```' >> "$report"
    else
        echo "_No se encontraron IPs con score suficiente. Ver sección de baja confianza._" >> "$report"
    fi

    cat >> "$report" << 'REPEOF'

---

##  Candidatos de Baja Confianza (Investigar Manualmente)

REPEOF

    if [ -s "$OUTPUT_DIR/04_verification/low_score.txt" ]; then
        echo '```' >> "$report"
        cat "$OUTPUT_DIR/04_verification/low_score.txt" >> "$report"
        echo '```' >> "$report"
    else
        echo "_Ninguno._" >> "$report"
    fi

    cat >> "$report" << REPEOF

---

##  Comandos de Verificación Manual

\`\`\`bash
# Probar IP candidata directamente
curl -sk -H "Host: $TARGET" https://CANDIDATE_IP | head -50

# Verificar certificado SSL
echo Q | openssl s_client -connect CANDIDATE_IP:443 -servername $TARGET 2>/dev/null | openssl x509 -noout -text

# Comparar headers
curl -skI -H "Host: $TARGET" https://CANDIDATE_IP
curl -skI https://$TARGET

# NMAP detallado
nmap -sV -sC -p 443,8443,80,8080 CANDIDATE_IP

# Si tienes Shodan — buscar por JARM hash
shodan search "jarm:JARM_HASH_AQUI"

# Verificar desde otro origen (bypass de GeoBlocking)
curl -sk -H "Host: $TARGET" --interface eth0 https://CANDIDATE_IP
\`\`\`

---

## 📂 Archivos Generados

| Archivo | Descripción |
|---------|-------------|
| \`01_osint/all_osint_ips.txt\` | Todas las IPs de fuentes pasivas |
| \`02_enumeration/non_cdn_ips.txt\` | IPs filtradas (no CDN) |
| \`03_fingerprinting/ssl_matches.txt\` | Matches por certificado SSL |
| \`03_fingerprinting/httpx_results.json\` | Fingerprints HTTP completos |
| \`04_verification/verified_origins.txt\` | Orígenes verificados con score |

REPEOF

    echo ""
    log_ok "Reporte guardado: $report"
    echo ""
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════${NC}"
    echo -e "${BOLD}${GREEN}  RESULTADOS FINALES: $TARGET${NC}"
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════${NC}"
    if [ -s "$OUTPUT_DIR/04_verification/verified_origins.txt" ]; then
        cat "$OUTPUT_DIR/04_verification/verified_origins.txt"
    else
        echo -e "${YELLOW}  No se encontraron orígenes verificados.${NC}"
        echo -e "${YELLOW}  Revisar: $OUTPUT_DIR/04_verification/low_score.txt${NC}"
    fi
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════${NC}"
    echo ""
    echo -e "  Workspace completo: ${CYAN}$OUTPUT_DIR/${NC}"
}

# ─── PROCESAMIENTO MULTI-TARGET ───────────────────────────────────────────────
process_multiple_targets() {
    log_phase "PROCESANDO $TARGETS_COUNT TARGETS"
    
    local results_summary="$OUTPUT_DIR/reports/summary_all_targets.txt"
    local results_json="$OUTPUT_DIR/reports/summary_all_targets.json"
    touch "$results_summary"
    
    # Inicializar JSON
    echo "[" > "$results_json"
    
    local target_num=0
    while IFS= read -r TARGET; do
        # Saltar líneas vacías y comentarios
        [[ -z "$TARGET" || "$TARGET" =~ ^# ]] && continue
        
        # Limpiar espacios
        TARGET=$(echo "$TARGET" | xargs)
        
        ((target_num++))
        
        log_phase "[$target_num/$TARGETS_COUNT] Procesando: $TARGET"
        
        # Crear subdirectorio por target
        local target_dir="$OUTPUT_DIR/targets/${TARGET}"
        mkdir -p "${target_dir}"/{01_osint,02_enumeration,03_fingerprinting,04_verification}
        
        # Ejecutar fases para este target
        phase1_osint_target "$target_dir" "$TARGET"
        phase2_enumeration_target "$target_dir" "$TARGET"
        phase3_fingerprinting_target "$target_dir" "$TARGET"
        phase4_verification_target "$target_dir" "$TARGET"
        
        # Agregar resultado al summary
        local verified_count=0
        [ -f "${target_dir}/04_verification/verified_origins.txt" ] && \
            verified_count=$(wc -l < "${target_dir}/04_verification/verified_origins.txt")
        
        echo "$TARGET | Orígenes encontrados: $verified_count" >> "$results_summary"
        
        # Agregar a JSON (con coma excepto en el último)
        if [ "$target_num" -lt "$TARGETS_COUNT" ]; then
            cat >> "$results_json" << JSONEOF
  {
    "target": "$TARGET",
    "origins_found": $verified_count,
    "results_file": "targets/${TARGET}/04_verification/verified_origins.txt"
  },
JSONEOF
        else
            cat >> "$results_json" << JSONEOF
  {
    "target": "$TARGET",
    "origins_found": $verified_count,
    "results_file": "targets/${TARGET}/04_verification/verified_origins.txt"
  }
JSONEOF
        fi
    done < "$TARGETS_FILE"
    
    # Cerrar JSON
    echo "]" >> "$results_json"
    
    log_ok "Procesamiento completado. Summary: $results_summary"
}

# ─── FASES ADAPTADAS PARA MULTI-TARGET ───────────────────────────────────────
phase1_osint_target() {
    local target_dir="$1"
    local target="$2"
    local osint_ips="${target_dir}/01_osint/all_osint_ips.txt"
    touch "$osint_ips"

    log_info "[1.1] Certificate Transparency (crt.sh) — $target..."
    local crt_raw="${target_dir}/01_osint/crt_raw.json"
    local crt_domains="${target_dir}/01_osint/crt_domains.txt"
    local crt_ips="${target_dir}/01_osint/crt_ips.txt"

    {
        curl -s --retry 3 --retry-delay 2 "https://crt.sh/?q=%25.${target}&output=json" 2>/dev/null
        curl -s --retry 3 --retry-delay 2 "https://crt.sh/?q=${target}&output=json" 2>/dev/null
    } | jq -r '.[].name_value' 2>/dev/null \
        | sed 's/\*\.//g' | tr ',' '\n' \
        | grep -iE "^[a-z0-9._-]+\.${target}$|^${target}$" \
        | sort -u > "$crt_domains" || true

    grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' "$crt_domains" 2>/dev/null | sort -u > "$crt_ips" || touch "$crt_ips"
    append_unique "$crt_ips" "$osint_ips"
    log_ok "  crt.sh: $(count_lines "$crt_domains") dominios"

    log_info "[1.2] SecurityTrails — $target..."
    local st_ips="${target_dir}/01_osint/securitytrails_ips.txt"
    touch "$st_ips"
    if has_key "SECURITY_TRAILS"; then
        local ST_KEY; ST_KEY=$(get_key "SECURITY_TRAILS")
        curl -s --retry 2 "https://api.securitytrails.com/v1/domain/${target}/history/a" \
            -H "APIKEY: $ST_KEY" 2>/dev/null \
            | jq -r '.records[].values[]?.ip // empty' 2>/dev/null \
            | sort -u > "$st_ips" || true
        append_unique "$st_ips" "$osint_ips"
        log_ok "  SecurityTrails: $(count_lines "$st_ips") IPs"
    fi

    log_info "[1.3] VirusTotal — $target..."
    local vt_ips="${target_dir}/01_osint/virustotal_ips.txt"
    touch "$vt_ips"
    if has_key "VIRUSTOTAL"; then
        local VT_KEY; VT_KEY=$(get_key "VIRUSTOTAL")
        curl -s "https://www.virustotal.com/api/v3/domains/${target}/resolutions?limit=40" \
            -H "x-apikey: $VT_KEY" 2>/dev/null \
            | jq -r '.data[].attributes.ip_address // empty' 2>/dev/null \
            | sort -u > "$vt_ips" || true
        append_unique "$vt_ips" "$osint_ips"
        log_ok "  VirusTotal: $(count_lines "$vt_ips") IPs"
    fi

    log_info "[1.4] Wayback Machine — $target..."
    local wb_ips="${target_dir}/01_osint/wayback_ips.txt"
    curl -s --max-time 30 \
        "http://web.archive.org/cdx/search/cdx?url=*.${target}/*&output=text&fl=original&collapse=urlkey&limit=50000" \
        2>/dev/null \
        | grep -oE 'https?://[0-9]{1,3}(\.[0-9]{1,3}){3}' \
        | sed 's|https\?://||' \
        | sort -u > "$wb_ips" || touch "$wb_ips"
    append_unique "$wb_ips" "$osint_ips"
    log_ok "  Wayback: $(count_lines "$wb_ips") IPs"
}

phase2_enumeration_target() {
    local target_dir="$1"
    local target="$2"
    
    log_info "[2.1] Enumeración de subdominios — $target..."
    local subs_file="${target_dir}/02_enumeration/all_subs.txt"
    touch "$subs_file"

    if has_cmd subfinder; then
        subfinder -d "$target" -silent -recursive -all \
            -o "${target_dir}/02_enumeration/subfinder.txt" 2>/dev/null || true
        append_unique "${target_dir}/02_enumeration/subfinder.txt" "$subs_file"
    fi

    if has_cmd amass; then
        timeout 120 amass enum -passive -norecursive -d "$target" \
            -o "${target_dir}/02_enumeration/amass.txt" 2>/dev/null || true
        append_unique "${target_dir}/02_enumeration/amass.txt" "$subs_file"
    fi

    sort -u "$subs_file" -o "$subs_file"
    log_ok "  Subdominios encontrados: $(count_lines "$subs_file")"

    log_info "[2.2] Resolución DNS — $target..."
    local resolved_file="${target_dir}/02_enumeration/resolved_all.txt"
    local all_ips_raw="${target_dir}/02_enumeration/all_ips_raw.txt"

    if has_cmd dnsx; then
        dnsx -l "$subs_file" -resp -a -aaaa -cname \
            -silent -t "$THREADS" \
            -o "$resolved_file" 2>/dev/null || true
    else
        while IFS= read -r sub; do
            local r; r=$(dig +short A "$sub" 2>/dev/null)
            [ -n "$r" ] && echo "$sub [$r]"
        done < "$subs_file" > "$resolved_file" || true
    fi

    grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' "$resolved_file" | sort -u > "$all_ips_raw"
    log_ok "  IPs resueltas: $(count_lines "$all_ips_raw")"

    log_info "[2.3] Filtrando rangos CDN — $target..."
    local non_cdn_ips="${target_dir}/02_enumeration/non_cdn_ips.txt"
    touch "$non_cdn_ips"

    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        if is_cdn_ip "$ip"; then
            :
        else
            echo "$ip" >> "$non_cdn_ips"
        fi
    done < "$all_ips_raw"

    sort -u "$non_cdn_ips" -o "$non_cdn_ips"
    log_ok "  IPs no-CDN: $(count_lines "$non_cdn_ips")"
}

phase3_fingerprinting_target() {
    local target_dir="$1"
    local target="$2"
    
    local candidates="${target_dir}/02_enumeration/non_cdn_ips.txt"
    [ ! -s "$candidates" ] && return

    log_info "[3.1] SSL Fingerprinting — $target..."
    local ssl_matches="${target_dir}/03_fingerprinting/ssl_matches.txt"
    touch "$ssl_matches"

    local main_fp main_cn
    main_fp=$(echo Q | openssl s_client -connect "${target}:443" \
        -servername "$target" -timeout "$TIMEOUT_SSL" 2>/dev/null \
        | openssl x509 -fingerprint -sha256 -noout 2>/dev/null \
        | cut -d'=' -f2 || echo "")
    main_cn=$(echo Q | openssl s_client -connect "${target}:443" \
        -servername "$target" -timeout "$TIMEOUT_SSL" 2>/dev/null \
        | openssl x509 -noout -subject 2>/dev/null \
        | grep -oE 'CN=[^,/]+' | cut -d'=' -f2 || echo "")

    [ -n "$main_fp" ] && log_info "  SSL FP ref: ${main_fp:0:20}... CN: $main_cn"

    while IFS= read -r ip; do
        local fp
        fp=$(echo Q | openssl s_client -connect "${ip}:443" \
            -servername "$target" -timeout "$TIMEOUT_SSL" 2>/dev/null \
            | openssl x509 -fingerprint -sha256 -noout 2>/dev/null \
            | cut -d'=' -f2 || echo "")
        
        if [ -n "$fp" ] && [ "$fp" = "$main_fp" ]; then
            echo "$ip" >> "$ssl_matches"
        fi
    done < "$candidates"

    log_ok "  SSL matches: $(count_lines "$ssl_matches")"
}

phase4_verification_target() {
    local target_dir="$1"
    local target="$2"
    
    local consolidated="${target_dir}/04_verification/candidates_consolidated.txt"
    [ -f "${target_dir}/03_fingerprinting/ssl_matches.txt" ] && \
        cp "${target_dir}/03_fingerprinting/ssl_matches.txt" "$consolidated" || \
        cp "${target_dir}/02_enumeration/non_cdn_ips.txt" "$consolidated"

    local verified="${target_dir}/04_verification/verified_origins.txt"
    touch "$verified"

    log_info "[4.1] Verificación de candidatos — $target..."

    while IFS= read -r ip; do
        local score=0
        local status
        status=$(curl -sk -m "$TIMEOUT_CURL" \
            -H "Host: $target" \
            -o /dev/null -w "%{http_code}" \
            "https://$ip" 2>/dev/null || echo "000")
        
        [[ "$status" =~ ^(200|301|302|304|307|308)$ ]] && score=$((score + 1))


        local cn
        cn=$(echo Q | openssl s_client -connect "${ip}:443" \
            -servername "$target" -timeout "$TIMEOUT_SSL" 2>/dev/null \
            | openssl x509 -noout -subject 2>/dev/null \
            | grep -oE 'CN=[^,/]+' | cut -d'=' -f2 || echo "")
        echo "$cn" | grep -qi "${target}$" && score=$((score + 1))

        if [ "$score" -ge "$SCORE_THRESHOLD" ]; then
            echo "$ip | score=$score/7 | HTTP:$status CN:$cn" >> "$verified"
        fi
    done < "$consolidated"

    log_ok "  Orígenes verificados: $(count_lines "$verified")"
}

# ─── MAIN ─────────────────────────────────────────────────────────────────────
main() {
    echo ""
    echo -e "${BOLD}${CYAN}  ╔═══════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}  ║    ORIGIN HUNTER v2.0             ║${NC}"
    echo -e "${BOLD}${CYAN}  ║    Multi-Target Version           ║${NC}"
    echo -e "${BOLD}${CYAN}  ║    Real IP Discovery — Bug Bounty ║${NC}"
    echo -e "${BOLD}${CYAN}  ╚═══════════════════════════════════╝${NC}"
    echo -e "  Targets: ${BOLD}$TARGETS_COUNT dominios${NC}  |  Threads: $THREADS"
    echo ""

    phase0_setup
    process_multiple_targets
    phase5_report_multi
}

# ─── REPORTE MULTI-TARGET ─────────────────────────────────────────────────────
phase5_report_multi() {
    log_phase "FASE 5: Reporte Final Consolidado"

    local report="$OUTPUT_DIR/reports/RESULTADOS_FINALES.md"

    cat > "$report" << REPEOF
#  Origin Hunter — Reporte Multi-Target

**Fecha:** $(date)  
**Targets procesados:** $TARGETS_COUNT dominios  
**Herramienta:** Origin Hunter v2.0

---

##  Resumen Ejecutivo

\`\`\`
REPEOF

    cat "$OUTPUT_DIR/reports/summary_all_targets.txt" >> "$report"

    cat >> "$report" << 'REPEOF'
\`\`\`

---

## Resultados por Target

REPEOF

    while IFS= read -r TARGET; do
        [[ -z "$TARGET" || "$TARGET" =~ ^# ]] && continue
        TARGET=$(echo "$TARGET" | xargs)
        
        local target_dir="$OUTPUT_DIR/targets/${TARGET}"
        local verified="${target_dir}/04_verification/verified_origins.txt"
        
        if [ -f "$verified" ] && [ -s "$verified" ]; then
            echo "" >> "$report"
            echo "###  ${TARGET}" >> "$report"
            echo "" >> "$report"
            echo '```' >> "$report"
            cat "$verified" >> "$report"
            echo '```' >> "$report"
        fi
    done < "$TARGETS_FILE"

    cat >> "$report" << REPEOF

---

##  Estructura de Resultados

\`\`\`
$OUTPUT_DIR/
├── targets/
│   ├── domain1.com/
│   │   ├── 01_osint/
│   │   ├── 02_enumeration/
│   │   ├── 03_fingerprinting/
│   │   └── 04_verification/
│   ├── domain2.com/
│   └── ...
├── reports/
│   ├── RESULTADOS_FINALES.md
│   ├── summary_all_targets.txt
│   ├── summary_all_targets.json
│   └── run_info.txt
└── cdn_ranges.txt
\`\`\`

REPEOF

    echo ""
    log_ok "Reporte guardado: $report"
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════${NC}"
    echo -e "${BOLD}${GREEN}  PROCESAMIENTO COMPLETADO${NC}"
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════${NC}"
    echo ""
    echo -e "  Workspace: ${CYAN}$OUTPUT_DIR/${NC}"
    echo -e "  Reporte: ${CYAN}$OUTPUT_DIR/reports/RESULTADOS_FINALES.md${NC}"
}

main "$@"
