#!/usr/bin/env bash
#===============================================================================
# CDN_FILTER_REPORT.sh — Extrae subdominios SIN CDN + IPs de origen reales
# Uso: bash cdn_filter_report.sh httpx_output.json
#===============================================================================
set -uo pipefail

JSON_FILE="${1:-httpx_output.json}"
OUTPUT_DIR="cdn_filter_$(date +%Y%m%d_%H%M%S)"

# Verificar archivo
[[ ! -f "$JSON_FILE" ]] && { echo "✗ Archivo no encontrado: $JSON_FILE"; exit 1; }

mkdir -p "$OUTPUT_DIR"
echo " Analizando: $JSON_FILE"
echo " Output: $OUTPUT_DIR/"
echo ""

# ── EXTRAER DATOS CON JQ (todo en una pasada) ────────────────────────────────
jq -r '
  # Filtrar solo entradas SIN CDN (cdn_name null, vacío o ausente)
  select(.cdn_name == null or .cdn_name == "" or .cdn_name == false) |
  
  # Extraer campos relevantes
  {
    url: .url,
    ip: .host_ip,
    title: (.title // "N/A"),
    server: (.webserver // .server // "N/A"),
    status: (.status_code // "N/A"),
    tech: (.tech // .technologies // [] | join(",")),
    is_login: (.title // "" | test("login|admin|dashboard|panel|auth|sign.?in|console"; "i")),
    is_api: (.url | test("/api|/v[0-9]|/graphql|swagger"; "i")),
    is_private_ip: (.host_ip | test("^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)"))
  }
' "$JSON_FILE" 2>/dev/null | jq -s '.' > "${OUTPUT_DIR}/filtered_data.json"

# ── GENERAR ARCHIVOS DE SALIDA ───────────────────────────────────────────────

# 1. Lista completa de hosts sin CDN (TSV legible)
jq -r '.[] | [.url, .ip, .title, .server, .status, .is_login, .is_api, .is_private_ip] | @tsv' \
  "${OUTPUT_DIR}/filtered_data.json" | \
  column -t -s $'\t' > "${OUTPUT_DIR}/no_cdn_hosts.tsv"

# 2. Solo URLs sin CDN (para usar con otras herramientas)
jq -r '.[].url' "${OUTPUT_DIR}/filtered_data.json" | sort -u > "${OUTPUT_DIR}/no_cdn_hosts.txt"

# 3. IPs únicas sin CDN
jq -r '.[].ip' "${OUTPUT_DIR}/filtered_data.json" | grep -v '^$' | sort -u > "${OUTPUT_DIR}/no_cdn_ips.txt"

# 4. IPs privadas (RFC1918 leak) — ¡CRÍTICO!
jq -r '.[] | select(.is_private_ip == true) | "\(.ip)\t\(.url)\t\(.title)"' \
  "${OUTPUT_DIR}/filtered_data.json" | sort -u > "${OUTPUT_DIR}/private_ips_leak.txt"

# 5. Paneles de login/admin sin CDN — ¡ALTA PRIORIDAD!
jq -r '.[] | select(.is_login == true) | "\(.url)\t\(.ip)\t\(.title)\t\(.server)"' \
  "${OUTPUT_DIR}/filtered_data.json" | sort -u > "${OUTPUT_DIR}/login_panels_no_cdn.txt"

# 6. APIs expuestas sin CDN
jq -r '.[] | select(.is_api == true) | "\(.url)\t\(.ip)\t\(.status)"' \
  "${OUTPUT_DIR}/filtered_data.json" | sort -u > "${OUTPUT_DIR}/api_endpoints_no_cdn.txt"

# ── REPORTE RESUMEN EN CONSOLA ───────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════════"
echo " RESUMEN DE HALLAZGOS — Subdominios SIN CDN"
echo "═══════════════════════════════════════════════════════════"

total=$(jq 'length' "${OUTPUT_DIR}/filtered_data.json")
logins=$(jq '[.[] | select(.is_login == true)] | length' "${OUTPUT_DIR}/filtered_data.json")
apis=$(jq '[.[] | select(.is_api == true)] | length' "${OUTPUT_DIR}/filtered_data.json")
private=$(jq '[.[] | select(.is_private_ip == true)] | length' "${OUTPUT_DIR}/filtered_data.json")
unique_ips=$(wc -l < "${OUTPUT_DIR}/no_cdn_ips.txt")

echo "  Total hosts sin CDN:        $total"
echo "  IPs únicas sin CDN:         $unique_ips"
echo "  ─────────────────────────────────────"
echo "   Login/Admin panels:      $logins  ← ¡ALTA PRIORIDAD!"
echo "   API endpoints:           $apis"
echo "   IPs privadas (leak):     $private ← ¡CRÍTICO!"
echo ""

# ── ALERTAS CRÍTICAS ─────────────────────────────────────────────────────────
if [[ $private -gt 0 ]]; then
  echo -e " ${RED}ALERTA: IPs privadas detectadas (posible DNS leak)${NC}"
  echo "   Revisar: ${OUTPUT_DIR}/private_ips_leak.txt"
  echo ""
fi

if [[ $logins -gt 0 ]]; then
  echo -e " ${RED}ALERTA: Paneles de login sin protección CDN${NC}"
  echo "   Revisar: ${OUTPUT_DIR}/login_panels_no_cdn.txt"
  echo ""
fi

# ── TOP 10 MÁS INTERESANTES (por score manual) ───────────────────────────────
echo " TOP 10 HOSTS SIN CDN — Más interesantes para investigar:"
echo "═══════════════════════════════════════════════════════════"

jq -r '
  .[] | 
  # Score manual: login=3, api=2, private_ip=5, status 200=1
  (if .is_login then 3 else 0 end) +
  (if .is_api then 2 else 0 end) +
  (if .is_private_ip then 5 else 0 end) +
  (if .status == 200 then 1 else 0 end) as $score |
  "\($score)\t\(.url)\t\(.ip)\t\(.title)\t\(.server)"
' "${OUTPUT_DIR}/filtered_data.json" | \
  sort -t$'\t' -k1 -rn | head -10 | \
  cut -f2- | \
  column -t -s $'\t'

echo ""
echo "═══════════════════════════════════════════════════════════"
echo " Archivos generados en: ${OUTPUT_DIR}/"
echo ""
echo "  • no_cdn_hosts.tsv          → Lista completa legible"
echo "  • no_cdn_hosts.txt          → Solo URLs (para herramientas)"
echo "  • no_cdn_ips.txt            → IPs únicas sin CDN"
echo "  • private_ips_leak.txt      →  IPs RFC1918 (CRÍTICO)"
echo "  • login_panels_no_cdn.txt   →  Login/Admin sin CDN"
echo "  • api_endpoints_no_cdn.txt  →  APIs expuestas"
echo "  • filtered_data.json        → Datos completos en JSON"
echo ""
echo " Próximos pasos:"
echo "  1. Revisar IPs privadas: cat ${OUTPUT_DIR}/private_ips_leak.txt"
echo "  2. Probar logins: cat ${OUTPUT_DIR}/login_panels_no_cdn.txt | cut -f1 | head -5 | xargs -I{} curl -sk {}"
echo "  3. Escanear IPs: nmap -sV -iL ${OUTPUT_DIR}/no_cdn_ips.txt"
echo "═══════════════════════════════════════════════════════════"