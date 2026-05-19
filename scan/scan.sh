
#!/bin/bash

# ------------------------------------------------------------
# Script de reconocimiento ITZKOATL v2.5 (robusto)
# ------------------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SUBDOMAINS_FILE="subdominios.txt"
HTTPX_JSON="httpx_results.json"
FREE_HOSTS="FreeHosts.txt"
IPS_FILE="IPs.txt"
PORTS_FILE="puertos_abiertos.txt"

# Verificar herramientas
echo -e "${YELLOW}[*] Verificando dependencias...${NC}"
for tool in subfinder httpx jq naabu nmap; do
    if ! command -v $tool &> /dev/null; then
        echo -e "${RED}[!] $tool no está instalado.${NC}"
        exit 1
    fi
done

# Entrada: archivo con dominios (scope.txt)
echo -e "${YELLOW}[*] Introduce el nombre del archivo de scope (ej: scope.txt):${NC}"
read -r domain_file

# Validación estricta
if [ -z "$domain_file" ]; then
    echo -e "${RED}[!] No ingresaste ningún nombre de archivo.${NC}"
    exit 1
fi

if [ ! -f "$domain_file" ]; then
    echo -e "${RED}[!] El archivo '$domain_file' no existe.${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Usando archivo: $domain_file${NC}"

# 1. Recolección con subfinder
echo -e "${YELLOW}[1/4] Buscando subdominios...${NC}"
subfinder -dL "$domain_file" -silent > "$SUBDOMAINS_FILE"
sub_count=$(wc -l < "$SUBDOMAINS_FILE" 2>/dev/null || echo "0")
# Asegurar que sea número
sub_count=${sub_count:-0}
echo -e "${GREEN}[+] $sub_count subdominios encontrados.${NC}"

if [ "$sub_count" -eq 0 ]; then
    echo -e "${RED}[!] No se encontraron subdominios. Saliendo.${NC}"
    exit 1
fi

# 2. Validación HTTP con httpx
echo -e "${YELLOW}[2/4] Validando servicios y detectando WAF...${NC}"
cat "$SUBDOMAINS_FILE" | httpx -json -ip -server -status-code -silent -fc 404 > "$HTTPX_JSON"

# Verificar que el JSON no esté vacío
if [ ! -s "$HTTPX_JSON" ]; then
    echo -e "${RED}[!] El archivo $HTTPX_JSON está vacío. No hay resultados de httpx.${NC}"
    exit 1
fi

# 3. Filtro de Oro
echo -e "${YELLOW}[3/4] Aplicando Filtro de Oro (sin Cloudflare ni Akamai)...${NC}"

jq -r 'select(
    (.webserver // "" | ascii_downcase | contains("cloudflare") | not) and
    (.webserver // "" | ascii_downcase | contains("akamai") | not) and
    (.cdn_name // "" | ascii_downcase | contains("akamai") | not)
) | select(.host_ip != null) | "\(.url) -> \(.host_ip)"' "$HTTPX_JSON" > "$FREE_HOSTS"

jq -r 'select(
    (.webserver // "" | ascii_downcase | contains("cloudflare") | not) and
    (.webserver // "" | ascii_downcase | contains("akamai") | not) and
    (.cdn_name // "" | ascii_downcase | contains("akamai") | not)
) | select(.host_ip != null) | .host_ip' "$HTTPX_JSON" | sort -u > "$IPS_FILE"

golden_count=$(wc -l < "$IPS_FILE" 2>/dev/null | tr -d ' ')
golden_count=${golden_count:-0}
echo -e "${GREEN}[+] $golden_count IPs únicas pasan el filtro.${NC}"

if [ "$golden_count" -eq 0 ]; then
    echo -e "${RED}[!] No hay IPs sin Cloudflare ni Akamai. Saliendo.${NC}"
    exit 1
fi

# 4. Escaneo de puertos
echo -e "${YELLOW}[4/4] Escaneando puertos top 100 con naabu...${NC}"
naabu -list "$IPS_FILE" -top-ports 100 -rate 500 -silent -verify -o "$PORTS_FILE" 2>/dev/null
ports_count=$(wc -l < "$PORTS_FILE" 2>/dev/null | tr -d ' ')
ports_count=${ports_count:-0}
echo -e "${GREEN}[+] $ports_count puertos abiertos encontrados.${NC}"

if [ "$ports_count" -gt 0 ]; then
    echo -e "${YELLOW}[4/4] Detectando servicios con nmap...${NC}"
    puertos=$(cut -d':' -f2 "$PORTS_FILE" | sort -u | tr '\n' ',' | sed 's/,$//')
    nmap -sV -T4 -iL "$IPS_FILE" -p "$puertos" -oN nmap_scan.txt 2>/dev/null
    echo -e "${GREEN}[+] Service discovery completado. Resultados en nmap_scan.xml${NC}"
fi

# Resumen
echo -e "\n${YELLOW}===== RESULTADOS ITZKOATL v2.5 ====${NC}"
echo -e "Archivo de scope: $domain_file"
echo -e "Subdominios totales: $sub_count"
echo -e "IPs únicas sin Cloudflare ni Akamai: $golden_count"
if [ "$ports_count" -gt 0 ]; then
    echo -e "\n${YELLOW}Primeros 10 puertos abiertos:${NC}"
    head -10 "$PORTS_FILE"
fi

echo -e "\n${GREEN}[✓] Archivos generados: $SUBDOMAINS_FILE, $HTTPX_JSON, $FREE_HOSTS, $IPS_FILE, $PORTS_FILE, nmap_scan.txt${NC}"
