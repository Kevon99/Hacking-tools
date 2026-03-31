#  DXt MINER

> **High-Performance Data Mining Engine for Security Auditing** > Procesa archivos masivos (+10GB) buscando fugas de datos con un consumo de RAM insignificante y una estética **Dracula Theme**.

![License](https://img.shields.io/badge/license-MIT-purple.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![Theme](https://img.shields.io/badge/theme-Dracula-pink.svg)

---

##  Características Principales

* ** Streaming Engine:** Lectura línea por línea mediante generadores. Procesa millones de registros sin saturar la memoria RAM.
* ** Dual-Search Mode:**
    * **Wordlist Matching:** Búsqueda ultra rápida basada en diccionarios personalizados.
    * **Auto-Recon:** Motor de Regex obligatorio para cazar UUIDs, JWTs, AWS Keys, IPs y Emails de forma automática.
* ** Dracula Visual Identity:** Interfaz CLI profesional con soporte para **True Color (24-bit)**.
* ** Smart Output:** Organización automática de hallazgos en la carpeta `gold/`, separando resultados por diccionario.

---

## 🛠 Instalación

1. Clona el repositorio:
   ```bash
   git clone [https://github.com/tu-usuario/dxt-miner.git](https://github.com/tu-usuario/dxt-miner.git)
   cd dxt-miner


Asegúrate de tener Python 3.8+ instalado. No requiere librerías externas (Standard Library Only).


Modo de Uso

La filosofía de DXt Miner es la simplicidad. Solo necesitas el archivo de datos y tu wordlist.

python3 dxtminer.py -d ruta/al/archivo_gigante.txt -w dicts/mis_secretos.txt


Argumentos:

    -d, --data: Ruta al archivo masivo (logs, URLs, SQL dumps, etc.).

    -w, --wordlist: Diccionario con las palabras clave a buscar.


Estructura de Salida (The Gold Mine)

El script genera automáticamente una jerarquía de carpetas para mantener tus auditorías limpias:

gold/
├── auto_recon_obligatory.txt    # Hallazgos automáticos (UUID, JWT, etc.)
└── [nombre_del_diccionario]/   
    └── matches.txt              # Líneas que coincidieron con tu wordlist


Motor de Auto-Recon

El script busca por defecto los siguientes patrones críticos:

    UUID/GUID: Identificadores únicos de sesiones o usuarios.

    JWT Tokens: JSON Web Tokens (detecta el header eyJ).

    AWS Keys: Credenciales de acceso de Amazon Web Services (AKIA...).

    Emails & IPs: Fugas de PII e infraestructura.

    JS Files: Rutas a archivos JavaScript para descubrimiento de endpoints.


Aviso Legal

Esta herramienta ha sido creada exclusivamente para fines de auditoría de seguridad y ética. El uso de DXta Miner contra objetivos sin consentimiento previo es ilegal. El desarrollador no se hace responsable del mal uso de esta herramienta.
