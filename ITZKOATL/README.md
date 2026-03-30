# 🐍 ITZKOATL — Obsidian Recon Engine


ITZKOATL (Nahuatl: Obsidian Serpent) is a high-performance, automated reconnaissance pipeline designed for Bug Bounty hunters and Security Researchers. Unlike generic tools, ITZKOATL focuses on Smart Prioritization, using Python-based scoring to filter noise and target high-impact attack surfaces.


Key Features

-Parallel Subdomain Discovery: Uses subfinder, assetfinder, and amass simultaneously.

-Intelligent Scoring (M7): Python engine that categorizes endpoints into High Priority, IDOR Candidates, and API endpoints.

-WAF-Aware Execution: Built-in wafw00f detection that suggests Stealth Mode to avoid IP bans.

-Focused Fuzzing: Only performs content discovery (ffuf/feroxbuster) on high-score targets to save bandwidth.

-Multi-Mode Logic: Toggle between --stealth, --normal, and --aggressive depending on the target.


## Installation & Usage

# Clone and enter the directory
git clone https://github.com/youruser/ITZKOATL.git && cd ITZKOATL

# Run the engine
bash recon.sh <project_name> [targets.txt] [out_scope.txt] --normal


## SPANISH

ITZKOATL (Náhuatl: Serpiente de Obsidiana) es un pipeline de reconocimiento automatizado de alto rendimiento diseñado para Bug Bounty hunters y consultores de seguridad. A diferencia de otras herramientas, ITZKOATL se enfoca en la Priorización Inteligente, utilizando un motor de scoring en Python para filtrar el ruido y atacar superficies de alto impacto.

### Características Principales

- Descubrimiento en Paralelo: Ejecuta subfinder, assetfinder y amass al mismo tiempo para máxima velocidad.

- Scoring Inteligente (M7): Motor en Python que clasifica endpoints en: Prioridad Alta, Candidatos a IDOR y Endpoints de API.

- Detección de WAF: Integración con wafw00f que sugiere el modo Stealth para evitar bloqueos de IP.

- Fuzzing Enfocado: Solo realiza descubrimiento de contenido (ffuf/feroxbuster) en objetivos de alto puntaje.

- Lógica Multimodal: Elige entre --stealth, --normal y --aggressive según el objetivo.

# Clonar y entrar al directorio
git clone https://github.com/tuusuario/ITZKOATL.git && cd ITZKOATL

# Ejecutar el motor
bash recon.sh <nombre_proyecto> [targets.txt] [out_scope.txt] --normal



# Disclaimer

This tool is for educational and authorized security testing purposes only. The author is not responsible for any misuse or damage caused by this tool.
