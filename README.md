# Hacking-tools

A collection of custom offensive security tooling focused on **recon automation**, **attack surface analysis** and **data mining** during authorized security assessments and bug bounty research.

Every tool was built to solve a real problem encountered during hands-on engagements — filtering noise, prioritizing high-impact targets and extracting value from massive data dumps.

---

## Tool Index

| Tool | Language | Purpose |
|------|----------|---------|
| [ITZKOATL](ITZKOATL/) | Bash + Python | Automated external reconnaissance pipeline with intelligent target scoring |
| [CDN_FILTER](CDN_FILTER/) | Bash + jq | Extracts subdomains behind no CDN (real origin IPs) and flags critical exposures |
| [dxtaminer](dxtaminer/) | Python | High-performance data mining engine for auditing massive files (+10 GB) |
| [Hacking_prompt](Hacking_prompt/) | Prompt | Structured AI copilot prompt for red team workflows |

---

## ITZKOATL

*Obsidian Serpent* — an automated reconnaissance engine for bug bounty hunters. Runs **subfinder**, **assetfinder** and **amass** in parallel, then applies an **M7 scoring engine** that classifies endpoints into High Priority, IDOR Candidates and API endpoints. WAF-aware (`wafw00f`) with dedicated execution modes to avoid IP bans.

```bash
bash itzkoatl.sh <project_name> [targets.txt] [out_scope.txt] --normal   # --stealth | --normal | --aggressive
```

Content discovery (ffuf / feroxbuster) is only triggered against high-score targets, saving bandwidth and time.

Full details: [ITZKOATL/README.md](ITZKOATL/README.md)

---

## CDN_FILTER

Parses **httpx JSON output** to isolate subdomains **without CDN protection** — exposing real origin IPs. Automatically detects and prioritizes:

- **RFC1918 private IP leaks** (critical DNS misconfiguration)
- **Login/admin panels** exposed without CDN shielding
- **API endpoints** directly reachable
- Interest scoring to surface the top 10 most promising targets

```bash
bash cdn_filter.sh httpx_output.json
```

Generates an organized output directory (TSV, URL lists, IP lists, JSON) ready to pipe into nmap or other tooling.

---

## dxtaminer

Streaming data-mining engine for security audits. Reads files line-by-line via Python generators — processes **multi-gigabyte logs, SQL dumps and URL lists** with negligible RAM consumption.

- **Dual-search mode:** custom wordlist matching + mandatory auto-recon regexes
- **Auto-recon patterns:** UUID/GUIDs, JWTs (`eyJ` header), AWS keys (`AKIA...`), emails, IPs and JS file paths
- **Smart output:** findings organized automatically under `gold/` by dictionary

```bash
python3 dxtaminer.py -d huge_dump.txt -w dicts/dm_secrets.txt
```

No external dependencies (standard library only, Python 3.8+).

Full details: [dxtaminer/README.md](dxtaminer/README.md)

---

## Hacking_prompt

A battle-tested system prompt that turns any LLM into a structured red team copilot: CVE/vulnerability research, false-positive refutation, lateral-thinking exploitation ideas, professional-grade output analysis (LinPEAS, long logs) and technique debugging.

Copy the content of [`Hacking_Prompt.txt`](Hacking_prompt/Hacking_Prompt.txt) as the initial context of your AI assistant session.

---

## Requirements

| Dependency | Used by |
|------------|---------|
| `jq` | CDN_FILTER |
| `subfinder`, `assetfinder`, `amass`, `wafw00f`, `ffuf`/`feroxbuster` | ITZKOATL |
| Python 3.8+ | dxtaminer |

---

## Disclaimer

These tools are intended **exclusively for educational purposes and authorized security testing** (CTF platforms, bug bounty programs within scope, controlled lab environments). The author assumes no responsibility for misuse or damage caused by improper use.
