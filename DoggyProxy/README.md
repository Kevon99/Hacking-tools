# DoggyProxy

**DoggyProxy** is a small collection of offensive-security tools built to run **entirely through `proxychains` and SOCKS proxies**. It focuses on the workflows that usually break when traffic has to traverse a pivot: HTTP content discovery, hidden parameter discovery and host discovery.

Every network operation is a plain TCP `connect()`, which is exactly what proxychains hooks. That makes these tools compatible with Tor, `ssh -D`, Chisel, Ligolo-style SOCKS pivots, Cobalt Strike SOCKS and any other proxy supported by proxychains.

Intended for authorized security assessments, CTFs and bug bounty engagements only.

---

## Why a proxychains-specific toolkit?

| Design decision | Benefit |
|---|---|
| TCP `connect()` only — no ICMP, ARP or raw SYN | Works through SOCKS proxies, unlike `nmap -sn` or `-sS` |
| Persistent HTTP keep-alive per worker | Pays the SOCKS/TLS handshake once per thread instead of once per request |
| Bounded queues and configurable concurrency | High throughput without exhausting the proxy |
| Numeric-IP connections for host discovery | No DNS round-trips through the proxy |
| Python standard library only | Nothing to install on the pivot host |

---

## Tools

| Tool | Description |
|---|---|
| [`proxfuzz.py`](#proxfuzzpy) | Concurrent HTTP/HTTPS fuzzing of paths and files, automatic extensions, and hidden GET parameter discovery |
| [`proxydiscover.py`](#proxydiscoverpy) | TCP-connect host discovery (equivalent to `nmap -sT`) over a CIDR range |

---

## proxfuzz.py

Concurrent HTTP fuzzer optimized for proxy chains. It only takes two arguments: `-url` and `-w`.

```bash
proxychains4 -q ./proxfuzz.py -url https://target/FUZZ -w wordlist.txt
```

### Modes

The URL controls the mode automatically:

| URL form | Mode | Example request |
|---|---|---|
| Contains `FUZZ` | Replace the marker in path, query or host | `https://target/FUZZ` |
| No `FUZZ` | Word is appended as a path segment | `https://target/` + `admin` |
| Ends in `?` or `&` | Hidden **GET parameter discovery** | `shell.php?` + `cmd=value` |

### Path and file fuzzing

- Each word is requested as-is and with the extensions listed in `EXTENSIONS` (28 by default: `php`, `bak`, `zip`, `sql`, `env`, `tar.gz`, ...).
- Extensions are skipped when `FUZZ` is in the host, when the word ends in `/`, or when the word already ends with that extension.
- HTTP keep-alive is reused per thread, so proxychains only establishes the SOCKS tunnel once per worker.
- Responses are filtered by status: `404` is hidden by default (`SHOW_404`).

```bash
# Path fuzzing with automatic extensions
proxychains4 -q ./proxfuzz.py -url https://target/FUZZ -w raft-medium-directories.txt

# File fuzzing with extensions
proxychains4 -q ./proxfuzz.py -url https://target/backup/ -w files.txt
```

Example output (colored in a terminal):

```text
200      1423      84ms  https://target/admin.php
301         0      61ms  https://target/uploads
403       287      73ms  https://target/.env
```

### Hidden GET parameter discovery

When the URL ends in `?` (or `&` if there is already a query string), each word is tested as `?word=<random marker>` and the response is compared against a baseline:

1. **2 requests** to the target without the candidate parameter.
2. **3 requests** with a random control parameter to model how the application reacts to unknown parameters.
3. **1 request per word** with `?word=<random marker>`.

A parameter is reported as a candidate when its response:

- returns a different HTTP status;
- reflects the random marker in the body (disabled automatically if the control parameter is also reflected);
- differs in body length beyond `max(20 bytes, 3%)` from every baseline sample;
- or has a different normalized content hash (long timestamps, IDs and hex tokens are normalized out).

```bash
proxychains4 -q ./proxfuzz.py -url "http://10.10.10.3/shell.php?" -w params.txt
```

Example output:

```text
[+] cmd   [200 | 33b | reflejado]  http://10.10.10.3/shell.php?cmd=z1a2b3c4
[+] ps    [200 | 60b | longitud]   http://10.10.10.3/shell.php?ps=z1a2b3c4
[i] parametros posibles (2): cmd, ps
```

The final summary lists every candidate parameter, making it easy to feed them into the next stage.

### Tuning

| Constant | Default | Purpose |
|---|---|---|
| `THREADS` | `60` | Concurrent workers / keep-alive connections |
| `TIMEOUT` | `10.0` | Socket timeout in seconds |
| `MAX_BODY` | `1 MiB` | Maximum body read per response |
| `SHOW_404` | `False` | Show `404` responses in path mode |
| `EXTENSIONS` | 28 entries | Extensions appended in path/file mode |
| `PARAM_MIN_DIFF` | `20` | Minimum absolute body-length difference |
| `PARAM_DIFF` | `0.03` | Relative body-length difference (3%) |

### Notes and limitations

- Only `GET` requests are sent.
- Parameter discovery assumes the parameter name is what matters; values are randomized markers.
- Highly dynamic pages can still produce false positives. Increase the number of baseline samples or raise `PARAM_MIN_DIFF` / `PARAM_DIFF` if needed.
- TLS certificates are **not verified**, which is useful for self-signed lab targets but means the tool is not suitable for trusting production traffic.
- `404` responses are hidden by default in path mode; set `SHOW_404 = True` to see them.

---

## proxydiscover.py

TCP-connect host discovery, equivalent to `nmap -sT`. It marks a host as alive as soon as one of the selected TCP ports accepts a connection.

```bash
proxychains4 -q ./proxydiscover.py -net 10.10.10.0/24
```

### Options

| Option | Default | Description |
|---|---|---|
| `-net` | required | Target CIDR or single IP (`10.10.10.0/24`, `10.10.10.5`) |
| `-p` | 26 common ports | Port list or ranges: `22,80,443` or `1-1024` |
| `-t` | `3.0` | Timeout per connection in seconds |
| `-c` | `100` | Concurrent connections (1–1000) |

Default ports: `80,443,22,445,3389,8080,8443,21,23,25,53,110,135,139,143,993,995,1433,1521,2049,3306,5432,5900,6379,9200,27017`.

```bash
# Quick web-focused sweep
proxychains4 -q ./proxydiscover.py -net 10.10.10.0/24 -p 80,443,8080,8443

# Range of ports with higher concurrency
proxychains4 -q ./proxydiscover.py -net 10.10.10.0/24 -p 1-1024 -t 2 -c 150
```

### How it works

- Enumerates every usable address in the CIDR block (up to 65,536 addresses).
- Tries ports in priority order across the whole range.
- After a host answers on one port, its remaining probes are skipped (discovery, not a full port scan).
- Connects directly to numeric IPs — no DNS traffic through the proxy.
- Prints live hosts in green (when attached to a terminal) and a final sorted list.

```text
[+] 10.10.10.5 puerto 80/tcp abierto
[+] 10.10.10.9 puerto 443/tcp abierto
[i] 2 hosts vivos | 6604 comprobaciones | 12.4s | 532/s
[i] vivos: 10.10.10.5, 10.10.10.9
```

Because only TCP is used, a host with none of the selected ports open will not be discovered. ICMP echo and ARP do not traverse a SOCKS proxy.

---

## Requirements

- Linux or Unix (proxychains relies on `LD_PRELOAD`)
- Python 3.8+ (standard library only)
- `proxychains4` and a reachable SOCKS/HTTP proxy that can route to the target network

---

## proxychains configuration

Both tools work with any proxychains-supported proxy. A minimal configuration:

```ini
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 3000

[ProxyList]
socks5 127.0.0.1 1080
```

Examples of proxy sources:

- **Tor:** `socks5 127.0.0.1 9050` (internet targets only)
- **SSH pivot:** `ssh -D 1080 -N user@pivot` then use `socks5 127.0.0.1 1080`
- **Chisel / Ligolo / Cobalt Strike:** point proxychains at the local SOCKS listener

### Important for internal networks

If you scan private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) through a pivot, make sure those ranges are **not** listed under `localnet` in `proxychains.conf`. `localnet` entries bypass the proxy, so the traffic would hit your local network instead of the target network.

Also align the proxy connect timeout with the tool timeout:

```ini
tcp_connect_time_out 3000
```

A high `tcp_connect_time_out` can make `proxydiscover.py -t 3` appear much slower, because proxychains controls the proxy-side connection timeout.

---

## Disclaimer

These tools are intended **exclusively for educational purposes and authorized security testing** (CTF platforms, bug bounty programs within scope, controlled lab environments). You must obtain explicit permission before scanning any target you do not own. The author assumes no responsibility for misuse, legal consequences or damage caused by improper use.

---

## License

MIT License. See the repository-level [LICENSE](../LICENSE) for the full text.
