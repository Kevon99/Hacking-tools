#!/usr/bin/env python3
"""Host discovery por TCP connect (estilo nmap -sT) para proxychains.

    proxychains4 -q python3 proxydiscover.py -net 10.10.10.0/24
    proxychains4 -q python3 proxydiscover.py -net 10.10.10.0/24 -p 22,80,443 -t 2 -c 150

Solo usa connect() TCP: ICMP y SYN crudo no atraviesan un proxy SOCKS. Un host
se marca vivo en cuanto acepta conexion en alguno de los puertos indicados.
Se conecta siempre por IP, sin resolver DNS, para no penalizar via proxychains.
"""

import argparse
import ipaddress
import os
import queue
import socket
import sys
import threading
import time

DEFAULT_PORTS = (
    "80,443,22,445,3389,8080,8443,21,23,25,53,110,135,139,143,993,995,"
    "1433,1521,2049,3306,5432,5900,6379,9200,27017"
)
THREADS = 100
TIMEOUT = 3.0
MAX_HOSTS = 65536

_RESET = "\033[0m"
_USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ
_GREEN = "\033[1;32m" if _USE_COLOR else ""

_lock = threading.Lock()
_out_lock = threading.Lock()
_stop = threading.Event()
_abort = threading.Event()

_scanned = 0
_alive = set()


def _parse_ports(spec):
    ports = []
    seen = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            if "-" in chunk:
                first, last = chunk.split("-", 1)
                start, end = int(first), int(last)
                if start > end:
                    start, end = end, start
                values = range(start, end + 1)
            else:
                values = [int(chunk)]
        except ValueError:
            raise ValueError("puerto invalido: %s" % chunk)
        for port in values:
            if not 1 <= port <= 65535:
                raise ValueError("puerto fuera de rango: %d" % port)
            if port not in seen:
                seen.add(port)
                ports.append(port)
    if not ports:
        raise ValueError("la lista de puertos esta vacia")
    return ports


def _hosts(spec):
    try:
        network = ipaddress.ip_network(spec, strict=False)
    except ValueError as exc:
        raise ValueError("red invalida: %s" % exc)
    if network.num_addresses > MAX_HOSTS:
        raise ValueError("red demasiado grande (maximo %d direcciones)" % MAX_HOSTS)
    return [str(ip) for ip in network.hosts()]


def _worker(tasks, timeout):
    global _scanned
    while True:
        item = tasks.get()
        if item is None:
            return
        if _abort.is_set():
            continue
        ip, port = item
        with _lock:
            if ip in _alive:
                _scanned += 1
                continue
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            open_port = True
        except OSError:
            open_port = False
        finally:
            sock.close()
        with _lock:
            _scanned += 1
            new = open_port and ip not in _alive
            if new:
                _alive.add(ip)
        if new:
            line = "[+] %s puerto %d/tcp abierto" % (ip, port)
            if _USE_COLOR:
                line = _GREEN + line + _RESET
            with _out_lock:
                print(line, flush=True)


def _progress(total, start):
    while not _stop.wait(0.5):
        with _lock:
            scanned, found = _scanned, len(_alive)
        rate = scanned / max(time.time() - start, 1e-9)
        sys.stderr.write(
            "\r[+] %d/%d | %d vivos | %.0f/s   " % (scanned, total, found, rate)
        )
        sys.stderr.flush()
    sys.stderr.write("\r" + " " * 72 + "\r")
    sys.stderr.flush()


def main():
    parser = argparse.ArgumentParser(
        description="Host discovery TCP connect para proxychains",
        usage=(
            "proxychains4 -q python3 proxydiscover.py -net RED "
            "[-p PUERTOS] [-t SEG] [-c HILOS]"
        ),
    )
    parser.add_argument(
        "-net", required=True, metavar="CIDR", help="red objetivo, p. ej. 10.10.10.0/24"
    )
    parser.add_argument(
        "-p", default=DEFAULT_PORTS, metavar="PUERTOS", help="ej. 22,80,443 o 1-1024"
    )
    parser.add_argument(
        "-t", type=float, default=TIMEOUT, metavar="SEG", help="timeout por conexion"
    )
    parser.add_argument(
        "-c", type=int, default=THREADS, metavar="N", help="conexiones concurrentes"
    )
    args = parser.parse_args()

    try:
        hosts = _hosts(args.net)
        ports = _parse_ports(args.p)
    except ValueError as exc:
        parser.error(str(exc))
    if not 1 <= args.c <= 1000:
        parser.error("los hilos deben estar entre 1 y 1000")
    if args.t <= 0:
        parser.error("el timeout debe ser mayor que 0")

    total = len(hosts) * len(ports)
    sys.stderr.write(
        "[i] red: %s | hosts: %d | puertos: %d | timeout: %.1fs | hilos: %d\n"
        % (args.net, len(hosts), len(ports), args.t, args.c)
    )
    sys.stderr.write(
        "[i] TCP connect (tipo nmap -sT); se para al primer puerto abierto por host\n"
    )

    tasks = queue.Queue(maxsize=args.c * 8)
    threads = [
        threading.Thread(target=_worker, args=(tasks, args.t), daemon=True)
        for _ in range(args.c)
    ]
    for thread in threads:
        thread.start()

    start = time.time()
    progress = threading.Thread(target=_progress, args=(total, start), daemon=True)
    progress.start()

    try:
        for port in ports:
            if _abort.is_set():
                break
            for ip in hosts:
                while not _abort.is_set():
                    try:
                        tasks.put((ip, port), timeout=0.5)
                        break
                    except queue.Full:
                        pass
                if _abort.is_set():
                    break
    except KeyboardInterrupt:
        _abort.set()
        _stop.set()
        sys.stderr.write("\n[!] interrumpido por el usuario\n")
    finally:
        for _ in range(args.c):
            tasks.put(None)
        deadline = time.time() + args.t + 5
        for thread in threads:
            thread.join(timeout=max(0.0, deadline - time.time()))
        _stop.set()
        progress.join(timeout=1.0)

    with _lock:
        scanned = _scanned
        found = sorted(_alive, key=ipaddress.ip_address)
    elapsed = max(time.time() - start, 1e-9)
    sys.stderr.write(
        "[i] %d hosts vivos | %d comprobaciones | %.1fs | %.0f/s\n"
        % (len(found), scanned, elapsed, scanned / elapsed)
    )
    if found:
        sys.stderr.write("[i] vivos: %s\n" % ", ".join(found))
    return 0


if __name__ == "__main__":
    sys.exit(main())
