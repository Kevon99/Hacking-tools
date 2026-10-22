#!/usr/bin/env python3
"""Fuzzer HTTP concurrente optimizado para ejecutarse a traves de proxychains.

    proxychains4 -q python3 proxfuzz.py -url https://host/FUZZ -w wordlist.txt

La URL puede llevar FUZZ en la ruta, la query o el host. Si no lo lleva, la
palabra se anade como segmento de ruta. Por cada palabra se prueban tambien
sus variantes con las extensiones de EXTENSIONS (salvo si FUZZ esta en el
host). Cada hilo mantiene su conexion keep-alive, de modo que el handshake
SOCKS/TLS solo se paga una vez por hilo. Los hallazgos se colorean segun el
codigo de estado.
"""

import argparse
import http.client
import os
import queue
import socket
import ssl
import sys
import threading
import time
from urllib.parse import quote, urlsplit

THREADS = 60
TIMEOUT = 10.0
MAX_BODY = 1 << 20
SHOW_404 = False
SAFE_CHARS = "/?&=%#:;@!$'()*+,~[]-._"
EXTENSIONS = [
    "php", "php3", "php4", "php5", "phtml",
    "html", "htm", "asp", "aspx", "jsp",
    "js", "json", "xml", "txt",
    "bak", "old", "orig", "swp",
    "zip", "tar.gz", "sql", "db", "sqlite",
    "conf", "config", "env", "yml", "log",
]

_RESET = "\033[0m"
_USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode = ssl.CERT_NONE

HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "*/*",
    "Accept-Encoding": "identity",
    "Connection": "keep-alive",
}

_local = threading.local()
_out_lock = threading.Lock()
_stat_lock = threading.Lock()
_stop = threading.Event()
_abort = threading.Event()

_done = 0
_errors = 0
_hits = 0
_err_samples = 0


def _close_conn():
    conn = getattr(_local, "conn", None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass
    _local.conn = None
    _local.key = None


def _get_conn(scheme, host, port):
    key = (scheme, host, port)
    if getattr(_local, "key", None) == key and getattr(_local, "conn", None):
        return _local.conn
    _close_conn()
    if scheme == "https":
        conn = http.client.HTTPSConnection(host, port, timeout=TIMEOUT, context=_SSL)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=TIMEOUT)
    conn.connect()
    try:
        conn.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    _local.conn = conn
    _local.key = key
    return conn


def _variants(word, with_ext):
    yield word
    if not with_ext or word.endswith("/"):
        return
    low = word.lower()
    for ext in EXTENSIONS:
        if low.endswith("." + ext):
            continue
        yield word + "." + ext


def _build_target(template, word):
    token = quote(word, safe=SAFE_CHARS)
    if "FUZZ" in template:
        return template.replace("FUZZ", token)
    base = template if template.endswith("/") else template + "/"
    return base + token.lstrip("/")


def _status_color(status):
    if not _USE_COLOR:
        return ""
    if 200 <= status < 300:
        return "\033[1;32m"
    if 300 <= status < 400:
        return "\033[1;36m"
    if status in (401, 403):
        return "\033[1;33m"
    if 500 <= status < 600:
        return "\033[1;35m"
    if status == 404:
        return "\033[2m"
    return "\033[1;31m"


def _fetch(template, word):
    target = _build_target(template, word)
    parts = urlsplit(target)
    scheme = (parts.scheme or "http").lower()
    if scheme not in ("http", "https"):
        raise ValueError("esquema no soportado: " + scheme)
    host = parts.hostname
    if not host:
        raise ValueError("URL invalida: " + target)
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    port = parts.port or (443 if scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path = path + "?" + parts.query

    last = None
    for _ in range(2):
        try:
            conn = _get_conn(scheme, host, port)
            conn.request("GET", path, headers=HEADERS)
            resp = conn.getresponse()
            body = resp.read(MAX_BODY)
            reusable = resp.isclosed()
            status, length = resp.status, len(body)
            if not reusable:
                _close_conn()
            return status, length, target
        except Exception as exc:
            last = exc
            _close_conn()
    raise last


def _worker(template, words):
    global _done, _errors, _hits, _err_samples
    while True:
        word = words.get()
        if word is None:
            return
        if _abort.is_set():
            continue
        t0 = time.perf_counter()
        try:
            status, length, target = _fetch(template, word)
        except Exception as exc:
            with _stat_lock:
                _done += 1
                _errors += 1
                show = _err_samples < 3
                if show:
                    _err_samples += 1
            if show:
                with _out_lock:
                    msg = "\n[!] %s: %s\n" % (word, exc)
                    if _USE_COLOR:
                        msg = "\033[1;31m" + msg + _RESET
                    sys.stderr.write(msg)
                    sys.stderr.flush()
            continue
        elapsed = (time.perf_counter() - t0) * 1000.0
        interesting = SHOW_404 or status != 404
        with _stat_lock:
            _done += 1
            if interesting:
                _hits += 1
        if interesting:
            line = "%-3d %9d  %6.0fms  %s" % (status, length, elapsed, target)
            if _USE_COLOR:
                line = _status_color(status) + line + _RESET
            with _out_lock:
                print(line, flush=True)


def _progress(start):
    while not _stop.wait(0.5):
        with _stat_lock:
            done, errors, hits = _done, _errors, _hits
        rate = done / max(time.time() - start, 1e-9)
        sys.stderr.write(
            "\r[+] %d req | %d hits | %d err | %.0f req/s   "
            % (done, hits, errors, rate)
        )
        sys.stderr.flush()
    sys.stderr.write("\r" + " " * 72 + "\r")
    sys.stderr.flush()


def main():
    parser = argparse.ArgumentParser(
        description="Fuzzer HTTP rapido para proxychains",
        usage="proxychains4 -q python3 proxfuzz.py -url URL -w DICCIONARIO",
    )
    parser.add_argument(
        "-url", required=True, metavar="URL", help="URL objetivo (FUZZ = punto de inyeccion)"
    )
    parser.add_argument(
        "-w", required=True, metavar="DICCIONARIO", help="ruta del wordlist"
    )
    args = parser.parse_args()

    template = args.url.strip()
    if "://" not in template:
        template = "http://" + template
    if not template.lower().startswith(("http://", "https://")):
        parser.error("solo se admiten URLs http:// o https://")

    try:
        fh = open(args.w, "r", encoding="utf-8", errors="replace")
    except OSError as exc:
        parser.error(str(exc))

    try:
        with_ext = "FUZZ" not in urlsplit(template).netloc
    except ValueError:
        with_ext = True

    sys.stderr.write(
        "[i] objetivo: %s\n[i] hilos: %d | timeout: %.0fs | extensiones: %d\n"
        % (template, THREADS, TIMEOUT, len(EXTENSIONS) if with_ext else 0)
    )
    if _USE_COLOR:
        sys.stderr.write(
            "[i] colores: 2xx verde | 3xx cian | 401/403 amarillo | 5xx magenta | otros rojo\n"
        )

    words = queue.Queue(maxsize=THREADS * 8)
    threads = [
        threading.Thread(target=_worker, args=(template, words), daemon=True)
        for _ in range(THREADS)
    ]
    for thread in threads:
        thread.start()

    start = time.time()
    progress = threading.Thread(target=_progress, args=(start,), daemon=True)
    progress.start()

    try:
        with fh:
            for line in fh:
                if _abort.is_set():
                    break
                word = line.strip()
                if not word:
                    continue
                for candidate in _variants(word, with_ext):
                    while not _abort.is_set():
                        try:
                            words.put(candidate, timeout=0.5)
                            break
                        except queue.Full:
                            pass
                    if _abort.is_set():
                        break
    except KeyboardInterrupt:
        _abort.set()
        _stop.set()
        sys.stderr.write("\n[!] interrumpido por el usuario\n")
    except OSError as exc:
        sys.stderr.write("\n[!] error leyendo el diccionario: %s\n" % exc)
    finally:
        for _ in range(THREADS):
            words.put(None)
        deadline = time.time() + TIMEOUT + 5
        for thread in threads:
            thread.join(timeout=max(0.0, deadline - time.time()))
        _stop.set()
        progress.join(timeout=1.0)

    with _stat_lock:
        done, errors, hits = _done, _errors, _hits
    elapsed = max(time.time() - start, 1e-9)
    sys.stderr.write(
        "[i] %d peticiones | %d resultados | %d errores | %.1fs | %.0f req/s\n"
        % (done, hits, errors, elapsed, done / elapsed)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
