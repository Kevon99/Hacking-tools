#!/usr/bin/env python3
"""Fuzzer HTTP concurrente optimizado para ejecutarse a traves de proxychains.

    proxychains4 -q python3 proxfuzz.py -url https://host/FUZZ -w wordlist.txt

La URL puede llevar FUZZ en la ruta, la query o el host. Si no lo lleva, la
palabra se anade como segmento de ruta. Por cada palabra se prueban tambien
sus variantes con las extensiones de EXTENSIONS (salvo si FUZZ esta en el
host). Cada hilo mantiene su conexion keep-alive, de modo que el handshake
SOCKS/TLS solo se paga una vez por hilo. Los hallazgos se colorean segun el
codigo de estado.

Si la URL termina en "?" o "&" se activa el descubrimiento de parametros GET:
cada palabra se prueba como ?palabra=valor y su respuesta se compara con una
linea base (sin parametro y con un parametro aleatorio) para mostrar solo los
parametros que parecen existir. Ejemplo:

    proxychains4 -q python3 proxfuzz.py -url "http://50.50.50.3/shell.php?" -w params.txt

Con -H se pueden enviar cabeceras extra. Si el valor contiene FUZZ se fuzzea,
lo que permite enumerar virtual hosts / subdominios:

    proxychains4 -q python3 proxfuzz.py -url http://10.0.0.5 -w subdominios.txt \
        -H "Host: FUZZ.test.local"

Filtros estilo ffuf: -fc codigos, -fs tamanos, -fw palabras, -fl lineas y
-fr regex sobre el cuerpo. Control de velocidad con -t hilos, -rate
peticiones/segundo y -timeout. Con -s solo se imprimen los resultados:

    proxychains4 -q python3 proxfuzz.py -url http://host/FUZZ -w wl.txt \
        -fc 403 -fs 1234 -rate 5 -s
"""

import argparse
import hashlib
import http.client
import os
import queue
import re
import secrets
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
PARAM_MIN_DIFF = 20
PARAM_DIFF = 0.03
VHOST_MIN_DIFF = 20
VHOST_DIFF = 0.03

_FILTER_CODES = None
_FILTER_SIZES = None
_FILTER_WORDS = None
_FILTER_LINES = None
_FILTER_REGEX = None
_MATCH_CODES = None
_RATE = 0.0
_SILENT = False

_HEX_RE = re.compile(r"\b[0-9a-fA-F]{12,}\b")
_DIGITS_RE = re.compile(r"\d{6,}")
_WS_RE = re.compile(r"\s+")

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
_rate_lock = threading.Lock()
_stop = threading.Event()
_abort = threading.Event()

_done = 0
_errors = 0
_hits = 0
_filtered = 0
_err_samples = 0
_param_hits = set()
_rate_next = 0.0


def _info(message):
    if not _SILENT:
        sys.stderr.write(message)
        sys.stderr.flush()


def _rate_wait():
    global _rate_next
    if _RATE <= 0:
        return
    interval = 1.0 / _RATE
    with _rate_lock:
        now = time.monotonic()
        if _rate_next < now:
            _rate_next = now
        wait = _rate_next - now
        _rate_next += interval
    if wait > 0:
        time.sleep(wait)


def _parse_ranges(spec, label):
    ranges = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                low, high = part.split("-", 1)
                low, high = int(low), int(high)
            else:
                low = high = int(part)
        except ValueError:
            raise ValueError("rango invalido en %s: %s" % (label, part))
        if low < 0 or high < 0:
            raise ValueError("valor negativo en %s: %s" % (label, part))
        if low > high:
            low, high = high, low
        ranges.append((low, high))
    if not ranges:
        raise ValueError("lista vacia en %s" % label)
    return ranges


def _in_ranges(value, ranges):
    for low, high in ranges:
        if low <= value <= high:
            return True
    return False


def _is_filtered(status, body):
    if _FILTER_CODES is not None and _in_ranges(status, _FILTER_CODES):
        return True
    if _FILTER_SIZES is not None and _in_ranges(len(body), _FILTER_SIZES):
        return True
    if (
        _FILTER_WORDS is None
        and _FILTER_LINES is None
        and _FILTER_REGEX is None
    ):
        return False
    text = body.decode("utf-8", "replace")
    if _FILTER_WORDS is not None and _in_ranges(len(text.split()), _FILTER_WORDS):
        return True
    if _FILTER_LINES is not None and _in_ranges(text.count("\n"), _FILTER_LINES):
        return True
    if _FILTER_REGEX is not None and _FILTER_REGEX.search(text):
        return True
    return False


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


def _build_target(template, word, append_path=True):
    token = quote(word, safe=SAFE_CHARS)
    if "FUZZ" in template:
        return template.replace("FUZZ", token)
    if not append_path:
        return template
    base = template if template.endswith("/") else template + "/"
    return base + token.lstrip("/")


def _parse_header(raw):
    if ":" not in raw:
        raise ValueError("cabecera invalida (falta ':'): " + raw)
    name, value = raw.split(":", 1)
    name = name.strip()
    value = value.strip()
    if not name:
        raise ValueError("cabecera invalida: " + raw)
    return name, value


def _set_header(headers, name, value):
    low = name.lower()
    for key in [k for k in headers if k.lower() == low]:
        del headers[key]
    headers[name] = value


def _base_headers(header_templates):
    headers = dict(HEADERS)
    for name, value in header_templates:
        _set_header(headers, name, value)
    return headers


def _build_candidate(template, word, header_templates, append_path):
    token = quote(word, safe=SAFE_CHARS)
    url = _build_target(template, word, append_path)
    headers = dict(HEADERS)
    display = None
    for name, value in header_templates:
        if "FUZZ" in value:
            value = value.replace("FUZZ", token)
            if display is None:
                display = "%s: %s" % (name, value)
        _set_header(headers, name, value)
    return url, headers, display


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


def _request_url(url, headers=None):
    parts = urlsplit(url)
    scheme = (parts.scheme or "http").lower()
    if scheme not in ("http", "https"):
        raise ValueError("esquema no soportado: " + scheme)
    host = parts.hostname
    if not host:
        raise ValueError("URL invalida: " + url)
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    port = parts.port or (443 if scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path = path + "?" + parts.query
    if headers is None:
        headers = HEADERS

    last = None
    for attempt in range(2):
        if attempt:
            _rate_wait()
        try:
            conn = _get_conn(scheme, host, port)
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            body = resp.read(MAX_BODY)
            reusable = resp.isclosed()
            status = resp.status
            if not reusable:
                _close_conn()
            return status, body, url
        except Exception as exc:
            last = exc
            _close_conn()
    raise last


def _normalize_hash(body):
    text = body.decode("utf-8", "replace")
    text = _HEX_RE.sub("#", text)
    text = _DIGITS_RE.sub("#", text)
    text = _WS_RE.sub(" ", text).strip()
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _build_param_target(base_url, word, value):
    name = word.split("=", 1)[0]
    separator = "&" if "?" in base_url else "?"
    return "%s%s%s=%s" % (
        base_url,
        separator,
        quote(name, safe="[]-._"),
        quote(value, safe=""),
    )


def _collect_param_refs(base_url, headers):
    marker = "z" + secrets.token_hex(4)
    marker_bytes = marker.encode()
    control_name = "zz" + secrets.token_hex(3)
    statuses = set()
    lengths = []
    hashes = set()
    control_reflects = False
    samples = 0
    last_error = None

    for _ in range(2):
        _rate_wait()
        try:
            status, body, _ = _request_url(base_url, headers)
        except Exception as exc:
            last_error = exc
            continue
        samples += 1
        statuses.add(status)
        lengths.append(len(body))
        hashes.add(_normalize_hash(body))

    for _ in range(3):
        _rate_wait()
        try:
            status, body, _ = _request_url(
                _build_param_target(base_url, control_name, marker), headers
            )
        except Exception as exc:
            last_error = exc
            continue
        samples += 1
        statuses.add(status)
        lengths.append(len(body))
        hashes.add(_normalize_hash(body))
        if marker_bytes in body:
            control_reflects = True

    if not samples:
        raise RuntimeError("no se pudo obtener la linea base: %s" % last_error)

    return {
        "marker": marker,
        "statuses": statuses,
        "lengths": lengths,
        "hashes": hashes,
        "control_reflects": control_reflects,
    }


def _normalize_vhost_hash(body, word):
    text = body.decode("utf-8", "replace")
    text = text.replace(word, "#")
    text = _HEX_RE.sub("#", text)
    text = _DIGITS_RE.sub("#", text)
    text = _WS_RE.sub(" ", text).strip()
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _collect_vhost_refs(template, header_templates, append_path):
    statuses = set()
    lengths = []
    hashes = set()
    samples = 0
    last_error = None

    for _ in range(3):
        word = "zz" + secrets.token_hex(4)
        url, headers, _ = _build_candidate(
            template, word, header_templates, append_path
        )
        _rate_wait()
        try:
            status, body, _ = _request_url(url, headers)
        except Exception as exc:
            last_error = exc
            continue
        samples += 1
        statuses.add(status)
        lengths.append(len(body))
        hashes.add(_normalize_vhost_hash(body, word))

    if not samples:
        raise RuntimeError("no se pudo obtener la linea base: %s" % last_error)

    return {"statuses": statuses, "lengths": lengths, "hashes": hashes}


def _vhost_reason(status, body, word, ref):
    if status not in ref["statuses"]:
        return "estado %d" % status
    length = len(body)
    for ref_length in ref["lengths"]:
        if abs(length - ref_length) <= max(VHOST_MIN_DIFF, ref_length * VHOST_DIFF):
            return None
    if _normalize_vhost_hash(body, word) in ref["hashes"]:
        return None
    return "longitud"


def _param_reason(status, body, ref):
    if status not in ref["statuses"]:
        return "estado %d" % status
    if not ref["control_reflects"] and ref["marker"].encode() in body:
        return "reflejado"
    length = len(body)
    for ref_length in ref["lengths"]:
        if abs(length - ref_length) <= max(PARAM_MIN_DIFF, ref_length * PARAM_DIFF):
            break
    else:
        return "longitud"
    if _normalize_hash(body) not in ref["hashes"]:
        return "contenido"
    return None


def _print_line(line):
    try:
        print(line, flush=True)
    except BrokenPipeError:
        _abort.set()


def _worker(
    template,
    words,
    header_templates,
    append_path,
    param_ref=None,
    vhost_ref=None,
):
    global _done, _errors, _hits, _filtered, _err_samples
    while True:
        word = words.get()
        if word is None:
            return
        if _abort.is_set():
            continue
        _rate_wait()
        t0 = time.perf_counter()
        try:
            if param_ref is None:
                target, headers, display = _build_candidate(
                    template, word, header_templates, append_path
                )
                status, body, _ = _request_url(target, headers)
                length = len(body)
                if display:
                    target = display
                if vhost_ref is not None:
                    reason = _vhost_reason(status, body, word, vhost_ref)
                else:
                    reason = None
            else:
                name = word.split("=", 1)[0]
                target = _build_param_target(template, word, param_ref["marker"])
                status, body, _ = _request_url(
                    target, _base_headers(header_templates)
                )
                length = len(body)
                reason = _param_reason(status, body, param_ref)
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
        if param_ref is not None:
            interesting = reason is not None
        elif vhost_ref is not None:
            interesting = SHOW_404 or reason is not None
        else:
            interesting = SHOW_404 or status != 404
        if _MATCH_CODES is not None:
            if param_ref is None and vhost_ref is None:
                interesting = _in_ranges(status, _MATCH_CODES)
            else:
                interesting = interesting and _in_ranges(status, _MATCH_CODES)
        filtered = interesting and _is_filtered(status, body)
        if filtered:
            interesting = False
        with _stat_lock:
            _done += 1
            if filtered:
                _filtered += 1
            elif interesting:
                _hits += 1
                if param_ref is not None and reason is not None:
                    _param_hits.add(name)
        if not interesting:
            continue
        if param_ref is None:
            line = "%-3d %9d  %6.0fms  %s" % (status, length, elapsed, target)
        else:
            line = "[+] %-24s [%d | %db | %s]  %s" % (
                name,
                status,
                length,
                reason,
                target,
            )
        if _USE_COLOR:
            line = _status_color(status) + line + _RESET
        with _out_lock:
            _print_line(line)


def _progress(start):
    while not _stop.wait(0.5):
        with _stat_lock:
            done, errors, hits, filtered = _done, _errors, _hits, _filtered
        rate = done / max(time.time() - start, 1e-9)
        sys.stderr.write(
            "\r[+] %d req | %d hits | %d filt | %d err | %.0f req/s   "
            % (done, hits, filtered, errors, rate)
        )
        sys.stderr.flush()
    sys.stderr.write("\r" + " " * 90 + "\r")
    sys.stderr.flush()


def main():
    global TIMEOUT, _RATE, _SILENT
    global _FILTER_CODES, _FILTER_SIZES, _FILTER_WORDS, _FILTER_LINES
    global _FILTER_REGEX, _MATCH_CODES

    parser = argparse.ArgumentParser(
        description="Fuzzer HTTP rapido para proxychains",
        usage=(
            "proxychains4 -q python3 proxfuzz.py -url URL -w DICCIONARIO "
            "[-H 'Nombre: valor'] [opciones]"
        ),
    )
    parser.add_argument(
        "-url",
        required=True,
        metavar="URL",
        help="URL objetivo (FUZZ = inyeccion; si termina en ? o & descubre parametros GET)",
    )
    parser.add_argument(
        "-w", required=True, metavar="DICCIONARIO", help="ruta del wordlist"
    )
    parser.add_argument(
        "-H",
        "--header",
        action="append",
        default=[],
        metavar="'Nombre: valor'",
        help="cabecera extra; si el valor contiene FUZZ se fuzzea "
        "(ej: -H 'Host: FUZZ.test.local')",
    )
    parser.add_argument(
        "--no-vhost-filter",
        action="store_true",
        help="no descartar respuestas iguales a la linea base al fuzzear cabeceras",
    )
    parser.add_argument(
        "-fc",
        "--filter-code",
        metavar="CODIGOS",
        help="ocultar codigos de estado (ej: 403,404 o 400-499)",
    )
    parser.add_argument(
        "-fs",
        "--filter-size",
        metavar="TAMANOS",
        help="ocultar longitudes de respuesta (ej: 1234 o 1000-2000)",
    )
    parser.add_argument(
        "-fw",
        "--filter-words",
        metavar="PALABRAS",
        help="ocultar respuestas con ese numero de palabras (admite rangos)",
    )
    parser.add_argument(
        "-fl",
        "--filter-lines",
        metavar="LINEAS",
        help="ocultar respuestas con ese numero de lineas (admite rangos)",
    )
    parser.add_argument(
        "-fr",
        "--filter-regex",
        metavar="REGEX",
        help="ocultar respuestas cuyo cuerpo case con la regex",
    )
    parser.add_argument(
        "-mc",
        "--match-code",
        metavar="CODIGOS",
        help="mostrar solo esos codigos de estado (ej: 200,301-302)",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=THREADS,
        metavar="N",
        help="numero de hilos (def: %d)" % THREADS,
    )
    parser.add_argument(
        "-rate",
        "--rate",
        type=float,
        default=0.0,
        metavar="N",
        help="maximo de peticiones por segundo, 0 = sin limite (def: 0)",
    )
    parser.add_argument(
        "-timeout",
        "--timeout",
        type=float,
        default=TIMEOUT,
        metavar="SEG",
        help="timeout por peticion en segundos (def: %.0f)" % TIMEOUT,
    )
    parser.add_argument(
        "-s",
        "--silent",
        action="store_true",
        help="modo silencioso: sin banner ni progreso, solo resultados",
    )
    args = parser.parse_args()

    if args.threads < 1:
        parser.error("el numero de hilos debe ser >= 1")
    if args.rate < 0:
        parser.error("la tasa debe ser >= 0")
    if args.timeout <= 0:
        parser.error("el timeout debe ser > 0")
    try:
        if args.filter_code:
            _FILTER_CODES = _parse_ranges(args.filter_code, "codigos")
        if args.filter_size:
            _FILTER_SIZES = _parse_ranges(args.filter_size, "tamanos")
        if args.filter_words:
            _FILTER_WORDS = _parse_ranges(args.filter_words, "palabras")
        if args.filter_lines:
            _FILTER_LINES = _parse_ranges(args.filter_lines, "lineas")
        if args.filter_regex:
            _FILTER_REGEX = re.compile(args.filter_regex)
        if args.match_code:
            _MATCH_CODES = _parse_ranges(args.match_code, "codigos")
    except (ValueError, re.error) as exc:
        parser.error("filtro invalido: %s" % exc)
    TIMEOUT = args.timeout
    _RATE = args.rate
    _SILENT = args.silent

    template = args.url.strip()
    if "://" not in template:
        template = "http://" + template
    if not template.lower().startswith(("http://", "https://")):
        parser.error("solo se admiten URLs http:// o https://")

    header_templates = []
    for raw in args.header:
        try:
            header_templates.append(_parse_header(raw))
        except ValueError as exc:
            parser.error(str(exc))
    header_fuzz = any("FUZZ" in value for _, value in header_templates)
    append_path = not header_fuzz

    try:
        fh = open(args.w, "r", encoding="utf-8", errors="replace")
    except OSError as exc:
        parser.error(str(exc))

    param_mode = template.endswith("?") or template.endswith("&")
    if param_mode:
        base_url = template[:-1]
        if header_fuzz:
            parser.error(
                "FUZZ en cabeceras no se puede combinar con el descubrimiento "
                "de parametros"
            )
        with_ext = False
    else:
        base_url = template
        try:
            netloc_fuzz = "FUZZ" in urlsplit(template).netloc
        except ValueError:
            netloc_fuzz = True
        with_ext = not header_fuzz and not netloc_fuzz

    _info(
        "[i] objetivo: %s\n[i] hilos: %d | timeout: %.0fs | extensiones: %d\n"
        % (template, args.threads, TIMEOUT, len(EXTENSIONS) if with_ext else 0)
    )
    if _RATE > 0:
        _info("[i] limite: %.1f req/s\n" % _RATE)
    for name, value in header_templates:
        _info("[i] cabecera: %s: %s\n" % (name, value))
    if _USE_COLOR:
        _info(
            "[i] colores: 2xx verde | 3xx cian | 401/403 amarillo | 5xx magenta | otros rojo\n"
        )

    vhost_ref = None
    if param_mode:
        _info(
            "[i] modo: parametros GET (linea base + comparacion de respuestas)\n"
        )
        _info("[i] obteniendo linea base...\n")
        try:
            param_ref = _collect_param_refs(
                base_url, _base_headers(header_templates)
            )
        except Exception as exc:
            parser.error(str(exc))
        finally:
            _close_conn()
    else:
        param_ref = None
        if header_fuzz and not args.no_vhost_filter:
            _info(
                "[i] modo: vhost / subdominios "
                "(filtro por linea base activo)\n"
            )
            _info("[i] obteniendo linea base...\n")
            try:
                vhost_ref = _collect_vhost_refs(
                    base_url, header_templates, append_path
                )
            except Exception as exc:
                parser.error(str(exc))
            finally:
                _close_conn()

    words = queue.Queue(maxsize=args.threads * 8)
    threads = [
        threading.Thread(
            target=_worker,
            args=(
                base_url,
                words,
                header_templates,
                append_path,
                param_ref,
                vhost_ref,
            ),
            daemon=True,
        )
        for _ in range(args.threads)
    ]
    for thread in threads:
        thread.start()

    start = time.time()
    progress = None
    if not _SILENT:
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
        for _ in range(args.threads):
            words.put(None)
        deadline = time.time() + TIMEOUT + 5
        for thread in threads:
            thread.join(timeout=max(0.0, deadline - time.time()))
        _stop.set()
        if progress is not None:
            progress.join(timeout=1.0)

    with _stat_lock:
        done, errors, hits, filtered = _done, _errors, _hits, _filtered
    elapsed = max(time.time() - start, 1e-9)
    _info(
        "[i] %d peticiones | %d resultados | %d filtradas | %d errores "
        "| %.1fs | %.0f req/s\n"
        % (done, hits, filtered, errors, elapsed, done / elapsed)
    )
    if param_mode:
        with _stat_lock:
            found_params = sorted(_param_hits)
        _info(
            "[i] parametros posibles (%d): %s\n"
            % (
                len(found_params),
                ", ".join(found_params) if found_params else "ninguno",
            )
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
