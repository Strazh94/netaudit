#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netaudit.py — lightweight port scanner and security audit (standard library only).

Features:
  * scanning a subnet (CIDR) or a single IP on the specified ports
    (defaults: 22, 80, 443, 5432) using a plain connect-scan;
  * service detection from banners: SSH, HTTP(S), PostgreSQL;
  * matching versions/banners against a local vulnerability database (vulnbase.json) —
    matching only, no exploitation;
  * TLS certificate and TLS version checks;
  * optional (flag --check-creds) LIMITED default-password check:
    - HTTP Basic Auth (stdlib, at most 5 attempts per target);
    - PostgreSQL (own protocol implementation over sockets, at most 5 attempts);
    - SSH — only if paramiko is installed (otherwise an honest [skip]).

Use ONLY on networks you have explicit permission to audit.

Exit codes:
  0 — no problems found
  1 — problems found
  2 — startup/arguments error
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

VERSION = "1.0"
DEFAULT_PORTS = [22, 80, 443, 5432]
SERVICE_BY_PORT = {22: "ssh", 80: "http", 443: "https", 5432: "postgres"}

# Mini dictionary for default-credential checks (only with --check-creds).
CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("postgres", "postgres"),
    ("postgres", "password"),
    ("root", "root"),
    ("user", "user"),
    ("test", "test"),
    ("admin", "123456"),
]
MAX_CREDS_PER_TARGET = 5          # hard limit of attempts per target
HTTP_AUTH_PATHS = ["/", "/admin/", "/manager/html"]

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

DISCLAIMER = """
[!] NETWORK SCANNING — ONLY WITH THE OWNER'S PERMISSION.
    The tool is intended for auditing YOUR OWN networks/systems.
    Unauthorized scanning of other people's networks is illegal.
"""


# ---------------------------------------------------------------------------
# Common utilities
# ---------------------------------------------------------------------------

def parse_ports(text: str) -> list[int]:
    """'22,80,443,8000-8010' -> [22, 80, 443, 8000, ...]"""
    ports: set[int] = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    for p in ports:
        if not 1 <= p <= 65535:
            raise ValueError(f"invalid port: {p}")
    return sorted(ports)


def version_tokens(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


def version_below(a: str, b: str) -> bool:
    """True if version a is strictly less than b."""
    ta, tb = version_tokens(a), version_tokens(b)
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return ta < tb


def recvall(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def finding(severity: str, title: str, detail: str = "", cve: list | None = None) -> dict:
    return {"severity": severity, "title": title, "detail": detail, "cve": cve or []}


# ---------------------------------------------------------------------------
# Banner grabbing
# ---------------------------------------------------------------------------

def do_http(sock: socket.socket, method: str, host: str, path: str = "/") -> tuple[str, dict]:
    """Sends a simple HTTP/1.0 request and returns (status line, headers)."""
    req = (
        f"{method} {path} HTTP/1.0\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: netaudit/{VERSION}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    try:
        sock.sendall(req)
        data = b""
        while len(data) < 8192:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                break
    except OSError:
        return "", {}

    text = data.decode("latin-1", "replace")
    lines = text.split("\r\n")
    status = lines[0] if lines else ""
    headers: dict = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, headers


def grab_ssh(sock: socket.socket) -> str:
    data = sock.recv(1024)
    line = data.decode("latin-1", "replace").strip().splitlines()
    return line[0] if line else ""


def tls_handshake(raw: socket.socket, host: str, timeout: float):
    """
    Tries to establish TLS. Returns (tls_sock, findings, verified).
    1) with chain-of-trust verification — if OK, parse the certificate;
    2) on a trust error — retry without verification to finish reading the
       banner, and record the certificate problem.
    """
    findings: list[dict] = []

    def make_ctx(verify: bool) -> ssl.SSLContext:
        if verify:
            ctx = ssl.create_default_context()
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    # 1) with verification
    try:
        ctx = make_ctx(True)
        ctx.check_hostname = False  # we check the chain here; hostname separately below
        tls = ctx.wrap_socket(raw, server_hostname=host)
        tls.settimeout(timeout)
        cert = tls.getpeercert() or {}
        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days = (exp - datetime.utcnow()).days
                if days < 0:
                    findings.append(finding(
                        "high", "TLS: certificate expired",
                        f"notAfter={not_after}"))
                elif days <= 30:
                    findings.append(finding(
                        "medium", "TLS: certificate expires soon",
                        f"{days} day(s) left, notAfter={not_after}"))
            except ValueError:
                pass
        return tls, findings, True
    except ssl.SSLCertVerificationError as e:
        findings.append(finding(
            "high", "TLS: certificate fails trust verification",
            e.verify_message or str(e)))
    except (ssl.SSLError, OSError, socket.timeout):
        pass

    # 2) without verification (to get the banner / TLS version)
    try:
        tls = ctx_off = make_ctx(False)
        tls = ctx_off.wrap_socket(raw, server_hostname=host)
        tls.settimeout(timeout)
        return tls, findings, False
    except (ssl.SSLError, OSError, socket.timeout):
        return None, findings, False


def tls_findings(tls: ssl.SSLSocket) -> list[dict]:
    out: list[dict] = []
    ver = tls.version() or ""
    if ver in ("TLSv1", "TLSv1.1", ""):
        out.append(finding(
            "high", f"TLS: outdated/unknown protocol version ({ver or 'unknown'})",
            "use TLS 1.2+"))
    return out


def grab_https(raw: socket.socket, host: str, timeout: float):
    tls, findings, _verified = tls_handshake(raw, host, timeout)
    if tls is None:
        return "TLS handshake failed", findings, None
    findings.extend(tls_findings(tls))
    try:
        status, headers = do_http(tls, "HEAD", host)
    finally:
        try:
            tls.close()
        except OSError:
            pass
    parts = []
    if status:
        parts.append(status)
    if headers.get("server"):
        parts.append(f"Server: {headers['server']}")
    if headers.get("x-powered-by"):
        parts.append(f"X-Powered-By: {headers['x-powered-by']}")
    return " | ".join(parts), findings, headers


PG_AUTH = {
    0: ("trust", "trust auth", "critical",
        "PostgreSQL: Trust authentication — login WITHOUT a password"),
    3: ("cleartext", "cleartext", "medium",
        "PostgreSQL: password sent in cleartext (cleartext auth)"),
    5: ("md5", "md5 hash", "medium",
        "PostgreSQL: legacy md5 authentication (SCRAM recommended)"),
    10: ("scram-sha-256", "scram", "info",
         "PostgreSQL: SCRAM-SHA-256 (fine)"),
}


def _cstr(buf: bytes, i: int) -> tuple[str, int]:
    end = buf.find(b"\x00", i)
    if end < 0:
        return "", len(buf)
    return buf[i:end].decode("utf-8", "replace"), end + 1


def pg_recv_msg(sock: socket.socket):
    hdr = recvall(sock, 5)
    if len(hdr) < 5:
        return None, b""
    typ = hdr[0:1]
    ln = struct.unpack("!i", hdr[1:5])[0]
    if ln < 4:
        return typ, b""
    body = recvall(sock, ln - 4)
    return typ, body


def pg_startup(sock: socket.socket, user: str = "postgres", database: str = "postgres"):
    payload = (b"user\x00" + user.encode() + b"\x00" +
               b"database\x00" + database.encode() + b"\x00" + b"\x00")
    sock.sendall(struct.pack("!ii", 8 + len(payload), 196608) + payload)


def pg_error_fields(body: bytes) -> dict:
    out: dict = {}
    i = 0
    while i < len(body):
        code = body[i:i + 1]
        if code == b"\x00":
            break
        val, i = _cstr(body, i + 1)
        out[code.decode("latin-1")] = val
    return out


def grab_postgres(sock: socket.socket):
    """
    Detects the PostgreSQL authentication method without sending any password.
    Returns (banner, auth_code, findings).
    """
    pg_startup(sock, user="postgres")
    findings: list[dict] = []
    for _ in range(10):
        typ, body = pg_recv_msg(sock)
        if typ is None:
            break
        if typ == b"R" and len(body) >= 4:
            code = struct.unpack("!i", body[:4])[0]
            name, _h, sev, title = PG_AUTH.get(code, (f"code{code}", "?", "info", ""))
            # normal state (SCRAM) — just a banner, not a "finding"
            if title and sev != "info":
                findings.append(finding(sev, title, f"auth method = {name}"))
            return f"PostgreSQL (auth: {name})", code, findings
        if typ == b"E":
            f = pg_error_fields(body)
            msg = f.get("M", "")
            sev = "medium" if code_requires_attention(f) else "info"
            banner = f"PostgreSQL (error: {msg})" if msg else "PostgreSQL (error)"
            findings.append(finding(sev, "PostgreSQL: connection error", msg))
            return banner, None, findings
        if typ in (b"Z", b"S", b"K"):
            continue
    return "PostgreSQL", None, findings


def code_requires_attention(fields: dict) -> bool:
    # e.g. "no pg_hba.conf entry" — potentially weak configuration
    m = fields.get("M", "").lower()
    return "pg_hba" in m or "trust" in m


# ---------------------------------------------------------------------------
# Port probing
# ---------------------------------------------------------------------------

def probe_port(ip: str, port: int, timeout: float) -> dict | None:
    service = SERVICE_BY_PORT.get(port, "unknown")
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None

    info = {
        "port": port,
        "service": service,
        "banner": "",
        "version": None,
        "findings": [],
    }

    try:
        raw.settimeout(timeout)
        if service == "ssh":
            info["banner"] = grab_ssh(raw)
        elif service == "http":
            status, headers = do_http(raw, "HEAD", ip)
            info["banner"] = describe_http(status, headers)
        elif service == "https":
            banner, fnd, _headers = grab_https(raw, ip, timeout)
            info["banner"] = banner
            info["findings"].extend(fnd)
            raw = None  # socket already closed inside grab_https
        elif service == "postgres":
            banner, _code, fnd = grab_postgres(raw)
            info["banner"] = banner
            info["findings"].extend(fnd)
        else:
            info.update(probe_unknown(raw, ip, timeout))
    except (OSError, ssl.SSLError, socket.timeout):
        if not info["banner"]:
            info["banner"] = "(no response)"
    finally:
        if raw is not None:
            try:
                raw.close()
            except OSError:
                pass

    info["version"] = extract_version(info["banner"], info["service"])
    return info


def describe_http(status: str, headers: dict) -> str:
    parts = [status] if status else []
    if headers.get("server"):
        parts.append(f"Server: {headers['server']}")
    if headers.get("x-powered-by"):
        parts.append(f"X-Powered-By: {headers['x-powered-by']}")
    return " | ".join(parts) or "(no response)"


def probe_unknown(sock: socket.socket, ip: str, timeout: float) -> dict:
    """Auto-detect: wait for a banner first, otherwise try HTTP."""
    sock.settimeout(min(timeout, 0.7))
    peek = b""
    try:
        peek = sock.recv(256)
    except (socket.timeout, OSError):
        pass

    if peek.startswith(b"SSH-"):
        line = peek.decode("latin-1", "replace").strip().splitlines()[0]
        return {"service": "ssh", "banner": line}

    if peek:
        return {"service": "unknown",
                "banner": peek.decode("latin-1", "replace").strip()[:200]}

    sock.settimeout(timeout)
    status, headers = do_http(sock, "HEAD", ip)
    if status.startswith("HTTP/"):
        return {"service": "http", "banner": describe_http(status, headers)}
    return {"service": "unknown", "banner": "(no response)"}


def extract_version(banner: str, service: str) -> str | None:
    if service == "ssh":
        m = (re.search(r"OpenSSH_([\w.]+)", banner) or
             re.search(r"Dropbear_([\w.]+)", banner) or
             re.search(r"([\w.-]+)_([0-9][\w.]*)", banner))
        if m:
            return m.group(m.lastindex)
    if service in ("http", "https"):
        # take the version from Server:/X-Powered-by:, not from the HTTP/1.0 status line
        for part in banner.split("|"):
            part = part.strip()
            if part.lower().startswith(("server:", "x-powered-by:")):
                m = re.search(r"([A-Za-z][\w.-]*)[/ ]([\d.]+)", part)
                if m:
                    return f"{m.group(1)} {m.group(2)}"
        return None
    return None


# ---------------------------------------------------------------------------
# Vulnerability database
# ---------------------------------------------------------------------------

def load_vulnbase(path: str) -> list[dict]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data.get("rules", [])
    except FileNotFoundError:
        print(f"[!] Vulnerability database '{path}' not found — version matching disabled.")
        return []
    except (json.JSONDecodeError, OSError) as e:
        print(f"[!] Failed to read the vulnerability database: {e}")
        return []


def match_vulns(service: str, text: str, rules: list[dict]) -> list[dict]:
    """Matches banner/version against the rules. Matching only, no exploitation."""
    if not text:
        return []
    out: list[dict] = []
    rule_service = {"https": "http"}.get(service, service)
    for r in rules:
        if r.get("service") not in (rule_service, "*", None):
            continue
        m = re.search(r["pattern"], text, re.IGNORECASE)
        if not m:
            continue
        ver = m.group(r.get("group", 1)) if m.groups() else ""
        vf, vb = r.get("vulnerable_from"), r.get("vulnerable_below")
        # version outside the vulnerable range — not counted as a problem
        if vf and version_below(ver, vf):
            continue
        if vb and not version_below(ver, vb):
            continue
        out.append(finding(
            r.get("severity", "medium"),
            r.get("title", "Match in the vulnerability database"),
            (f"version {ver}: " if ver else "") + r.get("advisory", ""),
            r.get("cve", []),
        ))
    return out


# ---------------------------------------------------------------------------
# Default password checks (only with --check-creds, hard attempt limit)
# ---------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _opener(timeout_ctx: bool = True):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=ctx))


def http_open(ip: str, port: int, use_tls: bool, path: str,
              creds: tuple | None, timeout: float) -> int | None:
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{ip}:{port}{path}"
    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent": f"netaudit/{VERSION}"})
    if creds:
        token = base64.b64encode(f"{creds[0]}:{creds[1]}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    try:
        resp = _opener().open(req, timeout=timeout)
        code = resp.status
        resp.close()
        return code
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


def check_http_creds(ip: str, port: int, use_tls: bool, timeout: float) -> dict:
    result = {"supported": True, "attempts": 0, "success": False,
              "credential": None, "detail": ""}

    # look for a path returning 401 + Basic
    target_path = None
    for path in HTTP_AUTH_PATHS:
        code = http_open(ip, port, use_tls, path, None, timeout)
        if code == 401:
            target_path = path
            break
    if target_path is None:
        result["detail"] = "no HTTP Basic Auth area found"
        return result

    for user, pw in CREDS[:MAX_CREDS_PER_TARGET]:
        result["attempts"] += 1
        code = http_open(ip, port, use_tls, target_path, (user, pw), timeout)
        if code == 200:
            result.update(success=True, credential=f"{user}:{pw}",
                          detail=f"successful login on {target_path}")
            return result

    result["detail"] = f"default passwords did not work ({target_path})"
    return result


# --- PostgreSQL ------------------------------------------------------------

def pg_login(ip: str, port: int, timeout: float, user: str, password: str) -> dict:
    """Full PostgreSQL login. Returns status/detail/version."""
    out = {"status": "fail", "detail": "", "version": None}
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
    except OSError as e:
        out["status"] = "error"
        out["detail"] = str(e)
        return out

    try:
        pg_startup(sock, user=user, database="postgres")
        for _ in range(30):
            typ, body = pg_recv_msg(sock)
            if typ is None:
                out["detail"] = "connection closed"
                return out
            if typ == b"R" and len(body) >= 4:
                code = struct.unpack("!i", body[:4])[0]
                if code == 0:
                    out["status"] = "success"
                    out["detail"] = "trust authentication (no password required)"
                elif code == 3:
                    pw = password.encode() + b"\x00"
                    sock.sendall(b"p" + struct.pack("!i", 4 + len(pw)) + pw)
                elif code == 5 and len(body) >= 8:
                    salt = body[4:8]
                    inner = hashlib.md5((password + user).encode()).hexdigest()
                    outer = hashlib.md5(inner.encode() + salt).hexdigest()
                    pw = ("md5" + outer).encode() + b"\x00"
                    sock.sendall(b"p" + struct.pack("!i", 4 + len(pw)) + pw)
                elif code == 10:
                    out["status"] = "unsupported"
                    out["detail"] = "SCRAM-SHA-256 not supported (stdlib client required)"
                    return out
                else:
                    out["status"] = "unsupported"
                    out["detail"] = f"authentication method code={code}"
                    return out
            elif typ == b"S" and body:
                k, i = _cstr(body, 0)
                v, _ = _cstr(body, i)
                if k == "server_version":
                    out["version"] = v
                if out["status"] == "success" and out["version"]:
                    return out
            elif typ == b"E":
                f = pg_error_fields(body)
                out["detail"] = f.get("M", "")
                out["status"] = "fail"
                return out
            elif typ == b"Z":
                if out["status"] == "success":
                    return out
                out["detail"] = "readyForQuery without authentication"
                return out
        out["detail"] = "message limit exceeded"
        return out
    except (OSError, socket.timeout) as e:
        out["status"] = "error"
        out["detail"] = str(e)
        return out
    finally:
        try:
            sock.close()
        except OSError:
            pass


def check_postgres_creds(ip: str, port: int, timeout: float) -> dict:
    result = {"supported": True, "attempts": 0, "success": False,
              "credential": None, "detail": "", "version": None}
    for user, pw in CREDS[:MAX_CREDS_PER_TARGET]:
        result["attempts"] += 1
        r = pg_login(ip, port, timeout, user, pw)
        if r["version"]:
            result["version"] = r["version"]
        if r["status"] == "success":
            result.update(success=True, credential=f"{user}:{pw}",
                          detail=r["detail"] or "successful login")
            return result
        if r["status"] == "unsupported":
            result["supported"] = False
            result["detail"] = r["detail"]
            return result
        if r["status"] == "error" and not result["detail"]:
            result["detail"] = r["detail"]
    if not result["detail"]:
        result["detail"] = "default passwords did not work"
    return result


# --- SSH -------------------------------------------------------------------

def check_ssh_creds(ip: str, port: int, timeout: float) -> dict:
    result = {"supported": True, "attempts": 0, "success": False,
              "credential": None, "detail": ""}
    try:
        import paramiko  # type: ignore
    except ImportError:
        result["supported"] = False
        result["detail"] = "paramiko not installed — SSH check skipped"
        return result

    last_err = ""
    for user, pw in CREDS[:MAX_CREDS_PER_TARGET]:
        result["attempts"] += 1
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(ip, port=port, username=user, password=pw,
                           timeout=timeout, banner_timeout=timeout,
                           auth_timeout=timeout, allow_agent=False,
                           look_for_keys=False)
            client.close()
            result.update(success=True, credential=f"{user}:{pw}",
                          detail="successful login")
            return result
        except Exception as e:  # noqa: BLE001 — any authorization error
            last_err = str(e)
        finally:
            try:
                client.close()
            except Exception:
                pass
    result["detail"] = f"default passwords did not work ({last_err[:120]})"
    return result


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def resolve_hosts(network: str) -> list[str]:
    try:
        net = ipaddress.ip_network(network, strict=False)
        return [str(h) for h in net.hosts()] or [str(net.network_address)]
    except ValueError:
        # maybe a single IP or a hostname
        try:
            ipaddress.ip_address(network)
            return [network]
        except ValueError:
            return [socket.gethostbyname(network)]


def run_scan(hosts: list[str], ports: list[int], timeout: float,
             workers: int) -> list[dict]:
    results: list[dict] = []
    tasks = [(ip, p) for ip in hosts for p in ports]
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(probe_port, ip, p, timeout): (ip, p)
                   for ip, p in tasks}
        for fut in as_completed(futures):
            done += 1
            if done % 200 == 0 or done == len(tasks):
                print(f"\r[*] checked {done}/{len(tasks)} connections...",
                      end="", flush=True)
            try:
                info = fut.result()
            except Exception:  # noqa: BLE001
                info = None
            if info:
                info["ip"] = futures[fut][0]
                results.append(info)
    print("\r[*] scan complete.                          ")
    return results


def run_cred_checks(open_ports: list[dict], timeout: float, workers: int) -> None:
    def job(item: dict):
        svc = item["service"]
        ip, port = item["ip"], item["port"]
        if svc in ("http", "https"):
            return item, check_http_creds(ip, port, svc == "https", timeout)
        if svc == "postgres":
            return item, check_postgres_creds(ip, port, timeout)
        if svc == "ssh":
            return item, check_ssh_creds(ip, port, timeout)
        return item, None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for fut in as_completed([ex.submit(job, it) for it in open_ports]):
            item, res = fut.result()
            if res:
                item["cred_check"] = res


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def sev_rank(f: dict) -> int:
    return SEV_ORDER.get(f.get("severity", "info"), 9)


def summarize_findings(findings: list[dict]) -> str:
    if not findings:
        return "-"
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    parts = [f"{s.upper()}x{n}" for s, n in
             sorted(counts.items(), key=lambda kv: sev_rank({"severity": kv[0]}))]
    return ", ".join(parts)


def print_table(scan_results: list[dict]) -> None:
    hdr = f"{'HOST':<16} {'PORT':<6} {'STATE':<6} {'SERVICE':<10} {'VERSION':<24} FINDINGS"
    print("\n" + hdr)
    print("-" * len(hdr))
    for item in sorted(scan_results, key=lambda x: (x["ip"], x["port"])):
        print(f"{item['ip']:<16} {item['port']:<6} {'open':<6} "
              f"{item['service']:<10} {(item.get('version') or '-'):<24} "
              f"{summarize_findings(item['findings'])}")


def print_details(scan_results: list[dict]) -> int:
    total = 0
    details: list[tuple[str, dict]] = []
    for item in scan_results:
        for f in item["findings"]:
            details.append((item, f))
        cc = item.get("cred_check")
        if cc and cc.get("success"):
            details.append((item, finding(
                "critical",
                "Default password works!",
                f"{item['service']}: {cc['credential']} ({cc.get('detail','')})")))

    if not details:
        print("\n[OK] No problems found.")
        return 0

    print("\n=== Problems found ===")
    for item, f in sorted(details, key=lambda t: sev_rank(t[1])):
        cve = (" " + ", ".join(f["cve"])) if f["cve"] else ""
        print(f"[{f['severity'].upper():<8}] {item['ip']}:{item['port']}"
              f"  {f['title']}{cve}")
        if f.get("detail"):
            print(f"           -> {f['detail']}")
        if f.get("severity", "info") != "info":
            total += 1
    if total == 0:
        print("  (informational notes only, no critical problems)")
    return total


def write_report(path: str, meta: dict, hosts_total: int,
                 scan_results: list[dict], problem_count: int) -> None:
    up_ips = sorted({r["ip"] for r in scan_results})
    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0,
                                  "low": 0, "info": 0}
    for r in scan_results:
        for f in r["findings"]:
            sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
        cc = r.get("cred_check")
        if cc and cc.get("success"):
            sev_counts["critical"] += 1

    hosts = []
    for ip in up_ips:
        ports = []
        for r in sorted([x for x in scan_results if x["ip"] == ip],
                        key=lambda x: x["port"]):
            ports.append({
                "port": r["port"],
                "service": r["service"],
                "state": "open",
                "banner": r["banner"],
                "version": r["version"],
                "findings": r["findings"],
                "cred_check": r.get("cred_check"),
            })
        hosts.append({"ip": ip, "ports": ports})

    report = {
        "meta": meta,
        "summary": {
            "hosts_total": hosts_total,
            "hosts_up": len(up_ips),
            "open_ports": len(scan_results),
            "problems": problem_count,
            "by_severity": sev_counts,
        },
        "hosts": hosts,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Port scanner and security audit (stdlib only).",
        epilog="Use only on networks you have permission to scan.")
    p.add_argument("network", help="CIDR (192.168.1.0/24), a single IP or a hostname")
    p.add_argument("--ports", default=",".join(map(str, DEFAULT_PORTS)),
                   help="ports: '22,80,443' or ranges like '8000-8010' "
                        f"(default {','.join(map(str, DEFAULT_PORTS))})")
    p.add_argument("--timeout", type=float, default=1.0,
                   help="connection timeout, seconds (default 1.0)")
    p.add_argument("--workers", type=int, default=100,
                   help="number of threads (default 100)")
    p.add_argument("--max-hosts", type=int, default=4096,
                   help="maximum hosts in one subnet (default 4096)")
    p.add_argument("--out", default="report.json",
                   help="where to save the JSON report (default report.json)")
    p.add_argument("--vulnbase", default=None,
                   help="path to the vulnerability database (default vulnbase.json "
                        "next to the script)")
    p.add_argument("--check-creds", action="store_true",
                   help="check default passwords (at most 5 attempts per target)")
    p.add_argument("--yes", action="store_true",
                   help="do not ask for confirmation for --check-creds")
    return p


def confirm_creds(auto_yes: bool) -> bool:
    if auto_yes:
        return True
    if not sys.stdin.isatty():
        print("[!] Non-interactive mode: pass --yes to use --check-creds.")
        return False
    print(DISCLAIMER)
    print("[!] --check-creds performs login attempts with default passwords.")
    try:
        ans = input("    Confirm that you have permission: [y/N] ")
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return ans.strip().lower() in ("y", "yes", "д", "да")


def main(argv: list[str] | None = None) -> int:
    # Windows: console is not UTF-8 by default — fix Cyrillic output
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass

    args = build_parser().parse_args(argv)

    try:
        ports = parse_ports(args.ports)
    except (ValueError, TypeError) as e:
        print(f"[!] Invalid port list: {e}", file=sys.stderr)
        return 2

    try:
        hosts = resolve_hosts(args.network)
    except (socket.gaierror, OSError) as e:
        print(f"[!] Failed to resolve address: {e}", file=sys.stderr)
        return 2

    if not hosts:
        print("[!] Empty subnet.", file=sys.stderr)
        return 2
    if len(hosts) > args.max_hosts:
        print(f"[!] Subnet too large: {len(hosts)} hosts "
              f"(--max-hosts limit {args.max_hosts}).", file=sys.stderr)
        return 2

    do_creds = False
    if args.check_creds:
        if not confirm_creds(args.yes):
            print("[!] Password check cancelled.", file=sys.stderr)
            return 2
        do_creds = True

    vulnbase_path = args.vulnbase
    if vulnbase_path is None:
        vulnbase_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "vulnbase.json")
    rules = load_vulnbase(vulnbase_path)

    print(DISCLAIMER)
    print(f"[i] netaudit {VERSION} | target: {args.network} | hosts: {len(hosts)} "
          f"| ports: {','.join(map(str, ports))} | timeout: {args.timeout}s")

    started = time.time()
    try:
        scan_results = run_scan(hosts, ports, args.timeout, args.workers)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.", file=sys.stderr)
        return 130

    if do_creds and scan_results:
        print(f"[*] checking default passwords on {len(scan_results)} open ports "
              f"(at most {MAX_CREDS_PER_TARGET} attempts per target)...")
        try:
            run_cred_checks(scan_results, args.timeout, min(args.workers, 50))
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user.", file=sys.stderr)
            return 130

    # match against the vulnerability database
    for item in scan_results:
        svc = item["service"]
        if svc in ("ssh", "http", "https"):
            text = item["banner"]
        elif svc == "postgres":
            cc = item.get("cred_check") or {}
            text = item.get("version") or cc.get("version") or ""
        else:
            text = item["banner"]
        item["findings"].extend(match_vulns(svc, text, rules))
        item["findings"].sort(key=sev_rank)

    if not scan_results:
        print("\n[!] No open ports found (are all hosts down?).")

    print_table(scan_results)
    problems = print_details(scan_results)

    up_count = len({r["ip"] for r in scan_results})
    print(f"\n[i] Total: hosts on the network {len(hosts)}, with open ports {up_count}, "
          f"open ports {len(scan_results)}, problems {problems}")

    meta = {
        "tool": "netaudit",
        "version": VERSION,
        "target": args.network,
        "ports": ports,
        "timeout": args.timeout,
        "check_creds": do_creds,
        "cred_attempts_limit": MAX_CREDS_PER_TARGET,
        "hosts_scanned": len(hosts),
        "vulnbase": vulnbase_path if rules else None,
        "started_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_sec": round(time.time() - started, 2),
    }
    try:
        write_report(args.out, meta, len(hosts), scan_results, problems)
        print(f"[i] Report saved: {args.out}")
    except OSError as e:
        print(f"[!] Failed to save the report: {e}", file=sys.stderr)
        return 2

    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
