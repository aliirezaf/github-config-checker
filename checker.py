#!/usr/bin/env python3
"""Test proxy share links using Sing-box and a local SOCKS listener."""
import base64
import json
import os
import random
import socket
import subprocess
import tempfile
import time
from urllib.parse import urlsplit, parse_qs, unquote

import requests

SING_BOX = os.environ.get("SING_BOX", "./sing-box")
INPUT = os.environ.get("COLLECTED_FILE", "output/collected.txt")
GROUPED_INPUT = os.environ.get("GROUPED_FILE", "output/collected_by_source.json")
OUT_DIR = os.environ.get("OUTPUT_DIR", "output")
TEST_URL = os.environ.get("TEST_URL", "https://www.gstatic.com/generate_204")
TIMEOUT = int(os.environ.get("PROXY_TIMEOUT", "8"))
MAX_CANDIDATES = int(os.environ.get("MAX_CANDIDATES", "400"))
SUPPORTED = {"vless", "vmess", "trojan", "ss", "socks", "socks5", "http", "https"}

def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def parse_vmess(link):
    payload = link[len("vmess://"):]
    payload += "=" * ((4 - len(payload) % 4) % 4)
    data = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
    host = data.get("add") or data.get("address")
    port = int(data.get("port", 0))
    if not host or not (1 <= port <= 65535):
        raise ValueError("VMess link missing valid host/port")
    tls_enabled = str(data.get("tls", "")).lower() in ("tls", "true", "1")
    net = (data.get("net") or "tcp").lower()
    outbound = {
        "type": "vmess", "tag": "proxy", "server": host, "server_port": port,
        "uuid": data.get("id"), "security": data.get("scy") or "auto",
        "alter_id": int(data.get("aid", 0) or 0)
    }
    if not outbound["uuid"]:
        raise ValueError("VMess link missing UUID")
    if tls_enabled:
        outbound["tls"] = {"enabled": True}
        sni = data.get("sni") or data.get("host")
        if sni:
            outbound["tls"]["server_name"] = sni
        if str(data.get("allowInsecure", "false")).lower() == "true":
            outbound["tls"]["insecure"] = True
    if net == "ws":
        outbound["transport"] = {"type": "ws", "path": data.get("path") or "/"}
        ws_host = data.get("host")
        if ws_host:
            outbound["transport"]["headers"] = {"Host": ws_host}
    elif net == "grpc":
        outbound["transport"] = {"type": "grpc", "service_name": data.get("path") or ""}
    elif net not in ("tcp", "http"):
        raise ValueError(f"Unsupported VMess transport: {net}")
    return outbound

def parse_link(link):
    scheme = link.split(":", 1)[0].lower()
    if scheme not in SUPPORTED:
        raise ValueError("unsupported scheme")
    if scheme == "vmess":
        return parse_vmess(link)

    if scheme == "ss":
        # Modern SIP002: ss://base64(method:password)@host:port
        # Legacy whole-payload Base64 is also supported.
        payload = link[5:].split("#", 1)[0]
        if "@" not in payload:
            decoded = base64.urlsafe_b64decode(payload + "=" * ((4-len(payload)%4)%4)).decode()
            if "@" not in decoded:
                raise ValueError("unrecognized Shadowsocks URI")
            payload = decoded
        userinfo, address = payload.rsplit("@", 1)
        if ":" not in userinfo:
            userinfo = base64.urlsafe_b64decode(userinfo + "=" * ((4-len(userinfo)%4)%4)).decode()
        method, password = userinfo.split(":", 1)
        parsed = urlsplit("ss://" + address)
        if not parsed.hostname or not parsed.port:
            raise ValueError("invalid Shadowsocks host/port")
        return {"type": "shadowsocks", "tag": "proxy", "server": parsed.hostname,
                "server_port": parsed.port, "method": unquote(method), "password": unquote(password)}

    parsed = urlsplit(link)
    if not parsed.hostname or not parsed.port:
        raise ValueError("URI missing host or port")
    host, port = parsed.hostname, parsed.port
    user = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    q = parse_qs(parsed.query)
    tls_on = q.get("security", [""])[0].lower() == "tls" or scheme == "https"
    outbound = {"tag": "proxy", "server": host, "server_port": port}
    if scheme == "vless":
        outbound.update({"type": "vless", "uuid": user, "flow": q.get("flow", [""])[0]})
    elif scheme == "trojan":
        outbound.update({"type": "trojan", "password": password or user})
    elif scheme in ("socks", "socks5"):
        outbound.update({"type": "socks", "version": "5"})
        if user:
            outbound["username"] = user
        if password:
            outbound["password"] = password
    else:
        outbound.update({"type": "http"})
        if user:
            outbound["username"] = user
        if password:
            outbound["password"] = password

    if tls_on or scheme in ("vless", "trojan"):
        outbound["tls"] = {"enabled": tls_on or scheme in ("vless", "trojan")}
        sni = q.get("sni", q.get("serverName", [""]))[0]
        if sni:
            outbound["tls"]["server_name"] = sni
        fp = q.get("fp", [""])[0]
        if fp:
            outbound["tls"]["utls"] = {"enabled": True, "fingerprint": fp}
        if q.get("allowInsecure", ["false"])[0].lower() == "true":
            outbound["tls"]["insecure"] = True

    transport = q.get("type", [""])[0].lower()
    if transport == "ws":
        path = q.get("path", ["/"])[0]
        headers = {}
        host_header = q.get("host", [""])[0]
        if host_header:
            headers["Host"] = host_header
        outbound["transport"] = {"type": "ws", "path": path}
        if headers:
            outbound["transport"]["headers"] = headers
    elif transport == "grpc":
        outbound["transport"] = {"type": "grpc", "service_name": q.get("serviceName", [""])[0]}
    elif transport not in ("", "tcp", "raw"):
        raise ValueError(f"unsupported transport: {transport}")

    # Reality settings are required for many VLESS Reality links.
    if q.get("security", [""])[0].lower() == "reality":
        outbound["tls"] = {
            "enabled": True,
            "server_name": q.get("sni", [""])[0],
            "reality": {
                "enabled": True,
                "public_key": q.get("pbk", [""])[0],
                "short_id": q.get("sid", [""])[0],
            },
            "utls": {"enabled": True, "fingerprint": q.get("fp", ["chrome"])[0]},
        }
        if not outbound["tls"]["reality"]["public_key"]:
            raise ValueError("Reality link missing pbk")
    return outbound

def run_one(link):
    started = time.monotonic()
    outbound = parse_link(link)
    port = free_port()
    config = {
        "log": {"level": "error"},
        "inbounds": [{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": port}],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        "route": {"final": "proxy"}
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8", delete=False) as f:
        json.dump(config, f)
        cfg_path = f.name
    proc = None
    try:
        proc = subprocess.Popen([SING_BOX, "run", "-c", cfg_path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError("Sing-box exited during startup; config may be unsupported")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise TimeoutError("local proxy did not start")
        # curl supports SOCKS5 hostname resolution through the proxy.
        result = subprocess.run(
            ["curl", "--silent", "--show-error", "--max-time", str(TIMEOUT),
             "--connect-timeout", str(min(4, TIMEOUT)), "--output", os.devnull,
             "--write-out", "%{http_code}", "--proxy", f"socks5h://127.0.0.1:{port}",
             TEST_URL],
            capture_output=True, text=True, timeout=TIMEOUT + 3
        )
        code = result.stdout.strip()
        if result.returncode != 0 or code != "204":
            raise RuntimeError(f"HTTPS probe expected HTTP 204, got {code or chr(110)+chr(111)+chr(32)+chr(115)+chr(116)+chr(97)+chr(116)+chr(117)+chr(115)}")
        return max(1, int((time.monotonic() - started) * 1000)), code
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        try:
            os.unlink(cfg_path)
        except OSError:
            pass

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    try:
        with open(INPUT, encoding="utf-8") as f:
            candidates = [x.strip() for x in f if x.strip()]
    except FileNotFoundError:
        candidates = []
    # Round-robin candidates across each source so the first large feed cannot
    # monopolize the test budget. Fall back to the flat file if grouping is absent.
    try:
        with open(GROUPED_INPUT, encoding="utf-8") as f:
            grouped = json.load(f)
        buckets = [list(dict.fromkeys(v)) for v in grouped.values() if isinstance(v, list) and v]
        candidates = []
        seen = set()
        while len(candidates) < MAX_CANDIDATES and any(buckets):
            for bucket in buckets:
                while bucket and bucket[0] in seen:
                    bucket.pop(0)
                if bucket and len(candidates) < MAX_CANDIDATES:
                    item = bucket.pop(0)
                    seen.add(item)
                    candidates.append(item)
        if not candidates:
            with open(INPUT, encoding="utf-8") as f:
                candidates = [x.strip() for x in f if x.strip()][:MAX_CANDIDATES]
    except (OSError, ValueError, TypeError):
        candidates = candidates[:MAX_CANDIDATES]
    working, results = [], []
    protocol_files = {"vless": [], "vmess": [], "trojan": [], "ss": [], "socks": [], "http": []}
    for i, link in enumerate(candidates, 1):
        proto = link.split(":", 1)[0].lower()
        if proto not in SUPPORTED:
            continue
        try:
            latency, status = run_one(link)
            working.append(link)
            key = "ss" if proto == "ss" else ("socks" if proto in ("socks", "socks5") else ("http" if proto in ("http", "https") else proto))
            protocol_files[key].append(link)
            results.append({"protocol": proto, "latency_ms": latency, "http_status": status, "result": "working"})
            print(f"[{i}/{len(candidates)}] OK {proto} {latency}ms HTTP {status}")
        except Exception as exc:
            results.append({"protocol": proto, "result": "failed", "reason": str(exc)[:180]})
            print(f"[{i}/{len(candidates)}] FAIL {proto}: {type(exc).__name__}: {exc}")

    def write_lines(path, lines):
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + ("\n" if lines else ""))

    write_lines(os.path.join(OUT_DIR, "working.txt"), working)
    write_lines(os.path.join(OUT_DIR, "all.txt"), working)
    for proto, lines in protocol_files.items():
        write_lines(os.path.join(OUT_DIR, f"{proto}.txt"), lines)
    with open(os.path.join(OUT_DIR, "status.json"), "w", encoding="utf-8") as f:
        json.dump({"checked_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "tested": len(results), "working": len(working), "results": results},
                  f, ensure_ascii=False, indent=2)
    print(f"Finished: {len(working)}/{len(results)} passed")

if __name__ == "__main__":
    main()
