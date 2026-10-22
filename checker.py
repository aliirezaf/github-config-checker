#!/usr/bin/env python3
"""Test proxy share links using Sing-box and a local SOCKS listener."""
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import random
import socket
import subprocess
import tempfile
import time
from urllib.parse import urlsplit, parse_qs, unquote

from collector import dedupe_key

import requests

SING_BOX = os.environ.get("SING_BOX", "./sing-box")
INPUT = os.environ.get("COLLECTED_FILE", "output/collected.txt")
GROUPED_INPUT = os.environ.get("GROUPED_FILE", "output/collected_by_source.json")
OUT_DIR = os.environ.get("OUTPUT_DIR", "output")
TEST_URLS = [u.strip() for u in os.environ.get("TEST_URLS", "https://www.gstatic.com/generate_204,https://cp.cloudflare.com/generate_204").split(",") if u.strip()]
TIMEOUT = int(os.environ.get("PROXY_TIMEOUT", "6"))
MAX_CANDIDATES = int(os.environ.get("MAX_CANDIDATES", "500"))
FINAL_LIMIT = int(os.environ.get("FINAL_LIMIT", "0"))
RECHECK_LIMIT = int(os.environ.get("RECHECK_LIMIT", "500"))
TEST_WORKERS = max(1, int(os.environ.get("TEST_WORKERS", "20")))
STABILITY_ROUNDS = max(1, int(os.environ.get("STABILITY_ROUNDS", "3")))
STABILITY_INTERVAL = max(0, int(os.environ.get("STABILITY_INTERVAL", "10"))
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
    """Require HTTP 204 from every independent probe URL."""
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
        latencies = []
        for url in TEST_URLS:
            started = time.monotonic()
            result = subprocess.run(
                ["curl", "--silent", "--show-error", "--max-time", str(TIMEOUT),
                 "--connect-timeout", str(min(3, TIMEOUT)), "--output", os.devnull,
                 "--write-out", "%{http_code}", "--proxy", "socks5h://127.0.0.1:" + str(port),
                 url],
                capture_output=True, text=True, timeout=TIMEOUT + 2
            )
            code = result.stdout.strip()
            elapsed = max(1, int((time.monotonic() - started) * 1000))
            if result.returncode != 0 or code != "204":
                raise RuntimeError("Probe failed for " + url + ": expected HTTP 204, got " + (code or "no status"))
            latencies.append(elapsed)
        return round(sum(latencies) / len(latencies)), "204", latencies
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
                while bucket and dedupe_key(bucket[0]) in seen:
                    bucket.pop(0)
                if bucket and len(candidates) < MAX_CANDIDATES:
                    item = bucket.pop(0)
                    seen.add(dedupe_key(item))
                    candidates.append(item)
        if not candidates:
            with open(INPUT, encoding="utf-8") as f:
                candidates = [x.strip() for x in f if x.strip()][:MAX_CANDIDATES]
    except (OSError, ValueError, TypeError):
        candidates = candidates[:MAX_CANDIDATES]
    # Preserve source provenance so future runs can compare which feeds yield
    # genuinely working configs, not just the largest number of candidates.
    source_by_link = {}
    try:
        with open(GROUPED_INPUT, encoding="utf-8") as f:
            source_groups = json.load(f)
        for source, items in source_groups.items():
            if isinstance(items, list):
                for item in items:
                    source_by_link.setdefault(dedupe_key(item), []).append(source)
    except (OSError, ValueError, TypeError):
        source_by_link = {}

    working, results = [], []
    protocol_files = {"vless": [], "vmess": [], "trojan": [], "ss": [], "socks": [], "http": []}
    results_by_link = {}
    passed = []

    def test_with_retry(link, label):
        try:
            return run_one(link)
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            raise
        except Exception as first_exc:
            print(f"[{label}] RETRY: {type(first_exc).__name__}: {str(first_exc)[:120]}")
            time.sleep(0.6)
            return run_one(link)

    supported_candidates = []
    for link in candidates:
        proto = link.split(":", 1)[0].lower()
        if proto not in SUPPORTED:
            results_by_link[link] = {"protocol": proto, "sources": source_by_link.get(dedupe_key(link), []),
                "result": "failed", "reason": "unsupported scheme"}
        else:
            supported_candidates.append(link)

    print(f"Initial test: {len(supported_candidates)} supported candidates, {TEST_WORKERS} workers, timeout={TIMEOUT}s")
    with ThreadPoolExecutor(max_workers=TEST_WORKERS) as pool:
        futures = {pool.submit(test_with_retry, link, f"INITIAL {i}/{len(supported_candidates)}"): (i, link)
                   for i, link in enumerate(supported_candidates, 1)}
        for future in as_completed(futures):
            i, link = futures[future]
            proto = link.split(":", 1)[0].lower()
            try:
                latency, status, probes = future.result()
                passed.append((latency, link, proto, probes))
                results_by_link[link] = {"protocol": proto, "sources": source_by_link.get(dedupe_key(link), []),
                    "latency_ms": latency, "probe_latencies_ms": probes, "http_status": status,
                    "result": "passed_initial"}
                print(f"[{i}/{len(supported_candidates)}] PASS {proto} avg={latency}ms probes={probes}")
            except Exception as exc:
                results_by_link[link] = {"protocol": proto, "sources": source_by_link.get(dedupe_key(link), []),
                    "result": "failed", "reason": str(exc)[:180]}
                print(f"[{i}/{len(supported_candidates)}] FAIL {proto}: {type(exc).__name__}: {exc}")

    passed.sort(key=lambda item: item[0])
    finalists = passed[:max(0, RECHECK_LIMIT)]
    verified = []
    # Stability is checked in separate rounds. A candidate is published only
    # if every round succeeds; a transient success is not enough.
    active = {link: {"proto": proto, "latencies": [first_latency], "probes": list(first_probes)}
              for first_latency, link, proto, first_probes in finalists}
    for round_no in range(1, STABILITY_ROUNDS + 1):
        if round_no > 1 and STABILITY_INTERVAL:
            print(f"Waiting {STABILITY_INTERVAL}s before stability round {round_no}/{STABILITY_ROUNDS}")
            time.sleep(STABILITY_INTERVAL)
        print(f"Stability round {round_no}/{STABILITY_ROUNDS}: testing {len(active)} candidates")
        round_ok = {}
        with ThreadPoolExecutor(max_workers=TEST_WORKERS) as pool:
            futures = {pool.submit(test_with_retry, link, f"ROUND {round_no}"): link for link in list(active)}
            for future in as_completed(futures):
                link = futures[future]
                try:
                    latency, status, probes = future.result()
                    round_ok[link] = (latency, status, probes)
                except Exception as exc:
                    results_by_link[link]["result"] = "failed_stability"
                    results_by_link[link]["failed_round"] = round_no
                    results_by_link[link]["reason"] = str(exc)[:180]
                    print(f"[ROUND {round_no}] DROP {active[link]['proto']}: {type(exc).__name__}: {exc}")
        for link in list(active):
            if link not in round_ok:
                del active[link]
                continue
            latency, status, probes = round_ok[link]
            active[link]["latencies"].append(latency)
            active[link]["probes"].extend(probes)
            results_by_link[link]["latency_ms"] = round(active[link]["latencies"] and
                sum(active[link]["latencies"]) / len(active[link]["latencies"]))
            results_by_link[link]["probe_latencies_ms"] = active[link]["probes"]
            results_by_link[link]["http_status"] = status
            results_by_link[link]["stability_rounds_passed"] = round_no
            results_by_link[link]["result"] = "working" if round_no == STABILITY_ROUNDS else "checking_stability"

    for link, data in active.items():
        score = round(sum(data["latencies"]) / len(data["latencies"]))
        verified.append((score, link, data["proto"]))
        results_by_link[link]["result"] = "working"
        results_by_link[link]["rechecked"] = True
        results_by_link[link]["stability_rounds_required"] = STABILITY_ROUNDS
    verified.sort(key=lambda item: item[0])
    selected = verified if FINAL_LIMIT <= 0 else verified[:FINAL_LIMIT]
    working = [item[1] for item in selected]
    for _, link, proto in selected:
        key = "ss" if proto == "ss" else ("socks" if proto in ("socks", "socks5") else ("http" if proto in ("http", "https") else proto))
        protocol_files[key].append(link)
    results = [results_by_link[link] for link in candidates if link in results_by_link]

    def write_lines(path, lines):
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + ("\n" if lines else ""))

    write_lines(os.path.join(OUT_DIR, "working.txt"), working)
    write_lines(os.path.join(OUT_DIR, "all.txt"), working)
    for proto, lines in protocol_files.items():
        write_lines(os.path.join(OUT_DIR, f"{proto}.txt"), lines)
    # Aggregate source quality from this run. These metrics are descriptive:
    # feeds overlap, so a link appearing in multiple feeds is credited to each.
    source_stats = {}
    for source, items in source_groups.items() if "source_groups" in locals() else []:
        source_stats[source] = {"candidates": len(set(items)) if isinstance(items, list) else 0,
                                "tested": 0, "working": 0}
    for item in candidates:
        result = results_by_link.get(item, {})
        for source in result.get("sources", []):
            stats = source_stats.setdefault(source, {"candidates": 0, "tested": 0, "working": 0})
            stats["tested"] += 1
            if result.get("result") == "working":
                stats["working"] += 1
    for stats in source_stats.values():
        stats["success_rate_pct"] = round(100 * stats["working"] / stats["tested"], 1) if stats["tested"] else None

    with open(os.path.join(OUT_DIR, "status.json"), "w", encoding="utf-8") as f:
        json.dump({"checked_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "tested": len(results), "passed_initial": len(passed), "stability_candidates": len(finalists), "stability_rounds_required": STABILITY_ROUNDS, "stability_interval_seconds": STABILITY_INTERVAL, "test_workers": TEST_WORKERS, "rechecked": sum(1 for x in results if x.get("stability_rounds_passed")), "working": len(working),
                   "test_urls": TEST_URLS, "timeout_seconds": TIMEOUT, "final_limit": (None if FINAL_LIMIT <= 0 else FINAL_LIMIT),
                   "source_stats": source_stats, "results": results},
                  f, ensure_ascii=False, indent=2)
    print(f"Finished: {len(working)} configs passed all {STABILITY_ROUNDS} stability rounds; {len(passed)} passed initial tests; {len(finalists)} entered stability testing")

if __name__ == "__main__":
    main()
