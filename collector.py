#!/usr/bin/env python3
"""Collect supported proxy share links from configured text sources."""
import base64
import os
import re
import sys
import json
import time
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

import requests

SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "socks://", "socks5://", "http://")
MAX_SOURCE_BYTES = 5 * 1024 * 1024
TIMEOUT = 15
HEADERS = {"User-Agent": "GitHub-Config-Checker/1.0"}

def decode_possible_base64(text: str) -> str:
    cleaned = "".join(text.split())
    if not cleaned or len(cleaned) < 16:
        return text
    # Avoid treating ordinary text/URLs as base64.
    if not re.fullmatch(r"[A-Za-z0-9_\-+/=]+", cleaned):
        return text
    padded = cleaned + "=" * ((4 - len(cleaned) % 4) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            raw = decoder(padded)
            decoded = raw.decode("utf-8")
            if any(s in decoded.lower() for s in SCHEMES):
                return decoded
        except Exception:
            pass
    return text

def dedupe_key(link: str) -> str:
    """Build a conservative identity key without changing the published URI.

    URI fragments are display labels, not connection settings. For URI forms
    with query parameters, parameter order is normalized; the original link is
    still kept as the representative output value.
    """
    try:
        parsed = urlsplit(link.strip())
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc
        if parsed.hostname:
            credentials = ""
            hostport = netloc
            if "@" in netloc:
                credentials, hostport = netloc.rsplit("@", 1)
                credentials += "@"
            host = parsed.hostname.lower()
            if ":" in host and not host.startswith("["):
                host = "[" + host + "]"
            try:
                port = parsed.port
            except ValueError:
                return link.strip()
            netloc = credentials + host + ((":" + str(port)) if port is not None else "")
        query = parsed.query
        if query:
            query = urlencode(sorted(parse_qsl(query, keep_blank_values=True)), doseq=True)
        return urlunsplit((scheme, netloc, parsed.path, query, ""))
    except (TypeError, ValueError):
        return link.strip()

def extract_links(text: str):
    text = decode_possible_base64(text)
    # Links are separated by whitespace, quotes, commas, or HTML delimiters.
    # Some feeds concatenate links without a newline. Stop a match if the
    # next URI scheme starts immediately after the current link.
    pattern = re.compile(
        r"(?i)(?:vless|vmess|trojan|ss|socks5?|https?)://(?:(?!(?:vless|vmess|trojan|ss|socks5?|https?)://)[^\s\"'<>])+"
    )
    for match in pattern.findall(text):
        link = match.rstrip("),;]")
        if link.lower().startswith("http://"):
            try:
                from urllib.parse import urlsplit
                parsed = urlsplit(link)
                if not parsed.username or not parsed.password or not parsed.port:
                    continue
            except Exception:
                continue
        if len(link) <= 8192:
            yield link

def main():
    source_file = os.environ.get("SOURCES_FILE", "sources.txt")
    out_file = os.environ.get("COLLECTED_FILE", "output/collected.txt")
    os.makedirs(os.path.dirname(out_file) or ".", exist_ok=True)

    try:
        with open(source_file, encoding="utf-8") as f:
            sources = [
                line.strip() for line in f
                if line.strip() and not line.lstrip().startswith("#")
            ]
    except FileNotFoundError:
        print(f"Missing {source_file}", file=sys.stderr)
        sys.exit(1)

    session = requests.Session()
    links, seen = [], set()
    by_source = {}
    source_counts = {}
    duplicates_global = 0
    duplicates_within_source = 0
    for source in sources:
        try:
            parsed = urlsplit(source)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                print(f"Skipping invalid source URL: {source}")
                continue
            response = None
            for attempt in range(3):
                try:
                    response = session.get(source, timeout=TIMEOUT, headers=HEADERS, stream=True)
                    response.raise_for_status()
                    break
                except requests.RequestException:
                    if response is not None:
                        response.close()
                    if attempt == 2:
                        raise
                    delay = 1.5 * (attempt + 1)
                    print(f"Temporary source error; retrying in {delay:.1f}s ({attempt + 2}/3): {source}")
                    time.sleep(delay)
            try:
                chunks, size = [], 0
                for chunk in response.iter_content(65536, decode_unicode=False):
                    size += len(chunk)
                    if size > MAX_SOURCE_BYTES:
                        raise ValueError("source exceeds 5 MiB limit")
                    chunks.append(chunk)
                body = b"".join(chunks).decode("utf-8", errors="replace")
            finally:
                response.close()
            found = list(extract_links(body))
            unique_source = []
            seen_source = set()
            for link in found:
                key = dedupe_key(link)
                if key in seen_source:
                    duplicates_within_source += 1
                    continue
                seen_source.add(key)
                unique_source.append(link)
                if key not in seen:
                    seen.add(key)
                    links.append(link)
                else:
                    duplicates_global += 1
            by_source[source] = unique_source
            source_counts[source] = {
                "found": len(found),
                "unique": len(unique_source),
                "duplicates_within_source": len(found) - len(unique_source),
            }
            print(f"{source}: found {len(found)}, unique {len(unique_source)}, duplicates {len(found) - len(unique_source)}")
        except Exception as exc:
            print(f"Source failed ({source}): {type(exc).__name__}: {exc}")

    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(links) + ("\n" if links else ""))
    print(f"Wrote {len(links)} unique candidates to {out_file}")
    print(f"Duplicate summary: {duplicates_global} duplicates across sources; {duplicates_within_source} duplicates within sources")
    grouped_file = os.environ.get("GROUPED_FILE", "output/collected_by_source.json")
    with open(grouped_file, "w", encoding="utf-8") as f:
        json.dump(by_source, f, ensure_ascii=False)
    stats_file = os.environ.get("SOURCE_STATS_FILE", "output/source_collection_stats.json")
    with open(stats_file, "w", encoding="utf-8") as f:
        json.dump({
            "sources_total": len(sources),
            "sources_succeeded": len(by_source),
            "unique_candidates_global": len(links),
            "duplicates_across_sources": duplicates_global,
            "duplicates_within_sources": duplicates_within_source,
            "source_stats": source_counts,
        }, f, ensure_ascii=False, indent=2)
    print(f"Wrote per-source candidates to {grouped_file}")
    print(f"Wrote collection statistics to {stats_file}")

if __name__ == "__main__":
    main()
