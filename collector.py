#!/usr/bin/env python3
"""Collect supported proxy share links from configured text sources."""
import base64
import os
import re
import sys
from urllib.parse import urlsplit

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

def extract_links(text: str):
    text = decode_possible_base64(text)
    # Links are separated by whitespace, quotes, commas, or HTML delimiters.
    pattern = re.compile(
        r"(?i)(?:vless|vmess|trojan|ss|socks5?|https?)://[^\s\"'<>]+"
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
    for source in sources:
        try:
            parsed = urlsplit(source)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                print(f"Skipping invalid source URL: {source}")
                continue
            response = session.get(source, timeout=TIMEOUT, headers=HEADERS, stream=True)
            response.raise_for_status()
            chunks, size = [], 0
            for chunk in response.iter_content(65536, decode_unicode=False):
                size += len(chunk)
                if size > MAX_SOURCE_BYTES:
                    raise ValueError("source exceeds 5 MiB limit")
                chunks.append(chunk)
            body = b"".join(chunks).decode("utf-8", errors="replace")
            found = list(extract_links(body))
            print(f"{source}: found {len(found)} candidate(s)")
            for link in found:
                if link not in seen:
                    seen.add(link)
                    links.append(link)
        except Exception as exc:
            print(f"Source failed ({source}): {type(exc).__name__}: {exc}")

    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(links) + ("\n" if links else ""))
    print(f"Wrote {len(links)} unique candidates to {out_file}")

if __name__ == "__main__":
    main()
