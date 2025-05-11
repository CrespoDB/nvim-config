#!/usr/bin/env python3
import sys
import os
import argparse
import asyncio
import aiohttp
import time
import json
import base64
from urllib.parse import urlparse
from .ioc_utils import extract_iocs, save_buffer

# API keys - const ENABLED_SERVICES will check what keys are provided.
API_KEYS = {
    "abuseipdb": os.getenv("ABUSEIPDB_KEY"),
    "virustotal": os.getenv("VT_KEY"),
    "urlscan": os.getenv("URLSCAN_KEY"),
    "malwarebazaar": os.getenv("MALWAREBAZAAR_KEY"),
}

ENABLED_SERVICES = {k: v for k, v in API_KEYS.items() if v}


# ANSI escape codes for color & style
RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[31m"
GREEN   = "\033[32m"
YELLOW  = "\033[33m"
BLUE    = "\033[34m"
MAGENTA = "\033[35m"
CYAN    = "\033[36m"

# API endpoints
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VT_FILE_URL   = "https://www.virustotal.com/api/v3/files/{}"
VT_URL_LOOKUP = "https://www.virustotal.com/api/v3/urls/{}"
VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{}"
VT_IP_URL     = "https://www.virustotal.com/api/v3/ip_addresses/{}"
URLSCAN_SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
URLSCAN_RESULT_URL = "https://urlscan.io/api/v1/result/{}"

# Cache files
CACHE_FILE   = os.path.expanduser("~/.cache/ioc_enrichment_cache.json")
BUFFER_FILE  = os.path.expanduser("~/.cache/ioc_buffer.json")


def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    return {}


def save_cache(cache):
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)


def is_stale(entry, max_age_hours=24):
    if not entry or "timestamp" not in entry:
        return True
    return (time.time() - entry["timestamp"]) > (max_age_hours * 3600)


async def fetch_with_retries(session, url, headers=None, params=None,
                             max_retries=3, backoff_factor=1, timeout=10):
    for attempt in range(max_retries):
        try:
            async with session.get(url,
                                   headers=headers,
                                   params=params,
                                   timeout=timeout) as resp:
                resp.raise_for_status()
                return await resp.json()
        except Exception:
            if attempt == max_retries - 1:
                raise
            await asyncio.sleep(backoff_factor * (2 ** attempt))


# AbuseIPDB query (unchanged)
async def query_abuseipdb(ip, api_key, session, max_retries=3, backoff_factor=1):
    headers = {"Key": api_key, "Accept": "application/json"}
    params  = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        resp = await fetch_with_retries(
            session, ABUSEIPDB_URL,
            headers=headers, params=params,
            max_retries=max_retries,
            backoff_factor=backoff_factor
        )
        data = resp.get("data", {}) or {}
        return {
            "score": data.get("abuseConfidenceScore", "-"),
            "country": data.get("countryCode", "-"),
            "isp": data.get("isp", "-"),
            "reports": data.get("totalReports", "-"),
            "last_seen": data.get("lastReportedAt", "-"),
            "timestamp": time.time(),
        }
    except Exception as e:
        return {"error": str(e), "timestamp": time.time()}


# VT query helpers
async def query_vt_ip(ip, api_key, session, max_retries=3, backoff_factor=1):
    headers = {"x-apikey": api_key}
    try:
        resp = await fetch_with_retries(
            session, VT_IP_URL.format(ip),
            headers=headers,
            max_retries=max_retries,
            backoff_factor=backoff_factor
        )
        a = (resp.get("data") or {}).get("attributes") or {}
        return {
            "last_analysis_stats": a.get("last_analysis_stats", {}),
            "reverse_dns": a.get("reverse_dns", "-"),
            "whois_org": a.get("whois", "-"),
            "timestamp": time.time(),
        }
    except Exception as e:
        return {
            "error": str(e),
            "last_analysis_stats": {},
            "reverse_dns": "-",
            "whois_org": "-",
            "timestamp": time.time(),
        }

# Gets community comments from VT
"""
async def query_vt_comments(resource_type, resource_id, api_key, session, max_retries=3, backoff_factor=1):
    url = f"https://www.virustotal.com/api/v3/{resource_type}/{resource_id}/comments"
    headers = {"x-apikey": api_key}
    try:
        resp = await fetch_with_retries(
            session, url,
            headers=headers,
            max_retries=max_retries,
            backoff_factor=backoff_factor
        )
        return resp.get("data", [])
    except Exception:
        return []"""

async def query_vt_file(file_hash, api_key, session, max_retries=3, backoff_factor=1):
    headers = {"x-apikey": api_key}
    try:
        resp = await fetch_with_retries(
            session, VT_FILE_URL.format(file_hash),
            headers=headers,
            max_retries=max_retries,
            backoff_factor=backoff_factor
        )
        a = (resp.get("data") or {}).get("attributes") or {}
        return {
            "last_analysis_date": a.get("last_analysis_date", 0),
            "first_submission_date": a.get("first_submission_date", 0),
            "last_analysis_stats": a.get("last_analysis_stats", {}),
            "names": a.get("names", []),
            "tags": a.get("tags", []),
            "timestamp": time.time(),
        }
    except Exception as e:
        return {
            "error": str(e),
            "last_analysis_date": 0,
            "first_submission_date": 0,
            "last_analysis_stats": {},
            "names": [],
            "tags": [],
            "timestamp": time.time(),
        }


async def query_vt_url(url, api_key, session, max_retries=3, backoff_factor=1):
    headers = {"x-apikey": api_key}
    encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        resp = await fetch_with_retries(
            session, VT_URL_LOOKUP.format(encoded),
            headers=headers,
            max_retries=max_retries,
            backoff_factor=backoff_factor
        )
        a = (resp.get("data") or {}).get("attributes") or {}
        return {
            "last_analysis_stats": a.get("last_analysis_stats", {}),
            "redirect_chain": a.get("redirect_chain", []),
            "final_url": a.get("last_final_url", "-"),
            "tags": a.get("tags", []),
            "reputation": a.get("reputation", 0),
            "timestamp": time.time(),
        }
    except Exception as e:
        return {
            "error": str(e),
            "last_analysis_stats": {},
            "redirect_chain": [],
            "final_url": "-",
            "tags": [],
            "reputation": 0,
            "timestamp": time.time(),
        }

async def query_vt_domain(domain, api_key, session, max_retries=3, backoff_factor=1):
    headers = {"x-apikey": api_key}
    try:
        resp = await fetch_with_retries(
            session, VT_DOMAIN_URL.format(domain),
            headers=headers,
            max_retries=max_retries,
            backoff_factor=backoff_factor
        )
        a = (resp.get("data") or {}).get("attributes") or {}
        return {
            "last_analysis_stats": a.get("last_analysis_stats", {}),
            "categories": a.get("categories", {}),
            "registrar": a.get("registrar", "-"),
            "creation_date": a.get("creation_date", 0),
            "expiration_date": a.get("expiration_date", 0),
            "registrant_country": a.get("registrant_country", "-"),
            "subdomains": a.get("subdomains", []),
            "resolutions": a.get("last_dns_records", []),
            "timestamp": time.time(),
        }
    except Exception as e:
        return {
            "error": str(e),
            "last_analysis_stats": {},
            "categories": {},
            "registrar": "-",
            "creation_date": 0,
            "expiration_date": 0,
            "registrant_country": "-",
            "subdomains": [],
            "resolutions": [],
            "timestamp": time.time(),
        }

async def query_urlscan_submit(url, api_key, session, max_retries=3):
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    payload = {"url": url}
    resp = await fetch_with_retries(session, URLSCAN_SUBMIT_URL, headers=headers, json_data=payload, method="POST", max_retries=max_retries)
    return resp.get("uuid")

async def query_urlscan_result(scan_uuid, api_key, session, max_retries=3, poll_interval=5, max_polls=10):
    headers = {"API-Key": api_key}
    for _ in range(max_polls):
        try:
            resp = await fetch_with_retries(session, URLSCAN_RESULT_URL.format(scan_uuid), headers=headers, max_retries=max_retries)
            if resp.get("status") == "done" or resp.get("task", {}).get("state") == "done":
                return resp
            await asyncio.sleep(poll_interval)
        except Exception:
            await asyncio.sleep(poll_interval)
    return {}

def format_ts(ts):
    return time.strftime("%Y-%m-%d", time.localtime(ts)) if ts else "n/a"


def append_multiline(lines, label, text, indent=4):
    chunk = text.splitlines() or [""]
    lines.append(f"{' '*indent}{label}: {chunk[0]}\n")
    prefix = ' ' * (indent + len(label) + 2)
    for l in chunk[1:]:
        lines.append(f"{prefix}{l}\n")
    lines.append("\n")


def append_json(lines, label, obj, indent=4):
    dump = json.dumps(obj, indent=2)
    append_multiline(lines, label, dump, indent)


async def enrich_text(content, enabled_services, max_retries=3):
    iocs = extract_iocs(content); save_buffer(iocs)
    ips = sorted({v for t, v in iocs if t == "ip"})
    hashes = sorted({v for t, v in iocs if t == "hash"})
    urls = sorted({v for t, v in iocs if t == "url"})
    domains = sorted({v for t, v in iocs if t == "domain"})

    lines = []
    lines.append(f"{BOLD}{BLUE}=== 📝 THREAT INTELLIGENCE ==={RESET}\n")
    lines.append(f"• {len(ips)} IP(s)   • {len(hashes)} Hash(es)   • {len(urls)} URL(s)   • {len(domains)} Domain(s)\n\n")

    cache = load_cache(); updated = False
    async with aiohttp.ClientSession() as session:
        for ip in ips:
            lines.append(f"{BOLD}{YELLOW}🌐 IP: {ip}{RESET}\n\n")

            if "abuseipdb" in enabled_services:
                abuseipdb_key = enabled_services["abuseipdb"]
                if ip in cache and not is_stale(cache[ip]):
                    abuse = cache[ip]
                else:
                    await asyncio.sleep(1)
                    abuse = await query_abuseipdb(ip, abuseipdb_key, session, max_retries)
                    cache[ip] = abuse; updated = True

                lines.append(f"  {MAGENTA}🐝 AbuseIPDB:{RESET}\n")
                lines.append(f"    {BOLD}{GREEN}Link{RESET}     : https://www.abuseipdb.com/check/{ip}\n")
                lines.append(f"    {GREEN}Score{RESET}    : {abuse.get('score','-')}\n")
                lines.append(f"    {GREEN}Country{RESET}  : {abuse.get('country','-')}\n")
                lines.append(f"    {GREEN}ISP{RESET}      : {abuse.get('isp','-')}\n")
                lines.append(f"    {GREEN}Reports{RESET}  : {abuse.get('reports','-')}\n")
                lines.append(f"    {GREEN}Last Seen{RESET}: {abuse.get('last_seen','-')}\n\n")

            if "virustotal" in enabled_services:
                vt_key = enabled_services["virustotal"]
                await asyncio.sleep(1)
                vt = await query_vt_ip(ip, vt_key, session, max_retries)
                stats = vt.get("last_analysis_stats", {})

                lines.append(f"  {CYAN}🔍 VirusTotal:{RESET}\n")
                lines.append(f"    {BOLD}{GREEN}Link{RESET}     : https://www.virustotal.com/gui/ip-address/{ip}\n")
                lines.append(f"    {GREEN}Verdict{RESET}   : {stats.get('malicious',0)}/{stats.get('harmless',0)}\n")
                lines.append(f"    {GREEN}Reverse DNS{RESET}: {vt.get('reverse_dns','-')}\n")
                append_multiline(lines, f"{CYAN}WHOIS Org{RESET}", vt.get("whois_org",""), indent=4)

        if "virustotal" in enabled_services:
            vt_key = enabled_services["virustotal"]
            for h in hashes:
                await asyncio.sleep(1)
                r = await query_vt_file(h, vt_key, session, max_retries)
                stats = r.get("last_analysis_stats", {}) 

                lines.append(f"{BOLD}{YELLOW}🔑 Hash: {h}{RESET}\n\n")
                lines.append(f"  {CYAN}🔍 VirusTotal:{RESET}\n")
                lines.append(f"    {BOLD}{GREEN}Link{RESET}     : https://www.virustotal.com/gui/file/{h}\n") 
                lines.append(f"    {GREEN}Last Seen{RESET}: {format_ts(r.get('last_analysis_date'))}\n")
                lines.append(f"    {GREEN}Verdict{RESET}  : {stats.get('malicious',0)}/{stats.get('harmless',0)}\n")
                lines.append(f"    {GREEN}Filename{RESET}: {r.get('names',['-'])[0]}\n")
                lines.append(f"    {GREEN}First Seen{RESET}: {format_ts(r.get('first_submission_date'))}\n")
                append_json(lines, f"{CYAN}Tags{RESET}", r.get("tags", []), indent=4)

            for u in urls:
                await asyncio.sleep(1)
                r = await query_vt_url(u, vt_key, session, max_retries)
                stats = r.get("last_analysis_stats", {})

                lines.append(f"{BOLD}{YELLOW}🔗 URL: {u}{RESET}\n\n") 
                lines.append(f"  {CYAN}🔍 VirusTotal:{RESET}\n")
                encoded = base64.urlsafe_b64encode(u.encode()).decode().strip("=")
                vt_gui_url = f"https://www.virustotal.com/gui/url/{encoded}"
                lines.append(f"    {BOLD}{GREEN}Link{RESET}     : {vt_gui_url}\n")
                lines.append(f"    {GREEN}Verdict{RESET}  : {stats.get('malicious',0)}/{stats.get('harmless',0)}\n")
                append_json(lines, f"{CYAN}Redirect Chain{RESET}", r.get("redirect_chain", []), indent=4)
                append_multiline(lines, f"{CYAN}Final URL{RESET}", r.get("final_url",""), indent=4)
                append_json(lines, f"{CYAN}URL Tags{RESET}", r.get("tags", []), indent=4)
                lines.append(f"    {GREEN}Reputation{RESET}: {r.get('reputation',0)}\n\n")

            for d in domains:
                await asyncio.sleep(1)
                r = await query_vt_domain(d, vt_key, session, max_retries)
                stats = r.get("last_analysis_stats", {})

                lines.append(f"{BOLD}{YELLOW}🏷️ Domain: {d}{RESET}\n\n")
                lines.append(f"  {CYAN}🔍 VirusTotal:{RESET}\n")
                lines.append(f"    {BOLD}{GREEN}Link{RESET}     : https://www.virustotal.com/gui/domain/{d}\n")
                lines.append(f"    {GREEN}Verdict{RESET} : {stats.get('malicious',0)}/{stats.get('harmless',0)}\n")
                append_json(lines, f"{CYAN}Categories{RESET}", r.get("categories", {}), indent=4)
                append_multiline(lines, f"{CYAN}Registrar{RESET}", r.get("registrar",""), indent=4)
                append_multiline(lines, f"{CYAN}Created{RESET}", format_ts(r.get("creation_date")), indent=4)
                append_multiline(lines, f"{CYAN}Expires{RESET}", format_ts(r.get("expiration_date")), indent=4)
                append_multiline(lines, f"{CYAN}Country{RESET}", r.get("registrant_country",""), indent=4)
                append_json(lines, f"{CYAN}Subdomains{RESET}", r.get("subdomains", []), indent=4)
                append_json(lines, f"{CYAN}DNS Records{RESET}", r.get("resolutions", []), indent=4)

    if updated:
        save_cache(cache)

    return "".join(lines)

async def main_async():
    parser = argparse.ArgumentParser(description="IOC Enrichment Tool")
    parser.add_argument("file", nargs="?", help="File to read (stdin default)")
    parser.add_argument("--max-retries", type=int, default=3)
    args = parser.parse_args()

    if not ENABLED_SERVICES:
        print("[!] No usable API keys found — exiting.")
        sys.exit(1)

    if args.file:
        content = open(args.file).read()
    else:
        content = sys.stdin.read()

    print(await enrich_text(content, ENABLED_SERVICES, args.max_retries))



def main():
    asyncio.run(main_async())


if __name__ == "__main__":
    main()

