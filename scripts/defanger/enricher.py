# enricher.py
import sys
import os
import argparse
import requests
import time
import json
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from ioc_utils import extract_iocs, save_buffer

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VT_URL = "https://www.virustotal.com/api/v3/files/{}"
CACHE_FILE = os.path.expanduser("~/.cache/ioc_enrichment_cache.json")# enricher.py
import sys
import os
import argparse
import requests
import time
import json
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from ioc_utils import extract_iocs, save_buffer

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VT_URL = "https://www.virustotal.com/api/v3/files/{}"
CACHE_FILE = os.path.expanduser("~/.cache/ioc_enrichment_cache.json")
BUFFER_FILE = os.path.expanduser("~/.cache/ioc_buffer.json")

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
    elapsed = time.time() - entry["timestamp"]
    return elapsed > (max_age_hours * 3600)

def create_retry_session(max_retries=3, backoff_factor=1):
    session = requests.Session()
    retries = Retry(
        total=max_retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

def query_abuseipdb(ip, api_key, session):
    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
    }

    try:
        response = session.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()["data"]
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

def query_virustotal(hash, api_key, session):
    headers = {
        "x-apikey": api_key
    }
    try:
        response = session.get(VT_URL.format(hash), headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()["data"]["attributes"]
        return {
            "md5": data.get("md5", "-"),
            "sha256": data.get("sha256", "-"),
            "type": data.get("type_description", "-"),
            "malicious_votes": data.get("last_analysis_stats", {}).get("malicious", 0),
            "timestamp": time.time(),
        }
    except Exception as e:
        return {"error": str(e), "timestamp": time.time()}

def enrich_ips(ips, api_key, max_retries=3):
    if not ips:
        return "[i] No IP addresses found."

    result_lines = [f"[+] Found {len(ips)} IP(s). Querying AbuseIPDB...\n"]
    session = create_retry_session(max_retries=max_retries)
    cache = load_cache()
    updated = False

    for ip in ips:
        if ip in cache and not is_stale(cache[ip]):
            result = cache[ip]
        else:
            time.sleep(1)
            result = query_abuseipdb(ip, api_key, session)
            cache[ip] = result
            updated = True

        if "error" in result:
            result_lines.append(f"[-] {ip} — Error: {result['error']}")
        else:
            result_lines.append(
                f"{ip}:\n"
                f"  Score       : {result['score']}\n"
                f"  Country     : {result['country']}\n"
                f"  ISP         : {result['isp']}\n"
                f"  Reports     : {result['reports']}\n"
                f"  Last Seen   : {result['last_seen']}\n"
            )

    if updated:
        save_cache(cache)

    return "\n".join(result_lines)

def enrich_hashes(hashes, api_key, max_retries=3):
    if not hashes:
        return "[i] No hashes found."

    result_lines = [f"[+] Found {len(hashes)} hash(es). Querying VirusTotal...\n"]
    session = create_retry_session(max_retries=max_retries)

    for h in hashes:
        time.sleep(1)
        result = query_virustotal(h, api_key, session)

        if "error" in result:
            result_lines.append(f"[-] {h} — Error: {result['error']}")
        else:
            result_lines.append(
                f"{h}:\n"
                f"  Type        : {result['type']}\n"
                f"  Malicious   : {result['malicious_votes']}\n"
            )

    return "\n".join(result_lines)

def enrich_text(content, abuseipdb_key, vt_key, max_retries=3):
    iocs = extract_iocs(content)
    save_buffer(iocs)
    ips = sorted(set(value for ioc_type, value in iocs if ioc_type == "ip"))
    hashes = sorted(set(value for ioc_type, value in iocs if ioc_type == "hash"))

    ip_info = enrich_ips(ips, abuseipdb_key, max_retries)
    hash_info = enrich_hashes(hashes, vt_key, max_retries)
    return ip_info + "\n\n" + hash_info

def main():
    parser = argparse.ArgumentParser(description="IOC Enrichment Tool - AbuseIPDB + VirusTotal")
    parser.add_argument("file", nargs="?", help="File to read (default: stdin)")
    parser.add_argument("--max-retries", type=int, default=3, help="Max retry attempts (default: 3)")
    args = parser.parse_args()

    abuseipdb_key = os.getenv("ABUSEIPDB_KEY")
    vt_key = os.getenv("VT_KEY")

    if not abuseipdb_key:
        print("[!] ABUSEIPDB_KEY env var missing")
        sys.exit(1)
    if not vt_key:
        print("[!] VT_KEY env var missing")
        sys.exit(1)

    if args.file:
        with open(args.file, "r") as f:
            content = f.read()
    else:
        content = sys.stdin.read()

    print(enrich_text(content, abuseipdb_key, vt_key, args.max_retries))

if __name__ == "__main__":
    main()

BUFFER_FILE = os.path.expanduser("~/.cache/ioc_buffer.json")

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
    elapsed = time.time() - entry["timestamp"]
    return elapsed > (max_age_hours * 3600)

def create_retry_session(max_retries=3, backoff_factor=1):
    session = requests.Session()
    retries = Retry(
        total=max_retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

def query_abuseipdb(ip, api_key, session):
    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
    }

    try:
        response = session.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()["data"]
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

def query_virustotal(hash, api_key, session):
    headers = {
        "x-apikey": api_key
    }
    try:
        response = session.get(VT_URL.format(hash), headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()["data"]["attributes"]
        return {
            "md5": data.get("md5", "-"),
            "sha256": data.get("sha256", "-"),
            "type": data.get("type_description", "-"),
            "malicious_votes": data.get("last_analysis_stats", {}).get("malicious", 0),
            "timestamp": time.time(),
        }
    except Exception as e:
        return {"error": str(e), "timestamp": time.time()}

def enrich_ips(ips, api_key, max_retries=3):
    if not ips:
        return "[i] No IP addresses found."

    result_lines = [f"[+] Found {len(ips)} IP(s). Querying AbuseIPDB...\n"]
    session = create_retry_session(max_retries=max_retries)
    cache = load_cache()
    updated = False

    for ip in ips:
        if ip in cache and not is_stale(cache[ip]):
            result = cache[ip]
        else:
            time.sleep(1)
            result = query_abuseipdb(ip, api_key, session)
            cache[ip] = result
            updated = True

        if "error" in result:
            result_lines.append(f"[-] {ip} — Error: {result['error']}")
        else:
            result_lines.append(
                f"{ip}:\n"
                f"  Score       : {result['score']}\n"
                f"  Country     : {result['country']}\n"
                f"  ISP         : {result['isp']}\n"
                f"  Reports     : {result['reports']}\n"
                f"  Last Seen   : {result['last_seen']}\n"
            )

    if updated:
        save_cache(cache)

    return "\n".join(result_lines)

def enrich_hashes(hashes, api_key, max_retries=3):
    if not hashes:
        return "[i] No hashes found."

    result_lines = [f"[+] Found {len(hashes)} hash(es). Querying VirusTotal...\n"]
    session = create_retry_session(max_retries=max_retries)

    for h in hashes:
        time.sleep(1)
        result = query_virustotal(h, api_key, session)

        if "error" in result:
            result_lines.append(f"[-] {h} — Error: {result['error']}")
        else:
            result_lines.append(
                f"{h}:\n"
                f"  Type        : {result['type']}\n"
                f"  Malicious   : {result['malicious_votes']}\n"
            )

    return "\n".join(result_lines)

def enrich_text(content, abuseipdb_key, vt_key, max_retries=3):
    iocs = extract_iocs(content)
    save_buffer(iocs)
    ips = sorted(set(value for ioc_type, value in iocs if ioc_type == "ip"))
    hashes = sorted(set(value for ioc_type, value in iocs if ioc_type == "hash"))

    ip_info = enrich_ips(ips, abuseipdb_key, max_retries)
    hash_info = enrich_hashes(hashes, vt_key, max_retries)
    return ip_info + "\n\n" + hash_info

def main():
    parser = argparse.ArgumentParser(description="IOC Enrichment Tool - AbuseIPDB + VirusTotal")
    parser.add_argument("file", nargs="?", help="File to read (default: stdin)")
    parser.add_argument("--max-retries", type=int, default=3, help="Max retry attempts (default: 3)")
    args = parser.parse_args()

    abuseipdb_key = os.getenv("ABUSEIPDB_KEY")
    vt_key = os.getenv("VT_KEY")

    if not abuseipdb_key:
        print("[!] ABUSEIPDB_KEY env var missing")
        sys.exit(1)
    if not vt_key:
        print("[!] VT_KEY env var missing")
        sys.exit(1)

    if args.file:
        with open(args.file, "r") as f:
            content = f.read()
    else:
        content = sys.stdin.read()

    print(enrich_text(content, abuseipdb_key, vt_key, args.max_retries))

if __name__ == "__main__":
    main()







