import os

# API keys - const ENABLED_SERVICES will check what keys are provided.
API_KEYS = {
    "abuseipdb": os.getenv("ABUSEIPDB_KEY"),
    "virustotal": os.getenv("VT_KEY"),
    "urlscan": os.getenv("URLSCAN_KEY"),
    "ip2location": os.getenv("IP2LOCATION_KEY"),
    "ipqualityscore": os.getenv("IPQUALITYSCORE_KEY"),
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
