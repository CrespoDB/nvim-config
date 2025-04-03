import re
import ipaddress
import tldextract
import json
import os
from urllib.parse import urlparse

BUFFER_FILE = os.path.expanduser("~/.cache/ioc_buffer.json")

def detect_ioc(token):
    """Detect and classify the type of IOC."""
    try:
        ip = ipaddress.ip_address(token)
        if ip.is_private:
            return ("private_ip", str(ip))
        return ("ip", str(ip))
    except ValueError:
        pass

    if "@" in token and "." in token:
        return ("email", token)

    try:
        parsed = urlparse(token)
    except ValueError:
        return (None, token)

    if parsed.scheme and parsed.netloc:
        return ("url", token)

    ext = tldextract.extract(token)
    if ext.domain and ext.suffix:
        return ("domain", token)

    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", token):
        return ("hash", token)

    return (None, token)

def extract_iocs(text):
    """Return a flat list of (ioc_type, value) tuples from text."""
    iocs = []
    for token in re.findall(r"\S+", text):
        ioc_type, value = detect_ioc(token)
        if ioc_type:
            iocs.append((ioc_type, value))
    return iocs

def save_buffer(iocs):
    """Store IOCs in a JSON buffer, grouped by type."""
    grouped = {}
    for ioc_type, value in iocs:
        if ioc_type not in grouped:
            grouped[ioc_type] = set()
        grouped[ioc_type].add(value)

    # Convert sets to sorted lists for JSON compatibility
    grouped = {k: sorted(list(v)) for k, v in grouped.items()}

    os.makedirs(os.path.dirname(BUFFER_FILE), exist_ok=True)
    with open(BUFFER_FILE, "w") as f:
        json.dump(grouped, f, indent=2)



