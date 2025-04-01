import re
import ipaddress
import tldextract
from urllib.parse import urlparse

def detect_ioc(token):
    """Detect and classify the type of IOC."""
    try:
        ip = ipaddress.ip_address(token)
        return ("ip", str(ip))
    except ValueError:
        pass

    if "@" in token and "." in token:
        return ("email", token)

    parsed = urlparse(token)
    if parsed.scheme and parsed.netloc:
        return ("url", token)

    ext = tldextract.extract(token)
    if ext.domain and ext.suffix:
        return ("domain", token)

    # Match MD5, SHA1, or SHA256 hashes
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", token):
        return ("hash", token)

    return (None, token)

def extract_iocs(text):
    """Scan a full text and return a list of detected IOCs."""
    iocs = []
    for token in re.findall(r"\S+", text):
        ioc_type, value = detect_ioc(token)
        if ioc_type:
            iocs.append((ioc_type, value))
    return iocs
