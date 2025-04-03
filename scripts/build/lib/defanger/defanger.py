# defanger.py
import sys
import re
from urllib.parse import urlparse
import tldextract
import ipaddress
from .ioc_utils import extract_iocs, save_buffer

def defang_token(token):
    token = token.strip()  # Remove any surrounding whitespace
    try:
        ip_obj = ipaddress.ip_address(token)
        # Skip defanging if it's a private IP
        if ip_obj.is_private:
            return token
        # For IPv4 addresses, replace dots with [.]
        if ip_obj.version == 4:
            return token.replace('.', '[.]')
        # For IPv6 addresses, replace colons with [:]
        elif ip_obj.version == 6:
            return token.replace(':', '[:]')
    except ValueError:
        pass

    # Handle email addresses
    if "@" in token and "." in token:
        return token.replace("@", "[at]")

    # Handle URLs
    try:
        parsed = urlparse(token)
    except ValueError:
        return token

    if parsed.scheme and parsed.netloc:
        defanged_scheme = parsed.scheme.replace('http', 'hxxp')
        defanged_netloc = parsed.netloc.replace('.', '[.]')
        new_url = defanged_scheme + "://" + defanged_netloc + parsed.path
        if parsed.params:
            new_url += ";" + parsed.params
        if parsed.query:
            new_url += "?" + parsed.query
        if parsed.fragment:
            new_url += "#" + parsed.fragment
        return new_url

    # Handle domains (if not captured by URL parsing)
    if '.' in token:
        ext = tldextract.extract(token)
        if ext.domain and ext.suffix:
            return token.replace('.', '[.]')

    return token


def refang_token(token):
    token = token.replace("[at]", "@")
    token = token.replace("[.]", ".").replace("[:]", ":")
    token = re.sub(r"\bhxxp(s?)\b", r"http\1", token)
    return token


def defang_text(text):
    iocs = extract_iocs(text)
    save_buffer(iocs)  # Save for enrichment if needed
    return re.sub(r"\S+", lambda m: defang_token(m.group(0)), text)


def refang_text(text):
    return re.sub(r"\S+", lambda m: refang_token(m.group(0)), text)


def main():
    mode = "defang"
    if len(sys.argv) > 1 and sys.argv[1] == "--refang":
        mode = "refang"

    input_text = sys.stdin.read()

    if mode == "defang":
        output = defang_text(input_text)
    else:
        output = refang_text(input_text)

    sys.stdout.write(output)


if __name__ == "__main__":
    main()






