#!/usr/bin/env python3
import sys
import re
import ipaddress
import tldextract
from urllib.parse import urlparse

def defang_token(token):
    # --- Handle email addresses ---
    # A simple check: if the token contains "@" and a period, assume it's an email.
    if "@" in token and "." in token:
        token = token.replace("@", "[at]")

    # --- Handle IP addresses ---
    try:
        ipaddress.ip_address(token)
        return token.replace('.', '[.]').replace(':', '[:]')
    except ValueError:
        pass

    # --- Handle URLs ---
    parsed = urlparse(token)
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

    # --- Handle domains ---
    if '.' in token:
        ext = tldextract.extract(token)
        if ext.domain and ext.suffix:
            return token.replace('.', '[.]')

    return token

def refang_token(token):
    # Reverse email defanging
    token = token.replace("[at]", "@")
    # Reverse IP/domain defanging
    token = token.replace("[.]", ".").replace("[:]", ":")
    # Reverse URL scheme defanging: change hxxp back to http
    token = re.sub(r'\bhxxp(s?)\b', r'http\1', token)
    return token

def defang_text(text):
    return re.sub(r'\S+', lambda m: defang_token(m.group(0)), text)

def refang_text(text):
    return re.sub(r'\S+', lambda m: refang_token(m.group(0)), text)

def main():
    # Check for '--refang' argument (default is defang)
    mode = "defang"
    if len(sys.argv) > 1 and sys.argv[1] == "--refang":
        mode = "refang"
    input_text = sys.stdin.read()
    if mode == "defang":
        output_text = defang_text(input_text)
    else:
        output_text = refang_text(input_text)
    sys.stdout.write(output_text)

if __name__ == '__main__':
    main()


