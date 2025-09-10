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
from .settings import *
from .cache import *
from .provider_registry import get_registry

async def fetch_with_retries(session, url, headers=None, params=None,
                             json_data=None, method="GET",
                             max_retries=3, backoff_factor=1, timeout=10):
    """Shared fetch function with retries - used by all providers"""
    for attempt in range(max_retries):
        try:
            if method.upper() == "POST":
                async with session.post(url, headers=headers, json=json_data, timeout=timeout) as resp:
                    resp.raise_for_status()
                    return await resp.json()
            else:
                async with session.get(url, headers=headers, params=params, timeout=timeout) as resp:
                    resp.raise_for_status()
                    return await resp.json()
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            await asyncio.sleep(backoff_factor * (2 ** attempt))


async def enrich_text(content, enabled_services, max_retries=3):
    iocs = extract_iocs(content); save_buffer(iocs)
    ips = sorted({v for t, v in iocs if t == "ip"})
    hashes = sorted({v for t, v in iocs if t == "hash"})
    urls = sorted({v for t, v in iocs if t == "url"})
    domains = sorted({v for t, v in iocs if t == "domain"})

    lines = []
    lines.append(f"{BOLD}{BLUE}=== 📝 THREAT INTELLIGENCE ==={RESET}\n")
    lines.append(f"• {len(ips)} IP(s)   • {len(hashes)} Hash(es)   • {len(urls)} URL(s)   • {len(domains)} Domain(s)\n\n")

    # Get provider registry
    registry = get_registry()
    cache = load_cache(); updated = False
    
    ioc_groups = [
        ("ip", ips, "🌐 IP"),
        ("hash", hashes, "🔑 Hash"),
        ("url", urls, "🔗 URL"),
        ("domain", domains, "🏷️ Domain")
    ]
    
    async with aiohttp.ClientSession() as session:
        for ioc_type, ioc_list, icon in ioc_groups:
            providers = registry.get_providers_for_ioc_type(ioc_type)
            missing_providers = registry.get_missing_providers_for_ioc_type(ioc_type)
            
            for ioc_value in ioc_list:
                lines.append(f"{BOLD}{YELLOW}{icon}: {ioc_value}{RESET}\n\n")
                
                # Display active providers
                for provider in providers:
                    # Check cache for some providers (like AbuseIPDB)
                    cache_key = f"{provider.name}_{ioc_value}"
                    if provider.name == "AbuseIPDB" and cache_key in cache and not is_stale(cache[cache_key]):
                        extracted_data = cache[cache_key]
                    else:
                        await asyncio.sleep(1)  # Rate limiting
                        
                        # Query the provider
                        raw_response = await provider.query(ioc_value, ioc_type, session, max_retries=max_retries)
                        
                        # Extract fields using provider's logic
                        extracted_data = provider.extract_fields(raw_response, ioc_type)
                        
                        # Cache the result for some providers
                        if provider.name == "AbuseIPDB":
                            cache[cache_key] = extracted_data
                            updated = True
                    
                    # Format and display the result
                    display_lines = provider.format_display(ioc_value, ioc_type, extracted_data)
                    lines.extend(display_lines)
                
                # Display information about missing providers
                if missing_providers:
                    lines.append(f"  {CYAN}ℹ️  Available with API keys:{RESET}\n")
                    for provider_name, env_var in missing_providers:
                        lines.append(f"    {YELLOW}• {provider_name}{RESET}: Set {BOLD}{env_var}{RESET} environment variable\n")
                    lines.append("\n")

    if updated:
        save_cache(cache)

    return "".join(lines)


async def main_async():
    parser = argparse.ArgumentParser(description="IOC Enrichment Tool")
    parser.add_argument("file", nargs="?", help="File to read (stdin default)")
    parser.add_argument("--max-retries", type=int, default=3)
    args = parser.parse_args()

    # Check if we have any providers available (including those that don't need API keys)
    registry = get_registry()
    all_providers = registry.get_all_providers()
    if not all_providers:
        print("[!] No threat intelligence providers available — exiting.")
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

