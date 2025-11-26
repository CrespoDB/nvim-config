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


def aggregate_anonymizer_data(provider_results):
    """Aggregate VPN/Proxy/Tor detection data from all providers"""
    anonymizer_data = {
        'detected': False,
        'proxy': False,
        'vpn': False,
        'tor': False,
        'active_vpn': False,
        'active_tor': False,
        'sources': []
    }
    
    for provider_name, data in provider_results.items():
        if 'error' in data:
            continue
            
        # IPQualityScore data
        if provider_name == 'IPQualityScore':
            if data.get('proxy', False):
                anonymizer_data['proxy'] = True
                anonymizer_data['detected'] = True
                anonymizer_data['sources'].append(f"Proxy ({provider_name})")
            if data.get('vpn', False):
                anonymizer_data['vpn'] = True
                anonymizer_data['detected'] = True
                anonymizer_data['sources'].append(f"VPN ({provider_name})")
            if data.get('tor', False):
                anonymizer_data['tor'] = True
                anonymizer_data['detected'] = True
                anonymizer_data['sources'].append(f"Tor ({provider_name})")
            if data.get('active_vpn', False):
                anonymizer_data['active_vpn'] = True
                anonymizer_data['detected'] = True
                anonymizer_data['sources'].append(f"Active VPN ({provider_name})")
            if data.get('active_tor', False):
                anonymizer_data['active_tor'] = True
                anonymizer_data['detected'] = True
                anonymizer_data['sources'].append(f"Active Tor ({provider_name})")
        
        # IP2Location data
        elif provider_name == 'IP2Location':
            if data.get('is_proxy', False):
                anonymizer_data['proxy'] = True
                anonymizer_data['detected'] = True
                anonymizer_data['sources'].append(f"Proxy ({provider_name})")
            if data.get('is_vpn', False):
                anonymizer_data['vpn'] = True
                anonymizer_data['detected'] = True
                anonymizer_data['sources'].append(f"VPN ({provider_name})")
            if data.get('is_tor', False):
                anonymizer_data['tor'] = True
                anonymizer_data['detected'] = True
                anonymizer_data['sources'].append(f"Tor ({provider_name})")
    
    return anonymizer_data


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
                
                # Collect provider results for aggregation (IP anonymizer detection)
                provider_results = {}
                
                # Query all providers first to collect data
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
                    
                    # Store provider results for aggregation
                    provider_results[provider.name] = extracted_data
                
                # Show anonymizer detection FIRST for IPs (if detected)
                if ioc_type == "ip":
                    anonymizer_data = aggregate_anonymizer_data(provider_results)
                    if anonymizer_data['detected']:
                        lines.append(f"  {RED}🚩 ANONYMIZER DETECTED{RESET}\n")
                        detection_types = []
                        if anonymizer_data['active_vpn']:
                            detection_types.append(f"{RED}Active VPN{RESET}")
                        elif anonymizer_data['vpn']:
                            detection_types.append(f"{RED}VPN{RESET}")
                        if anonymizer_data['active_tor']:
                            detection_types.append(f"{RED}Active Tor{RESET}")
                        elif anonymizer_data['tor']:
                            detection_types.append(f"{RED}Tor{RESET}")
                        if anonymizer_data['proxy'] and not anonymizer_data['vpn'] and not anonymizer_data['tor']:
                            detection_types.append(f"{RED}Proxy{RESET}")
                        
                        if detection_types:
                            lines.append(f"    {GREEN}Type{RESET}     : {', '.join(detection_types)}\n")
                        
                        # Add Spur.us link
                        lines.append(f"    {GREEN}Analysis{RESET} : https://spur.us/context/{ioc_value}\n")
                        lines.append("\n")
                
                # Display provider results
                for provider in providers:
                    extracted_data = provider_results[provider.name]
                    display_lines = provider.format_display(ioc_value, ioc_type, extracted_data)
                    lines.extend(display_lines)
                
                # Show "NO ANONYMIZER DETECTED" only if no anonymizer was found for IPs
                if ioc_type == "ip" and not aggregate_anonymizer_data(provider_results)['detected']:
                    lines.append(f"  {GREEN}✅ NO ANONYMIZER DETECTED{RESET}\n\n")
                
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

