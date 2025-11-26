"""VirusTotal threat intelligence provider"""
import time
import base64
import json
from typing import Dict, List, Any
from .base import TIProvider
from ..settings import (VT_IP_URL, VT_FILE_URL, VT_URL_LOOKUP, VT_DOMAIN_URL, 
                       GREEN, CYAN, RESET, BOLD)


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


class VirusTotalProvider(TIProvider):
    """VirusTotal provider for IPs, files, URLs, and domains"""
    
    def __init__(self, api_key: str):
        super().__init__(api_key, "VirusTotal")
    
    def get_supported_ioc_types(self) -> List[str]:
        return ["ip", "hash", "url", "domain"]
    
    async def query(self, ioc_value: str, ioc_type: str, session, max_retries=3, backoff_factor=1, **kwargs) -> Dict[str, Any]:
        """Query VirusTotal for IOC information"""
        from ..enricher import fetch_with_retries
        
        headers = {"x-apikey": self.api_key}
        
        try:
            if ioc_type == "ip":
                url = VT_IP_URL.format(ioc_value)
            elif ioc_type == "hash":
                url = VT_FILE_URL.format(ioc_value)
            elif ioc_type == "url":
                encoded = base64.urlsafe_b64encode(ioc_value.encode()).decode().strip("=")
                url = VT_URL_LOOKUP.format(encoded)
            elif ioc_type == "domain":
                url = VT_DOMAIN_URL.format(ioc_value)
            else:
                return {"error": f"Unsupported IOC type: {ioc_type}"}
            
            resp = await fetch_with_retries(
                session, url,
                headers=headers,
                max_retries=max_retries,
                backoff_factor=backoff_factor
            )
            return resp
        except Exception as e:
            return {"error": str(e), "timestamp": time.time()}
    
    def extract_fields(self, raw_response: Dict[str, Any], ioc_type: str) -> Dict[str, Any]:
        """Extract relevant fields from VirusTotal response"""
        if "error" in raw_response:
            return raw_response
        
        attributes = (raw_response.get("data") or {}).get("attributes") or {}
        
        if ioc_type == "ip":
            return {
                "last_analysis_stats": attributes.get("last_analysis_stats", {}),
                "reverse_dns": attributes.get("reverse_dns", "-"),
                "whois_org": attributes.get("whois", "-"),
                "timestamp": time.time(),
            }
        elif ioc_type == "hash":
            return {
                "last_analysis_date": attributes.get("last_analysis_date", 0),
                "first_submission_date": attributes.get("first_submission_date", 0),
                "last_analysis_stats": attributes.get("last_analysis_stats", {}),
                "names": attributes.get("names", []),
                "tags": attributes.get("tags", []),
                "timestamp": time.time(),
            }
        elif ioc_type == "url":
            return {
                "last_analysis_stats": attributes.get("last_analysis_stats", {}),
                "redirect_chain": attributes.get("redirect_chain", []),
                "final_url": attributes.get("last_final_url", "-"),
                "tags": attributes.get("tags", []),
                "reputation": attributes.get("reputation", 0),
                "timestamp": time.time(),
            }
        elif ioc_type == "domain":
            return {
                "last_analysis_stats": attributes.get("last_analysis_stats", {}),
                "categories": attributes.get("categories", {}),
                "registrar": attributes.get("registrar", "-"),
                "creation_date": attributes.get("creation_date", 0),
                "expiration_date": attributes.get("expiration_date", 0),
                "registrant_country": attributes.get("registrant_country", "-"),
                "subdomains": attributes.get("subdomains", []),
                "resolutions": attributes.get("last_dns_records", []),
                "timestamp": time.time(),
            }
        
        return attributes
    
    def format_display(self, ioc_value: str, ioc_type: str, extracted_data: Dict[str, Any]) -> List[str]:
        """Format VirusTotal data for display"""
        lines = []
        lines.append(f"  {CYAN}🔍 VirusTotal:{RESET}\n")
        
        if "error" in extracted_data:
            from ..settings import RED
            lines.append(f"    {RED}ℹ️  Error{RESET}: {extracted_data['error']}\n\n")
            return lines
        
        if ioc_type == "ip":
            lines.append(f"    {BOLD}{GREEN}Link{RESET}     : https://www.virustotal.com/gui/ip-address/{ioc_value}\n")
            stats = extracted_data.get("last_analysis_stats", {})
            lines.append(f"    {GREEN}Verdict{RESET}   : {stats.get('malicious',0)}/{stats.get('harmless',0)}\n")
            lines.append(f"    {GREEN}Reverse DNS{RESET}: {extracted_data.get('reverse_dns','-')}\n")
            append_multiline(lines, f"{CYAN}WHOIS Org{RESET}", extracted_data.get("whois_org",""), indent=4)
        
        elif ioc_type == "hash":
            lines.append(f"    {BOLD}{GREEN}Link{RESET}     : https://www.virustotal.com/gui/file/{ioc_value}\n")
            lines.append(f"    {GREEN}Last Seen{RESET}: {format_ts(extracted_data.get('last_analysis_date'))}\n")
            stats = extracted_data.get("last_analysis_stats", {})
            lines.append(f"    {GREEN}Verdict{RESET}  : {stats.get('malicious',0)}/{stats.get('harmless',0)}\n")
            names = extracted_data.get('names', [])
            filename = names[0] if names else '-'
            lines.append(f"    {GREEN}Filename{RESET}: {filename}\n")
            lines.append(f"    {GREEN}First Seen{RESET}: {format_ts(extracted_data.get('first_submission_date'))}\n")
            append_json(lines, f"{CYAN}Tags{RESET}", extracted_data.get("tags", []), indent=4)
        
        elif ioc_type == "url":
            encoded = base64.urlsafe_b64encode(ioc_value.encode()).decode().strip("=")
            vt_gui_url = f"https://www.virustotal.com/gui/url/{encoded}"
            lines.append(f"    {BOLD}{GREEN}Link{RESET}     : {vt_gui_url}\n")
            stats = extracted_data.get("last_analysis_stats", {})
            lines.append(f"    {GREEN}Verdict{RESET}  : {stats.get('malicious',0)}/{stats.get('harmless',0)}\n")
            append_json(lines, f"{CYAN}Redirect Chain{RESET}", extracted_data.get("redirect_chain", []), indent=4)
            append_multiline(lines, f"{CYAN}Final URL{RESET}", extracted_data.get("final_url",""), indent=4)
            append_json(lines, f"{CYAN}URL Tags{RESET}", extracted_data.get("tags", []), indent=4)
            lines.append(f"    {GREEN}Reputation{RESET}: {extracted_data.get('reputation',0)}\n\n")
        
        elif ioc_type == "domain":
            lines.append(f"    {BOLD}{GREEN}Link{RESET}     : https://www.virustotal.com/gui/domain/{ioc_value}\n")
            stats = extracted_data.get("last_analysis_stats", {})
            lines.append(f"    {GREEN}Verdict{RESET} : {stats.get('malicious',0)}/{stats.get('harmless',0)}\n")
            append_json(lines, f"{CYAN}Categories{RESET}", extracted_data.get("categories", {}), indent=4)
            append_multiline(lines, f"{CYAN}Registrar{RESET}", extracted_data.get("registrar",""), indent=4)
            append_multiline(lines, f"{CYAN}Created{RESET}", format_ts(extracted_data.get("creation_date")), indent=4)
            append_multiline(lines, f"{CYAN}Expires{RESET}", format_ts(extracted_data.get("expiration_date")), indent=4)
            append_multiline(lines, f"{CYAN}Country{RESET}", extracted_data.get("registrant_country",""), indent=4)
            append_json(lines, f"{CYAN}Subdomains{RESET}", extracted_data.get("subdomains", []), indent=4)
            append_json(lines, f"{CYAN}DNS Records{RESET}", extracted_data.get("resolutions", []), indent=4)
        
        return lines
    
    def get_display_name(self) -> str:
        return f"{CYAN}🔍 VirusTotal{RESET}"