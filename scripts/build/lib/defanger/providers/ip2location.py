"""IP2Location.io threat intelligence provider"""
import time
from typing import Dict, List, Any
from .base import TIProvider
from ..settings import GREEN, CYAN, RESET, BOLD


class IP2LocationProvider(TIProvider):
    """IP2Location.io provider for IP geolocation and VPN detection"""
    
    def __init__(self, api_key: str):
        super().__init__(api_key, "IP2Location")
    
    def get_supported_ioc_types(self) -> List[str]:
        return ["ip"]
    
    async def query(self, ioc_value: str, ioc_type: str, session, max_retries=3, backoff_factor=1, **kwargs) -> Dict[str, Any]:
        """Query IP2Location.io for IP information"""
        from ..enricher import fetch_with_retries
        
        params = {
            "key": self.api_key,
            "ip": ioc_value,
            "format": "json"
        }
        
        try:
            resp = await fetch_with_retries(
                session, "https://api.ip2location.io/",
                params=params,
                max_retries=max_retries,
                backoff_factor=backoff_factor
            )
            return resp
        except Exception as e:
            return {"error": str(e), "timestamp": time.time()}
    
    def extract_fields(self, raw_response: Dict[str, Any], ioc_type: str) -> Dict[str, Any]:
        """Extract relevant fields from IP2Location.io response"""
        if "error" in raw_response:
            return raw_response
        
        # Handle API error responses
        if "error_code" in raw_response or "error_message" in raw_response:
            error_info = raw_response.get("error", {})
            error_msg = error_info.get("error_message", "Unknown error")
            return {"error": error_msg, "timestamp": time.time()}
        
        proxy_info = raw_response.get("proxy", {})
        return {
            "country": raw_response.get("country_name", "-"),
            "country_code": raw_response.get("country_code", "-"),
            "region": raw_response.get("region_name", "-"),
            "city": raw_response.get("city_name", "-"),
            "isp": raw_response.get("isp", "-"),
            "asn": raw_response.get("asn", "-"),
            "usage_type": raw_response.get("usage_type", "-"),
            "is_proxy": raw_response.get("is_proxy", False),
            "is_vpn": proxy_info.get("is_vpn", False),
            "is_tor": proxy_info.get("is_tor", False),
            "is_datacenter": proxy_info.get("is_data_center", False),
            "proxy_type": proxy_info.get("proxy_type", "-"),
            "provider": proxy_info.get("provider", "-"),
            "threat": proxy_info.get("threat", "-"),
            "fraud_score": raw_response.get("fraud_score", "-"),
            "timestamp": time.time(),
        }
    
    def format_display(self, ioc_value: str, ioc_type: str, extracted_data: Dict[str, Any]) -> List[str]:
        """Format IP2Location.io data for display"""
        lines = []
        lines.append(f"  {CYAN}🌍 IP2Location:{RESET}\n")
        
        if "error" in extracted_data:
            from ..settings import RED
            lines.append(f"    {RED}ℹ️  Error{RESET}: {extracted_data['error']}\n\n")
        else:
            # Location information
            location = f"{extracted_data.get('city', '-')}, {extracted_data.get('region', '-')}, {extracted_data.get('country', '-')}"
            lines.append(f"    {GREEN}Location{RESET} : {location}\n")
            lines.append(f"    {GREEN}ISP{RESET}      : {extracted_data.get('isp', '-')}\n")
            lines.append(f"    {GREEN}ASN{RESET}      : {extracted_data.get('asn', '-')}\n")
            lines.append(f"    {GREEN}Usage{RESET}    : {extracted_data.get('usage_type', '-')}\n")
            
            # VPN/Proxy detection
            is_proxy = extracted_data.get('is_proxy', False)
            is_vpn = extracted_data.get('is_vpn', False)
            is_tor = extracted_data.get('is_tor', False)
            is_datacenter = extracted_data.get('is_datacenter', False)
            
            if is_proxy or is_vpn or is_tor or is_datacenter:
                from ..settings import RED, YELLOW
                lines.append(f"    {RED}⚠️  Proxy{RESET}   : Yes\n")
                
                if is_vpn:
                    lines.append(f"    {RED}VPN{RESET}      : Yes\n")
                if is_tor:
                    lines.append(f"    {RED}Tor{RESET}      : Yes\n")
                if is_datacenter:
                    lines.append(f"    {YELLOW}DataCenter{RESET}: Yes\n")
                
                proxy_type = extracted_data.get('proxy_type', '-')
                if proxy_type != '-':
                    lines.append(f"    {GREEN}Type{RESET}     : {proxy_type}\n")
                
                provider = extracted_data.get('provider', '-')
                if provider != '-':
                    lines.append(f"    {GREEN}Provider{RESET} : {provider}\n")
                
                threat = extracted_data.get('threat', '-')
                if threat != '-':
                    lines.append(f"    {RED}Threat{RESET}   : {threat}\n")
            else:
                lines.append(f"    {GREEN}Proxy{RESET}    : No\n")
            
            # Fraud score
            fraud_score = extracted_data.get('fraud_score', '-')
            if fraud_score != '-':
                lines.append(f"    {GREEN}Fraud Score{RESET}: {fraud_score}\n")
            
            lines.append("\n")
        return lines
    
    def get_display_name(self) -> str:
        return f"{CYAN}🌍 IP2Location{RESET}"