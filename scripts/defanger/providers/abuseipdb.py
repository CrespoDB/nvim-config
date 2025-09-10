"""AbuseIPDB threat intelligence provider"""
import time
from typing import Dict, List, Any
from .base import TIProvider
from ..settings import ABUSEIPDB_URL, GREEN, MAGENTA, RESET, BOLD


class AbuseIPDBProvider(TIProvider):
    """AbuseIPDB provider for IP reputation"""
    
    def __init__(self, api_key: str):
        super().__init__(api_key, "AbuseIPDB")
    
    def get_supported_ioc_types(self) -> List[str]:
        return ["ip"]
    
    async def query(self, ioc_value: str, ioc_type: str, session, max_retries=3, backoff_factor=1, **kwargs) -> Dict[str, Any]:
        """Query AbuseIPDB for IP information"""
        from ..enricher import fetch_with_retries
        
        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": ioc_value, "maxAgeInDays": 90}
        
        try:
            resp = await fetch_with_retries(
                session, ABUSEIPDB_URL,
                headers=headers, params=params,
                max_retries=max_retries,
                backoff_factor=backoff_factor
            )
            return resp
        except Exception as e:
            return {"error": str(e), "timestamp": time.time()}
    
    def extract_fields(self, raw_response: Dict[str, Any], ioc_type: str) -> Dict[str, Any]:
        """Extract relevant fields from AbuseIPDB response"""
        if "error" in raw_response:
            return raw_response
        
        data = raw_response.get("data", {}) or {}
        return {
            "score": data.get("abuseConfidenceScore", "-"),
            "country": data.get("countryCode", "-"),
            "isp": data.get("isp", "-"),
            "reports": data.get("totalReports", "-"),
            "last_seen": data.get("lastReportedAt", "-"),
            "timestamp": time.time(),
        }
    
    def format_display(self, ioc_value: str, ioc_type: str, extracted_data: Dict[str, Any]) -> List[str]:
        """Format AbuseIPDB data for display"""
        lines = []
        lines.append(f"  {MAGENTA}🐝 AbuseIPDB:{RESET}\n")
        
        if "error" in extracted_data:
            from ..settings import RED
            lines.append(f"    {RED}ℹ️  Error{RESET}: {extracted_data['error']}\n\n")
        else:
            lines.append(f"    {BOLD}{GREEN}Link{RESET}     : https://www.abuseipdb.com/check/{ioc_value}\n")
            lines.append(f"    {GREEN}Score{RESET}    : {extracted_data.get('score', '-')}\n")
            lines.append(f"    {GREEN}Country{RESET}  : {extracted_data.get('country', '-')}\n")
            lines.append(f"    {GREEN}ISP{RESET}      : {extracted_data.get('isp', '-')}\n")
            lines.append(f"    {GREEN}Reports{RESET}  : {extracted_data.get('reports', '-')}\n")
            lines.append(f"    {GREEN}Last Seen{RESET}: {extracted_data.get('last_seen', '-')}\n\n")
        return lines
    
    def get_display_name(self) -> str:
        return f"{MAGENTA}🐝 AbuseIPDB{RESET}"