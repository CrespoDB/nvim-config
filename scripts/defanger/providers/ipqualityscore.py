"""IPQualityScore threat intelligence provider"""
import time
from typing import Dict, List, Any
from .base import TIProvider
from ..settings import GREEN, CYAN, RED, YELLOW, RESET, BOLD


class IPQualityScoreProvider(TIProvider):
    """IPQualityScore provider for IP reputation, VPN/proxy detection, and fraud scoring"""
    
    def __init__(self, api_key: str):
        super().__init__(api_key, "IPQualityScore")
    
    def get_supported_ioc_types(self) -> List[str]:
        return ["ip"]
    
    async def query(self, ioc_value: str, ioc_type: str, session, max_retries=3, backoff_factor=1, **kwargs) -> Dict[str, Any]:
        """Query IPQualityScore for IP reputation information"""
        from ..enricher import fetch_with_retries
        
        url = f"https://ipqualityscore.com/api/json/ip/{self.api_key}/{ioc_value}"
        
        try:
            resp = await fetch_with_retries(
                session, url,
                max_retries=max_retries,
                backoff_factor=backoff_factor
            )
            return resp
        except Exception as e:
            return {"error": str(e), "timestamp": time.time()}
    
    def extract_fields(self, raw_response: Dict[str, Any], ioc_type: str) -> Dict[str, Any]:
        """Extract relevant fields from IPQualityScore response"""
        if "error" in raw_response:
            return raw_response
        
        # Handle API error responses
        if not raw_response.get("success", True):
            error_msg = raw_response.get("message", "API request failed")
            return {"error": error_msg, "timestamp": time.time()}
        
        return {
            "fraud_score": raw_response.get("fraud_score", 0),
            "country_code": raw_response.get("country_code", "-"),
            "region": raw_response.get("region", "-"),
            "city": raw_response.get("city", "-"),
            "isp": raw_response.get("ISP", "-"),
            "organization": raw_response.get("organization", "-"),
            "asn": raw_response.get("ASN", "-"),
            "host": raw_response.get("host", "-"),
            "proxy": raw_response.get("proxy", False),
            "vpn": raw_response.get("vpn", False),
            "tor": raw_response.get("tor", False),
            "active_vpn": raw_response.get("active_vpn", False),
            "active_tor": raw_response.get("active_tor", False),
            "is_crawler": raw_response.get("is_crawler", False),
            "connection_type": raw_response.get("connection_type", "-"),
            "recent_abuse": raw_response.get("recent_abuse", False),
            "abuse_velocity": raw_response.get("abuse_velocity", "-"),
            "bot_status": raw_response.get("bot_status", False),
            "mobile": raw_response.get("mobile", False),
            "timezone": raw_response.get("timezone", "-"),
            "latitude": raw_response.get("latitude", None),
            "longitude": raw_response.get("longitude", None),
            "zip_code": raw_response.get("zip_code", "-"),
            "request_id": raw_response.get("request_id", "-"),
            "timestamp": time.time(),
        }
    
    def format_display(self, ioc_value: str, ioc_type: str, extracted_data: Dict[str, Any]) -> List[str]:
        """Format IPQualityScore data for display"""
        lines = []
        lines.append(f"  {CYAN}🛡️ IPQualityScore:{RESET}\n")
        
        if "error" in extracted_data:
            lines.append(f"    {RED}ℹ️  Error{RESET}: {extracted_data['error']}\n\n")
        else:
            # Fraud Score (prominent display)
            fraud_score = extracted_data.get('fraud_score', 0)
            if fraud_score >= 90:
                score_color = RED
                risk_level = "🚨 HIGH RISK"
            elif fraud_score >= 75:
                score_color = YELLOW
                risk_level = "⚠️  SUSPICIOUS"
            else:
                score_color = GREEN
                risk_level = "✅ LOW RISK"
            
            lines.append(f"    {BOLD}Fraud Score{RESET}: {score_color}{fraud_score}/100{RESET} ({risk_level})\n")
            
            # Location information
            location = f"{extracted_data.get('city', '-')}, {extracted_data.get('region', '-')}, {extracted_data.get('country_code', '-')}"
            lines.append(f"    {GREEN}Location{RESET}   : {location}\n")
            lines.append(f"    {GREEN}ISP{RESET}        : {extracted_data.get('isp', '-')}\n")
            lines.append(f"    {GREEN}Organization{RESET}: {extracted_data.get('organization', '-')}\n")
            lines.append(f"    {GREEN}ASN{RESET}        : {extracted_data.get('asn', '-')}\n")
            
            # Connection type
            conn_type = extracted_data.get('connection_type', '-')
            if conn_type != '-' and not conn_type.startswith('Premium required'):
                lines.append(f"    {GREEN}Conn. Type{RESET} : {conn_type}\n")
            
            # Proxy/VPN Detection (critical security info)
            proxy_flags = []
            if extracted_data.get('proxy', False):
                proxy_flags.append(f"{RED}Proxy{RESET}")
            if extracted_data.get('vpn', False):
                proxy_flags.append(f"{RED}VPN{RESET}")
            if extracted_data.get('tor', False):
                proxy_flags.append(f"{RED}Tor{RESET}")
            if extracted_data.get('active_vpn', False):
                proxy_flags.append(f"{RED}Active VPN{RESET}")
            if extracted_data.get('active_tor', False):
                proxy_flags.append(f"{RED}Active Tor{RESET}")
            
            if proxy_flags:
                lines.append(f"    {RED}⚠️  Anonymizer{RESET}: {', '.join(proxy_flags)}\n")
            else:
                lines.append(f"    {GREEN}Anonymizer{RESET} : No proxy/VPN detected\n")
            
            # Threat indicators
            threat_flags = []
            if extracted_data.get('recent_abuse', False):
                threat_flags.append(f"{RED}Recent Abuse{RESET}")
            if extracted_data.get('bot_status', False):
                threat_flags.append(f"{RED}Bot Activity{RESET}")
            if extracted_data.get('is_crawler', False):
                threat_flags.append(f"{YELLOW}Search Crawler{RESET}")
            
            if threat_flags:
                lines.append(f"    {RED}🚩 Threats{RESET}   : {', '.join(threat_flags)}\n")
            
            # Abuse velocity if available
            abuse_velocity = extracted_data.get('abuse_velocity', '-')
            if abuse_velocity != '-' and not abuse_velocity.startswith('Premium required'):
                velocity_color = RED if abuse_velocity in ['high', 'medium'] else GREEN
                lines.append(f"    {velocity_color}Abuse Rate{RESET}  : {abuse_velocity}\n")
            
            # Additional info
            if extracted_data.get('mobile', False):
                lines.append(f"    {GREEN}Device{RESET}     : Mobile\n")
            
            timezone = extracted_data.get('timezone', '-')
            if timezone != '-':
                lines.append(f"    {GREEN}Timezone{RESET}   : {timezone}\n")
            
            lines.append("\n")
        
        return lines
    
    def get_display_name(self) -> str:
        return f"{CYAN}🛡️ IPQualityScore{RESET}"