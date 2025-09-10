"""URLScan threat intelligence provider"""
import time
import asyncio
from typing import Dict, List, Any
from .base import TIProvider
from ..settings import URLSCAN_SUBMIT_URL, URLSCAN_RESULT_URL, GREEN, CYAN, RESET, BOLD


class URLScanProvider(TIProvider):
    """URLScan provider for URL analysis"""
    
    def __init__(self, api_key: str):
        super().__init__(api_key, "URLScan")
    
    def get_supported_ioc_types(self) -> List[str]:
        return ["url"]
    
    async def query(self, ioc_value: str, ioc_type: str, session, max_retries=3, poll_interval=5, max_polls=10, **kwargs) -> Dict[str, Any]:
        """Query URLScan for URL information"""
        from ..enricher import fetch_with_retries
        
        try:
            # Submit URL for scanning
            headers = {"API-Key": self.api_key, "Content-Type": "application/json"}
            payload = {"url": ioc_value}
            submit_resp = await fetch_with_retries(
                session, URLSCAN_SUBMIT_URL, 
                headers=headers, json_data=payload, 
                method="POST", max_retries=max_retries
            )
            
            scan_uuid = submit_resp.get("uuid")
            if not scan_uuid:
                return {"error": "Failed to get scan UUID"}
            
            # Poll for results
            headers = {"API-Key": self.api_key}
            for _ in range(max_polls):
                try:
                    result_resp = await fetch_with_retries(
                        session, URLSCAN_RESULT_URL.format(scan_uuid), 
                        headers=headers, max_retries=max_retries
                    )
                    if result_resp.get("status") == "done" or result_resp.get("task", {}).get("state") == "done":
                        return result_resp
                    await asyncio.sleep(poll_interval)
                except Exception:
                    await asyncio.sleep(poll_interval)
            
            return {"error": "Scan timeout - results not ready"}
            
        except Exception as e:
            return {"error": str(e)}
    
    def extract_fields(self, raw_response: Dict[str, Any], ioc_type: str) -> Dict[str, Any]:
        """Extract relevant fields from URLScan response"""
        if "error" in raw_response:
            return raw_response
        
        task = raw_response.get("task", {})
        stats = raw_response.get("stats", {})
        
        return {
            "screenshot_url": task.get("screenshotURL", ""),
            "report_url": task.get("reportURL", ""),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "safe": stats.get("safe", 0),
            "domain": task.get("domain", "-"),
            "ip": task.get("apexDomain", "-"),
            "country": task.get("country", "-")
        }
    
    def format_display(self, ioc_value: str, ioc_type: str, extracted_data: Dict[str, Any]) -> List[str]:
        """Format URLScan data for display"""
        lines = []
        lines.append(f"  {CYAN}🔎 URLScan:{RESET}\n")
        
        if "error" in extracted_data:
            lines.append(f"    {GREEN}Error{RESET}: {extracted_data['error']}\n")
        else:
            if extracted_data.get("report_url"):
                lines.append(f"    {BOLD}{GREEN}Report{RESET}   : {extracted_data['report_url']}\n")
            
            malicious = extracted_data.get("malicious", 0)
            suspicious = extracted_data.get("suspicious", 0)
            safe = extracted_data.get("safe", 0)
            lines.append(f"    {GREEN}Verdict{RESET}  : {malicious} malicious, {suspicious} suspicious, {safe} safe\n")
            lines.append(f"    {GREEN}Domain{RESET}   : {extracted_data.get('domain', '-')}\n")
            lines.append(f"    {GREEN}IP{RESET}       : {extracted_data.get('ip', '-')}\n")
            lines.append(f"    {GREEN}Country{RESET}  : {extracted_data.get('country', '-')}\n")
        
        lines.append("\n")
        return lines
    
    def get_display_name(self) -> str:
        return f"{CYAN}🔎 URLScan{RESET}"