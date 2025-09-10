"""Base class for threat intelligence providers"""
import time
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional


class TIProvider(ABC):
    """Base class for all threat intelligence providers"""
    
    def __init__(self, api_key: Optional[str] = None, name: str = ""):
        self.api_key = api_key
        self.name = name
        self.enabled = bool(api_key) if api_key else True
    
    @abstractmethod
    def get_supported_ioc_types(self) -> List[str]:
        """Return list of IOC types this provider supports (ip, hash, url, domain)"""
        pass
    
    @abstractmethod
    async def query(self, ioc_value: str, ioc_type: str, session, **kwargs) -> Dict[str, Any]:
        """Query the provider for information about an IOC"""
        pass
    
    def extract_fields(self, raw_response: Dict[str, Any], ioc_type: str) -> Dict[str, Any]:
        """Extract relevant fields from raw API response. Override in subclass."""
        return raw_response
    
    @abstractmethod
    def format_display(self, ioc_value: str, ioc_type: str, extracted_data: Dict[str, Any]) -> List[str]:
        """Format the extracted data for display"""
        pass
    
    def is_enabled(self) -> bool:
        """Check if provider is enabled"""
        return self.enabled
    
    def get_name(self) -> str:
        """Get provider name"""
        return self.name
    
    def get_display_name(self) -> str:
        """Get display name with icon"""
        return self.name