"""Provider registry for auto-discovery and management of TI providers"""
import os
import importlib
from typing import Dict, List
from .providers.base import TIProvider
from .settings import ENABLED_SERVICES


class ProviderRegistry:
    """Registry for managing threat intelligence providers"""
    
    def __init__(self):
        self.providers: Dict[str, List[TIProvider]] = {
            "ip": [],
            "hash": [],
            "url": [],
            "domain": []
        }
        self._discover_and_register_providers()
    
    def _discover_and_register_providers(self):
        """Auto-discover and register all available providers"""
        # Import and register each provider based on available API keys
        self.disabled_providers = []  # Track providers disabled due to missing API keys
        
        # AbuseIPDB
        if "abuseipdb" in ENABLED_SERVICES:
            try:
                from .providers.abuseipdb import AbuseIPDBProvider
                provider = AbuseIPDBProvider(ENABLED_SERVICES["abuseipdb"])
                self._register_provider(provider)
            except ImportError as e:
                print(f"[Registry] Failed to load AbuseIPDB provider: {e}")
        else:
            self.disabled_providers.append(("AbuseIPDB", "ABUSEIPDB_KEY", ["ip"]))
        
        # VirusTotal
        if "virustotal" in ENABLED_SERVICES:
            try:
                from .providers.virustotal import VirusTotalProvider
                provider = VirusTotalProvider(ENABLED_SERVICES["virustotal"])
                self._register_provider(provider)
            except ImportError as e:
                print(f"[Registry] Failed to load VirusTotal provider: {e}")
        else:
            self.disabled_providers.append(("VirusTotal", "VT_KEY", ["ip", "hash", "url", "domain"]))
        
        # MalwareBazaar (no API key required)
        try:
            from .providers.malwarebazaar import MalwareBazaarProvider
            provider = MalwareBazaarProvider()
            self._register_provider(provider)
        except ImportError as e:
            print(f"[Registry] Failed to load MalwareBazaar provider: {e}")
        
        # URLScan
        if "urlscan" in ENABLED_SERVICES:
            try:
                from .providers.urlscan import URLScanProvider
                provider = URLScanProvider(ENABLED_SERVICES["urlscan"])
                self._register_provider(provider)
            except ImportError as e:
                print(f"[Registry] Failed to load URLScan provider: {e}")
        else:
            self.disabled_providers.append(("URLScan", "URLSCAN_KEY", ["url"]))
    
    def _register_provider(self, provider: TIProvider):
        """Register a provider for its supported IOC types"""
        if not provider.is_enabled():
            return
        
        for ioc_type in provider.get_supported_ioc_types():
            if ioc_type in self.providers:
                self.providers[ioc_type].append(provider)
    
    def get_providers_for_ioc_type(self, ioc_type: str) -> List[TIProvider]:
        """Get all providers that support a specific IOC type"""
        return self.providers.get(ioc_type, [])
    
    def get_all_providers(self) -> List[TIProvider]:
        """Get all registered providers (deduplicated)"""
        all_providers = []
        seen = set()
        
        for provider_list in self.providers.values():
            for provider in provider_list:
                if provider.name not in seen:
                    all_providers.append(provider)
                    seen.add(provider.name)
        
        return all_providers
    
    def get_provider_count_by_type(self) -> Dict[str, int]:
        """Get count of providers per IOC type"""
        return {ioc_type: len(providers) for ioc_type, providers in self.providers.items()}
    
    def get_missing_providers_for_ioc_type(self, ioc_type: str) -> List[tuple]:
        """Get disabled providers that support a specific IOC type"""
        return [(name, env_var) for name, env_var, supported_types in self.disabled_providers 
                if ioc_type in supported_types]


# Global registry instance
_registry = None


def get_registry() -> ProviderRegistry:
    """Get the global provider registry instance"""
    global _registry
    if _registry is None:
        _registry = ProviderRegistry()
    return _registry