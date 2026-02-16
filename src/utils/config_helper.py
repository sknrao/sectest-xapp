"""
Configuration helper for building API URLs
Reads from config and constructs full endpoint URLs
"""

import logging

logger = logging.getLogger(__name__)


class ConfigHelper:
    """Helper class to manage configuration and build API URLs"""
    
    def __init__(self, config):
        self.config = config
        
        # Get platform settings
        platform = config.get('platform', {})
        self.base_url = platform.get('base_url', config.get('platform_api_url', 'https://localhost:8080'))
        self.verify_ssl = platform.get('verify_ssl', True)
        self.timeout = platform.get('timeout', 30)
        
        # Get endpoints
        self.endpoints = config.get('endpoints', {})
        
        # Get alternative endpoints
        self.alt_endpoints = config.get('alternative_endpoints', {})
        
        # Get authentication config
        auth = config.get('authentication', config.get('certificates', {}))
        self.cert_file = auth.get('cert_file', '/opt/certs/xapp-cert.pem')
        self.key_file = auth.get('key_file', '/opt/certs/xapp-key.pem')
        self.ca_file = auth.get('ca_file', '/opt/certs/ca-cert.pem')
        
        # Get test config
        self.test_config = config.get('test_configuration', config.get('test_config', {}))
        
        logger.info(f"Configuration loaded: base_url={self.base_url}")
    
    def get_url(self, endpoint_name, use_alternative=None, **kwargs):
        """
        Build full URL for an endpoint
        
        Args:
            endpoint_name: Name of endpoint (e.g., 'health', 'oauth_token')
            use_alternative: If provided, use alternative base URL
            **kwargs: Variables to substitute in path (e.g., policyTypeId)
        
        Returns:
            Full URL string
        """
        # Check if using alternative endpoint
        if use_alternative:
            alt_base = self.alt_endpoints.get(f"{use_alternative}_base_url")
            alt_path = self.alt_endpoints.get(f"{use_alternative}_{endpoint_name}")
            
            if alt_base and alt_path:
                url = f"{alt_base}{alt_path}"
                logger.debug(f"Using alternative endpoint: {url}")
                return self._substitute_vars(url, **kwargs)
        
        # Use standard endpoint
        # First check endpoints section, then fall back to legacy config
        endpoint_path = self.endpoints.get(endpoint_name)
        
        # Fallback mappings for legacy config
        if not endpoint_path:
            legacy_mappings = {
                'health': '/api/health',
                'services': '/api/services',
                'subscriptions': '/api/subscriptions',
                'a1_policytypes': '/a1-p/policytypes',
                'a1_policies': '/a1-p/policytypes/{policyTypeId}/policies',
                'security_logs': '/api/logs/security',
                'admin_config': '/api/admin/config',
                'admin_secrets': '/api/admin/secrets',
                'oauth_token': self.config.get('oauth_token_url', '/oauth/token').replace(self.base_url, ''),
                'oauth_introspect': '/oauth/introspect'
            }
            endpoint_path = legacy_mappings.get(endpoint_name, f'/api/{endpoint_name}')
        
        url = f"{self.base_url}{endpoint_path}"
        return self._substitute_vars(url, **kwargs)
    
    def _substitute_vars(self, url, **kwargs):
        """Substitute variables in URL template"""
        for key, value in kwargs.items():
            url = url.replace(f"{{{key}}}", str(value))
        return url
    
    def get_cert_tuple(self):
        """Get certificate tuple for requests"""
        return (self.cert_file, self.key_file)
    
    def is_test_enabled(self, test_category):
        """Check if a test category is enabled"""
        key = f"enable_{test_category}_tests"
        return self.test_config.get(key, True)
    
    def get_test_param(self, category, param, default=None):
        """Get test-specific parameter"""
        category_config = self.test_config.get(category, {})
        return category_config.get(param, default)


# Add to src/utils/__init__.py
__all__ = [
    'validate_xapp_cert',
    'get_cert_expiry',
    'get_cert_info',
    'SecurityReportGenerator',
    'SecurityMetrics',
    'ConfigHelper'  # Add this
]