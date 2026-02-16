# CODE UPDATES REQUIRED - Making Configuration Actually Work

## ❌ Current Problem

**You're absolutely right!** The current code does NOT use the enhanced configuration. It only uses:
- `platform_api_url` 
- `oauth_token_url`

The code **hardcodes** endpoint paths like:
```python
api_url = f"{platform_api_url}/health"
api_url = f"{platform_api_url}/subscriptions"
```

This means the `endpoints` and `alternative_endpoints` in config.json **won't be used** unless we update the code.

---

## ✅ Solution: Update the Code

I'll provide the updated code that actually uses the configuration properly.

---

## 📝 Step 1: Create Configuration Helper Utility

Create `src/utils/config_helper.py`:

```python
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
```

---

## 📝 Step 2: Update main.py to Use ConfigHelper

```python
#!/usr/bin/env python3
"""
Security Testing xApp for O-RAN Near-RT RIC
"""

import os
import sys
import time
import json
import logging
from threading import Thread
from ricxappframe.xapp_frame import RMRXapp, rmr

from security_tests.auth_tests import AuthenticationTester
from security_tests.authz_tests import AuthorizationTester
from security_tests.data_validation_tests import DataValidationTester
from security_tests.rate_limit_tests import RateLimitTester
from security_tests.logging_tests import LoggingTester
from utils.report_generator import SecurityReportGenerator
from utils.metrics import SecurityMetrics
from utils.config_helper import ConfigHelper  # Add this

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SecurityTestXapp:
    """Main xApp class for security testing"""
    
    def __init__(self):
        """Initialize the security testing xApp"""
        # Load configuration
        self.config = self._load_config()
        
        # Create configuration helper
        self.config_helper = ConfigHelper(self.config)  # Add this
        
        # Initialize RMR xApp framework
        self.xapp = RMRXapp(
            self._rmr_handler,
            config_file=self.config.get('config_file', '/opt/config/config-file.json'),
            rmr_port=self.config.get('rmr_port', 4560),
            rmr_wait_for_ready=True,
            use_fake_sdl=False
        )
        
        # Make config_helper available to test modules
        self.xapp.config = self.config
        self.xapp.config_helper = self.config_helper  # Add this
        
        # Initialize test modules (now they can use config_helper)
        self.auth_tester = AuthenticationTester(self.xapp)
        self.authz_tester = AuthorizationTester(self.xapp)
        self.data_validator = DataValidationTester(self.xapp)
        self.rate_limiter = RateLimitTester(self.xapp)
        self.log_tester = LoggingTester(self.xapp)
        
        # Metrics and reporting
        self.metrics = SecurityMetrics()
        self.report_gen = SecurityReportGenerator()
        
        # Test results
        self.test_results = {
            'authentication': {},
            'authorization': {},
            'data_validation': {},
            'rate_limiting': {},
            'logging': {}
        }
        
        logger.info("Security Testing xApp initialized")
        logger.info(f"Platform: {self.config_helper.base_url}")
    
    def _load_config(self):
        """Load configuration from file"""
        config_file = os.getenv('CONFIG_FILE', '/opt/config/config-file.json')
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            
            # Apply environment variable overrides
            config = self._apply_env_overrides(config)
            return config
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return {}
    
    def _apply_env_overrides(self, config):
        """Override config with environment variables"""
        # Platform URL
        if os.getenv('PLATFORM_BASE_URL'):
            if 'platform' not in config:
                config['platform'] = {}
            config['platform']['base_url'] = os.getenv('PLATFORM_BASE_URL')
        
        # OAuth endpoint
        if os.getenv('OAUTH_TOKEN_URL'):
            if 'endpoints' not in config:
                config['endpoints'] = {}
            config['endpoints']['oauth_token'] = os.getenv('OAUTH_TOKEN_URL')
        
        # xApp credentials
        if os.getenv('XAPP_ID'):
            if 'xapp_identity' not in config:
                config['xapp_identity'] = {}
            config['xapp_identity']['xapp_id'] = os.getenv('XAPP_ID')
        
        if os.getenv('XAPP_SECRET'):
            if 'xapp_identity' not in config:
                config['xapp_identity'] = {}
            config['xapp_identity']['xapp_secret'] = os.getenv('XAPP_SECRET')
        
        return config
    
    # ... rest of the code remains the same ...
```

---

## 📝 Step 3: Update Test Files to Use ConfigHelper

### Example: auth_tests.py

```python
"""
Authentication Security Tests
"""

import ssl
import requests
import logging
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import uuid

logger = logging.getLogger(__name__)


class AuthenticationTester:
    """Tests authentication mechanisms"""
    
    def __init__(self, xapp):
        self.xapp = xapp
        self.config_helper = xapp.config_helper  # Use config helper
        self.results = {}
    
    def run_tests(self):
        """Run all authentication tests"""
        logger.info("Testing Authentication Controls...")
        
        # Test 1: mTLS for REST APIs
        self.test_mtls_rest_api()
        
        # ... other tests ...
        
        return self.results
    
    def test_mtls_rest_api(self):
        """SEC-CTL-NEAR-RT-1: Test mTLS for REST APIs"""
        logger.info("  [1.1] Testing mTLS for REST APIs...")
        
        test_name = "mtls_rest_api"
        
        try:
            # OLD WAY (hardcoded):
            # api_url = f"{self.xapp.config.get('platform_api_url')}/health"
            
            # NEW WAY (configurable):
            api_url = self.config_helper.get_url('health')
            cert_tuple = self.config_helper.get_cert_tuple()
            
            # Attempt mTLS connection
            response = requests.get(
                api_url,
                cert=cert_tuple,
                verify=self.config_helper.ca_file,
                timeout=self.config_helper.timeout
            )
            
            if response.status_code == 200:
                self.results[test_name] = {
                    'status': 'PASS',
                    'message': 'mTLS authentication successful',
                    'control': 'SEC-CTL-NEAR-RT-1'
                }
                logger.info(f"    ✓ PASS: mTLS authentication working")
            else:
                self.results[test_name] = {
                    'status': 'FAIL',
                    'message': f'Unexpected status code: {response.status_code}',
                    'control': 'SEC-CTL-NEAR-RT-1'
                }
                logger.error(f"    ✗ FAIL: Status code {response.status_code}")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'SEC-CTL-NEAR-RT-1'
            }
            logger.error(f"    ✗ ERROR: {e}")
```

### Example: authz_tests.py

```python
class AuthorizationTester:
    """Tests authorization mechanisms"""
    
    def __init__(self, xapp):
        self.xapp = xapp
        self.config_helper = xapp.config_helper
        self.results = {}
    
    def test_oauth_token_flow(self):
        """SEC-CTL-NEAR-RT-3: Test OAuth 2.0 authorization flow"""
        logger.info("  [2.1] Testing OAuth 2.0 Token Flow...")
        
        test_name = "oauth_token_flow"
        
        try:
            # NEW WAY (configurable):
            token_url = self.config_helper.get_url('oauth_token')
            
            # Get credentials
            xapp_id = self.xapp.config.get('xapp_identity', {}).get('xapp_id')
            xapp_secret = self.xapp.config.get('xapp_identity', {}).get('xapp_secret')
            
            # Request token
            response = requests.post(
                token_url,
                data={
                    'grant_type': 'client_credentials',
                    'client_id': xapp_id,
                    'client_secret': xapp_secret,
                    'scope': 'platform:read platform:write'
                },
                cert=self.config_helper.get_cert_tuple(),
                verify=self.config_helper.ca_file,
                timeout=self.config_helper.timeout
            )
            
            # ... rest of test ...
```

### Example: data_validation_tests.py

```python
class DataValidationTester:
    """Tests data validation mechanisms"""
    
    def __init__(self, xapp):
        self.xapp = xapp
        self.config_helper = xapp.config_helper
        self.results = {}
    
    def test_a1_policy_schema_validation(self):
        """SEC-CTL-NEAR-RT-8: Test A1 policy schema validation"""
        
        try:
            # NEW WAY (configurable):
            # Build URL with path variable substitution
            api_url = self.config_helper.get_url('a1_policies', policyTypeId='20008')
            
            # Or if using alternative E2 manager:
            # api_url = self.config_helper.get_url('subscriptions', use_alternative='e2mgr')
            
            invalid_policy = {
                "policy_id": "test-policy-001",
            }
            
            response = requests.post(
                api_url,
                headers={
                    'Authorization': f'Bearer {self.xapp.oauth_token}',
                    'Content-Type': 'application/json'
                },
                json=invalid_policy,
                cert=self.config_helper.get_cert_tuple(),
                verify=self.config_helper.ca_file,
                timeout=self.config_helper.timeout
            )
            
            # ... rest of test ...
```

---

## 📝 Step 4: Update ALL Test Files

Apply the same pattern to:
- ✅ `auth_tests.py`
- ✅ `authz_tests.py`
- ✅ `data_validation_tests.py`
- ✅ `rate_limit_tests.py`
- ✅ `logging_tests.py`

**Pattern to replace in all files:**

**OLD:**
```python
api_url = self.xapp.config.get('platform_api_url', 'https://localhost:8080/api')
api_url = f"{api_url}/health"
```

**NEW:**
```python
api_url = self.config_helper.get_url('health')
```

**OLD:**
```python
cert_file = '/opt/certs/xapp-cert.pem'
key_file = '/opt/certs/xapp-key.pem'
ca_file = '/opt/certs/ca-cert.pem'
```

**NEW:**
```python
cert_tuple = self.config_helper.get_cert_tuple()
ca_file = self.config_helper.ca_file
```

---

## 📋 Complete List of Changes Needed

### Files to Create:
1. ✅ `src/utils/config_helper.py` (NEW FILE - provided above)

### Files to Update:
2. ✅ `src/main.py` - Add ConfigHelper initialization
3. ✅ `src/utils/__init__.py` - Export ConfigHelper
4. ✅ `src/security_tests/auth_tests.py` - Use config_helper
5. ✅ `src/security_tests/authz_tests.py` - Use config_helper
6. ✅ `src/security_tests/data_validation_tests.py` - Use config_helper
7. ✅ `src/security_tests/rate_limit_tests.py` - Use config_helper
8. ✅ `src/security_tests/logging_tests.py` - Use config_helper

---

## 🚀 Quick Find-and-Replace Guide

Use these patterns to update all test files:

**Pattern 1: API URL Construction**
```bash
# Find:
api_url = self.xapp.config.get('platform_api_url', '[^']+')
# Or:
api_url = f"{[^}]+}/[^"]*"

# Replace with:
api_url = self.config_helper.get_url('ENDPOINT_NAME')
```

**Pattern 2: Certificate Files**
```bash
# Find:
cert_file = [^
]+
key_file = [^
]+

# Replace with:
cert_tuple = self.config_helper.get_cert_tuple()
```

**Pattern 3: Add config_helper to __init__**
```python
# In every test class __init__:
def __init__(self, xapp):
    self.xapp = xapp
    self.config_helper = xapp.config_helper  # Add this line
    self.results = {}
```

---

## ✅ Testing the Changes

After making these changes:

```bash
# 1. Update your config
vim config/config-file.json
# Change: "base_url": "https://YOUR-ACTUAL-URL"

# 2. Create ConfigMap
kubectl create configmap security-test-xapp-config \
  --from-file=config-file.json \
  -n ricxapp \
  --dry-run=client -o yaml | kubectl apply -f -

# 3. Test config helper
python3 << EOF
import json
from src.utils.config_helper import ConfigHelper

with open('config/config-file.json') as f:
    config = json.load(f)

helper = ConfigHelper(config)
print(f"Health URL: {helper.get_url('health')}")
print(f"OAuth URL: {helper.get_url('oauth_token')}")
print(f"A1 Policy URL: {helper.get_url('a1_policies', policyTypeId='20008')}")
EOF

# 4. Rebuild and deploy
docker build -t security-xapp:latest .
kubectl delete pod -l app=security-test-xapp -n ricxapp
```

---

## 📊 Summary

### Current State: ❌
- Code only uses `platform_api_url` and `oauth_token_url`
- Endpoint paths are **hardcoded**
- `endpoints` and `alternative_endpoints` config **is NOT used**

### After Updates: ✅
- All endpoint paths configurable
- Support for alternative service URLs
- Certificate paths configurable
- Test parameters configurable
- **Just update JSON, no code changes needed**

### What You Need to Do:
1. ✅ Create `src/utils/config_helper.py` (copy code above)
2. ✅ Update `src/main.py` (add ConfigHelper)
3. ✅ Update all 5 test files (use config_helper)
4. ✅ Update `config-file.json` with your endpoints
5. ✅ Rebuild Docker image
6. ✅ Deploy!

**After these changes, just updating config.json will work!** 🎉
