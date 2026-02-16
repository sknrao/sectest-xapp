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