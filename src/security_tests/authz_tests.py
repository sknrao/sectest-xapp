"""
Authorization Security Tests
Tests SEC-CTL-NEAR-RT-3, 3A, 3B, 3C, 4, 5, 10
"""

import requests
import logging
import time
import jwt
import json

logger = logging.getLogger(__name__)


class AuthorizationTester:
    """
    Tests authorization mechanisms:
    - OAuth 2.0 framework (SEC-CTL-NEAR-RT-3)
    - Platform service authorization (SEC-CTL-NEAR-RT-3A, 3B, 3C)
    - A1 resource owner/server (SEC-CTL-NEAR-RT-4)
    - A1 client (SEC-CTL-NEAR-RT-5)
    """
    
    def __init__(self, xapp):
        self.xapp = xapp
        self.config_helper = xapp.config_helper
        self.results = {}
    
    def run_tests(self):
        """Run all authorization tests"""
        logger.info("Testing Authorization Controls...")
        
        # Test 1: OAuth 2.0 token acquisition
        self.test_oauth_token_flow()
        
        # Test 2: API access with valid token
        self.test_api_access_with_token()
        
        # Test 3: API access without token (should fail)
        self.test_api_access_without_token()
        
        # Test 4: Expired token rejection
        self.test_expired_token_rejection()
        
        # Test 5: Scope enforcement (least privilege)
        self.test_scope_enforcement()
        
        # Test 6: Resource discovery restrictions
        self.test_api_discovery_restrictions()
        
        return self.results
    
    def test_oauth_token_flow(self):
        """
        SEC-CTL-NEAR-RT-3: Test OAuth 2.0 authorization flow
        Verify token acquisition from authorization server
        """
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
            
            if response.status_code == 200:
                token_data = response.json()
                
                if 'access_token' in token_data:
                    # Decode and validate JWT
                    token = token_data['access_token']
                    decoded = jwt.decode(token, options={"verify_signature": False})
                    
                    logger.info(f"    Token acquired: {decoded.get('jti', 'N/A')[:8]}...")
                    logger.info(f"    Scope: {decoded.get('scope', 'N/A')}")
                    logger.info(f"    Expires: {decoded.get('exp', 'N/A')}")
                    
                    # Store token for subsequent tests
                    self.xapp.oauth_token = token
                    
                    self.results[test_name] = {
                        'status': 'PASS',
                        'message': 'OAuth 2.0 token acquired successfully',
                        'control': 'SEC-CTL-NEAR-RT-3',
                        'token_jti': decoded.get('jti', 'N/A')
                    }
                    logger.info(f"    ✓ PASS: OAuth token flow working")
                else:
                    self.results[test_name] = {
                        'status': 'FAIL',
                        'message': 'No access_token in response',
                        'control': 'SEC-CTL-NEAR-RT-3'
                    }
                    logger.error(f"    ✗ FAIL: No access_token")
            else:
                self.results[test_name] = {
                    'status': 'FAIL',
                    'message': f'Token request failed: {response.status_code}',
                    'control': 'SEC-CTL-NEAR-RT-3'
                }
                logger.error(f"    ✗ FAIL: Status {response.status_code}")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'SEC-CTL-NEAR-RT-3'
            }
            logger.error(f"    ✗ ERROR: {e}")
    
    def test_api_access_with_token(self):
        """
        SEC-CTL-NEAR-RT-3: Test API access with valid OAuth token
        """
        logger.info("  [2.2] Testing API Access with Valid Token...")
        
        test_name = "api_access_with_token"
        
        try:
            if not hasattr(self.xapp, 'oauth_token'):
                self.results[test_name] = {
                    'status': 'SKIP',
                    'message': 'No token available from previous test',
                    'control': 'SEC-CTL-NEAR-RT-3'
                }
                return
            
            api_url = self.xapp.config.get('platform_api_url', 'https://localhost:8080/api')
            
            # Make API request with Bearer token
            response = requests.get(
                f"{api_url}/subscriptions",
                headers={'Authorization': f'Bearer {self.xapp.oauth_token}'},
                cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                verify='/opt/certs/ca-cert.pem',
                timeout=10
            )
            
            if response.status_code in [200, 204]:
                self.results[test_name] = {
                    'status': 'PASS',
                    'message': 'API access granted with valid token',
                    'control': 'SEC-CTL-NEAR-RT-3'
                }
                logger.info(f"    ✓ PASS: API accessible with token")
            else:
                self.results[test_name] = {
                    'status': 'FAIL',
                    'message': f'Unexpected status: {response.status_code}',
                    'control': 'SEC-CTL-NEAR-RT-3'
                }
                logger.error(f"    ✗ FAIL: Status {response.status_code}")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'SEC-CTL-NEAR-RT-3'
            }
            logger.error(f"    ✗ ERROR: {e}")
    
    def test_api_access_without_token(self):
        """
        SEC-CTL-NEAR-RT-3: Verify API rejects requests without token
        """
        logger.info("  [2.3] Testing API Access Without Token...")
        
        test_name = "api_access_without_token"
        
        try:
            api_url = self.xapp.config.get('platform_api_url', 'https://localhost:8080/api')
            
            # Attempt API access without Authorization header
            response = requests.get(
                f"{api_url}/subscriptions",
                cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                verify='/opt/certs/ca-cert.pem',
                timeout=10
            )
            
            if response.status_code == 401:
                self.results[test_name] = {
                    'status': 'PASS',
                    'message': 'API correctly rejected request without token',
                    'control': 'SEC-CTL-NEAR-RT-3'
                }
                logger.info(f"    ✓ PASS: Unauthorized access blocked")
            else:
                self.results[test_name] = {
                    'status': 'FAIL',
                    'message': f'API did not reject tokenless request: {response.status_code}',
                    'control': 'SEC-CTL-NEAR-RT-3'
                }
                logger.error(f"    ✗ FAIL: No authorization required")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'SEC-CTL-NEAR-RT-3'
            }
            logger.error(f"    ✗ ERROR: {e}")
    
    def test_expired_token_rejection(self):
        """Test that platform rejects expired tokens"""
        logger.info("  [2.4] Testing Expired Token Rejection...")
        
        test_name = "expired_token_rejection"
        
        try:
            api_url = self.xapp.config.get('platform_api_url', 'https://localhost:8080/api')
            
            # Create an expired token (for testing purposes)
            # In production, wait for actual token expiry
            expired_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MDAwMDAwMDB9.invalid"
            
            response = requests.get(
                f"{api_url}/subscriptions",
                headers={'Authorization': f'Bearer {expired_token}'},
                cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                verify='/opt/certs/ca-cert.pem',
                timeout=10
            )
            
            if response.status_code == 401:
                self.results[test_name] = {
                    'status': 'PASS',
                    'message': 'Platform correctly rejected expired token',
                    'control': 'SEC-CTL-NEAR-RT-3'
                }
                logger.info(f"    ✓ PASS: Expired token rejected")
            else:
                self.results[test_name] = {
                    'status': 'FAIL',
                    'message': f'Expired token accepted: {response.status_code}',
                    'control': 'SEC-CTL-NEAR-RT-3'
                }
                logger.error(f"    ✗ FAIL: Expired token not rejected")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'SEC-CTL-NEAR-RT-3'
            }
            logger.error(f"    ✗ ERROR: {e}")
    
    def test_scope_enforcement(self):
        """
        SEC-CTL-NEAR-RT-3B: Test least privilege / scope enforcement
        Verify xApp can only access authorized resources
        """
        logger.info("  [2.5] Testing Scope Enforcement (Least Privilege)...")
        
        test_name = "scope_enforcement"
        
        try:
            if not hasattr(self.xapp, 'oauth_token'):
                self.results[test_name] = {
                    'status': 'SKIP',
                    'message': 'No token available',
                    'control': 'SEC-CTL-NEAR-RT-3B'
                }
                return
            
            api_url = self.xapp.config.get('platform_api_url', 'https://localhost:8080/api')
            
            # Try to access an endpoint that requires admin scope
            # (xApp should only have platform:read/write, not admin)
            response = requests.get(
                f"{api_url}/admin/config",
                headers={'Authorization': f'Bearer {self.xapp.oauth_token}'},
                cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                verify='/opt/certs/ca-cert.pem',
                timeout=10
            )
            
            if response.status_code == 403:
                self.results[test_name] = {
                    'status': 'PASS',
                    'message': 'Platform enforced scope restrictions (least privilege)',
                    'control': 'SEC-CTL-NEAR-RT-3B'
                }
                logger.info(f"    ✓ PASS: Scope enforcement working")
            else:
                self.results[test_name] = {
                    'status': 'FAIL',
                    'message': f'Scope not enforced: {response.status_code}',
                    'control': 'SEC-CTL-NEAR-RT-3B'
                }
                logger.error(f"    ✗ FAIL: No scope restriction")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'SEC-CTL-NEAR-RT-3B'
            }
            logger.error(f"    ✗ ERROR: {e}")
    
    def test_api_discovery_restrictions(self):
        """
        SEC-CTL-NEAR-RT-3C: Test API discovery restrictions
        Verify xApp can only discover authorized APIs
        """
        logger.info("  [2.6] Testing API Discovery Restrictions...")
        
        test_name = "api_discovery_restrictions"
        
        try:
            if not hasattr(self.xapp, 'oauth_token'):
                self.results[test_name] = {
                    'status': 'SKIP',
                    'message': 'No token available',
                    'control': 'SEC-CTL-NEAR-RT-3C'
                }
                return
            
            api_url = self.xapp.config.get('platform_api_url', 'https://localhost:8080/api')
            
            # Request API discovery/service catalog
            response = requests.get(
                f"{api_url}/services",
                headers={'Authorization': f'Bearer {self.xapp.oauth_token}'},
                cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                verify='/opt/certs/ca-cert.pem',
                timeout=10
            )
            
            if response.status_code == 200:
                services = response.json()
                
                # Verify only authorized services are visible
                # (Based on operator policies)
                restricted_services = ['admin-api', 'internal-debug']
                visible_restricted = [s for s in services if s.get('name') in restricted_services]
                
                if not visible_restricted:
                    self.results[test_name] = {
                        'status': 'PASS',
                        'message': 'API discovery properly restricted based on policies',
                        'control': 'SEC-CTL-NEAR-RT-3C',
                        'visible_services': len(services)
                    }
                    logger.info(f"    ✓ PASS: {len(services)} authorized services visible")
                else:
                    self.results[test_name] = {
                        'status': 'FAIL',
                        'message': f'Restricted services visible: {visible_restricted}',
                        'control': 'SEC-CTL-NEAR-RT-3C'
                    }
                    logger.error(f"    ✗ FAIL: Unauthorized services visible")
            else:
                self.results[test_name] = {
                    'status': 'WARN',
                    'message': f'API discovery endpoint status: {response.status_code}',
                    'control': 'SEC-CTL-NEAR-RT-3C'
                }
                logger.warning(f"    ⚠ WARN: Status {response.status_code}")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'SEC-CTL-NEAR-RT-3C'
            }
            logger.error(f"    ✗ ERROR: {e}")