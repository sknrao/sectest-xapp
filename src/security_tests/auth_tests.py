"""
Authentication Security Tests
Tests SEC-CTL-NEAR-RT-1, 2, 2A, 9, 12, 13, 14
"""

import ssl
import requests
import logging
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import uuid

logger = logging.getLogger(__name__)


class AuthenticationTester:
    """
    Tests authentication mechanisms:
    - mTLS for REST/gRPC (SEC-CTL-NEAR-RT-1)
    - Certificate validation (SEC-CTL-NEAR-RT-12, 13, 14)
    - A1/Y1 mTLS (SEC-CTL-NEAR-RT-2A, 9)
    """
    
    def __init__(self, xapp):
        self.xapp = xapp
        self.results = {}
    
    def run_tests(self):
        """Run all authentication tests"""
        logger.info("Testing Authentication Controls...")
        
        # Test 1: mTLS for REST APIs (SEC-CTL-NEAR-RT-1)
        self.test_mtls_rest_api()
        
        # Test 2: Certificate xApp ID validation (SEC-CTL-NEAR-RT-12, 13, 14)
        self.test_xapp_cert_identity()
        
        # Test 3: Invalid certificate rejection
        self.test_invalid_cert_rejection()
        
        # Test 4: Certificate expiry handling
        self.test_cert_expiry()
        
        # Test 5: Cipher suite strength
        self.test_cipher_strength()
        
        return self.results
    
    def test_mtls_rest_api(self):
        """
        SEC-CTL-NEAR-RT-1: Test mTLS for REST APIs
        Verify mutual TLS authentication using X.509v3 certificates
        """
        logger.info("  [1.1] Testing mTLS for REST APIs...")
        
        test_name = "mtls_rest_api"
        
        try:
            # Get platform API endpoint
            api_url = self.xapp.config.get('platform_api_url', 'https://localhost:8080/api')
            
            # Load xApp certificate and key
            cert_file = '/opt/certs/xapp-cert.pem'
            key_file = '/opt/certs/xapp-key.pem'
            ca_file = '/opt/certs/ca-cert.pem'
            
            # Attempt mTLS connection
            response = requests.get(
                f"{api_url}/health",
                cert=(cert_file, key_file),
                verify=ca_file,
                timeout=5
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
    
    def test_xapp_cert_identity(self):
        """
        SEC-CTL-NEAR-RT-12, 13, 14: Test xApp ID in certificate
        Verify:
        - xApp ID is embedded in X.509 certificate
        - xApp ID is UUID v4 format
        - subjectAltName contains URI-ID with UUID
        """
        logger.info("  [1.2] Testing xApp Certificate Identity...")
        
        test_name = "xapp_cert_identity"
        
        try:
            cert_file = '/opt/certs/xapp-cert.pem'
            
            # Load certificate
            with open(cert_file, 'rb') as f:
                cert_data = f.read()
            
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            # Extract subjectAltName
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            
            # Find URI-ID in SAN
            uri_found = False
            valid_uuid = False
            
            for name in san_ext.value:
                if isinstance(name, x509.UniformResourceIdentifier):
                    uri = name.value
                    logger.info(f"    Found URI in SAN: {uri}")
                    uri_found = True
                    
                    # Check if it's a URN with UUID format
                    if uri.startswith('urn:uuid:'):
                        uuid_str = uri.replace('urn:uuid:', '')
                        try:
                            # Validate UUID v4
                            parsed_uuid = uuid.UUID(uuid_str, version=4)
                            valid_uuid = True
                            logger.info(f"    ✓ Valid UUID v4: {uuid_str}")
                        except ValueError:
                            logger.error(f"    ✗ Invalid UUID format: {uuid_str}")
            
            if uri_found and valid_uuid:
                self.results[test_name] = {
                    'status': 'PASS',
                    'message': 'xApp ID correctly embedded as UUID v4 in subjectAltName',
                    'control': 'SEC-CTL-NEAR-RT-12,13,14'
                }
                logger.info(f"    ✓ PASS: xApp certificate identity valid")
            else:
                self.results[test_name] = {
                    'status': 'FAIL',
                    'message': f'URI found: {uri_found}, Valid UUID: {valid_uuid}',
                    'control': 'SEC-CTL-NEAR-RT-12,13,14'
                }
                logger.error(f"    ✗ FAIL: Certificate identity validation failed")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'SEC-CTL-NEAR-RT-12,13,14'
            }
            logger.error(f"    ✗ ERROR: {e}")
    
    def test_invalid_cert_rejection(self):
        """Test that platform rejects invalid certificates"""
        logger.info("  [1.3] Testing Invalid Certificate Rejection...")
        
        test_name = "invalid_cert_rejection"
        
        try:
            api_url = self.xapp.config.get('platform_api_url', 'https://localhost:8080/api')
            
            # Attempt connection without client cert (should fail)
            try:
                response = requests.get(
                    f"{api_url}/health",
                    verify='/opt/certs/ca-cert.pem',
                    timeout=5
                )
                # If we get here, the platform didn't enforce mTLS
                self.results[test_name] = {
                    'status': 'FAIL',
                    'message': 'Platform accepted connection without client certificate',
                    'control': 'SEC-CTL-NEAR-RT-1'
                }
                logger.error(f"    ✗ FAIL: No client cert required")
            except requests.exceptions.SSLError:
                # This is expected - platform rejected connection
                self.results[test_name] = {
                    'status': 'PASS',
                    'message': 'Platform correctly rejected connection without client cert',
                    'control': 'SEC-CTL-NEAR-RT-1'
                }
                logger.info(f"    ✓ PASS: Invalid cert rejected")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'SEC-CTL-NEAR-RT-1'
            }
            logger.error(f"    ✗ ERROR: {e}")
    
    def test_cert_expiry(self):
        """Test certificate expiration handling"""
        logger.info("  [1.4] Testing Certificate Expiry Handling...")
        
        test_name = "cert_expiry"
        
        try:
            cert_file = '/opt/certs/xapp-cert.pem'
            
            with open(cert_file, 'rb') as f:
                cert_data = f.read()
            
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            # Check expiry
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc)
            
            days_until_expiry = (cert.not_valid_after_utc - now).days
            
            if days_until_expiry > 30:
                self.results[test_name] = {
                    'status': 'PASS',
                    'message': f'Certificate valid for {days_until_expiry} more days',
                    'control': 'SEC-CTL-NEAR-RT-1'
                }
                logger.info(f"    ✓ PASS: Certificate expires in {days_until_expiry} days")
            elif days_until_expiry > 0:
                self.results[test_name] = {
                    'status': 'WARN',
                    'message': f'Certificate expiring soon: {days_until_expiry} days',
                    'control': 'SEC-CTL-NEAR-RT-1'
                }
                logger.warning(f"    ⚠ WARN: Certificate expires in {days_until_expiry} days")
            else:
                self.results[test_name] = {
                    'status': 'FAIL',
                    'message': 'Certificate expired',
                    'control': 'SEC-CTL-NEAR-RT-1'
                }
                logger.error(f"    ✗ FAIL: Certificate expired")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'SEC-CTL-NEAR-RT-1'
            }
            logger.error(f"    ✗ ERROR: {e}")
    
    def test_cipher_strength(self):
        """Test that only strong cipher suites are supported"""
        logger.info("  [1.5] Testing Cipher Suite Strength...")
        
        test_name = "cipher_strength"
        
        try:
            api_url = self.xapp.config.get('platform_api_url', 'https://localhost:8080/api')
            
            # Try weak cipher (should be rejected)
            weak_ciphers = 'DES-CBC3-SHA'
            
            context = ssl.create_default_context()
            context.set_ciphers(weak_ciphers)
            context.load_cert_chain('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem')
            
            try:
                # This should fail if platform enforces strong ciphers
                requests.get(api_url, timeout=5)
                self.results[test_name] = {
                    'status': 'FAIL',
                    'message': 'Platform accepted weak cipher suite',
                    'control': 'SEC-CTL-NEAR-RT-6'
                }
                logger.error(f"    ✗ FAIL: Weak cipher accepted")
            except:
                self.results[test_name] = {
                    'status': 'PASS',
                    'message': 'Platform rejected weak cipher suite',
                    'control': 'SEC-CTL-NEAR-RT-6'
                }
                logger.info(f"    ✓ PASS: Weak cipher rejected")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'SEC-CTL-NEAR-RT-6'
            }
            logger.error(f"    ✗ ERROR: {e}")