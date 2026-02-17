"""
Data Validation Security Tests
Tests SEC-CTL-NEAR-RT-8, 15, 17, 18
"""

import requests
import logging
import json
import time
from datetime import datetime

logger = logging.getLogger(__name__)


class DataValidationTester:
    """
    Tests data validation mechanisms:
    - A1 policy validation (SEC-CTL-NEAR-RT-8)
    - Y1 data validation (SEC-CTL-NEAR-RT-15, 16)
    - E2 data validation (SEC-CTL-NEAR-RT-17)
    - xApp→Platform data validation (SEC-CTL-NEAR-RT-18)
    """
    
    def __init__(self, xapp):
        self.xapp = xapp
        self.config_helper = xapp.config_helper
        self.results = {}
    
    def run_tests(self):
        """Run all data validation tests"""
        logger.info("Testing Data Validation Controls...")
        
        # Test 1: A1 policy schema validation
        self.test_a1_policy_schema_validation()
        
        # Test 2: A1 policy value validation
        self.test_a1_policy_value_validation()
        
        # Test 3: A1 policy rate limiting
        self.test_a1_policy_rate_validation()
        
        # Test 4: SQL injection protection
        self.test_sql_injection_protection()
        
        # Test 5: Command injection protection
        self.test_command_injection_protection()
        
        # Test 6: Buffer overflow protection
        self.test_buffer_overflow_protection()
        
        # Test 7: E2 subscription data validation
        self.test_e2_subscription_validation()
        
        # Test 8: Invalid data rejection logging
        self.test_invalid_data_logging()
        
        return self.results
    
    def test_a1_policy_schema_validation(self):
        """
        SEC-CTL-NEAR-RT-8: Test A1 policy schema validation
        Verify policies conform to pre-defined schema
        """
        logger.info("  [3.1] Testing A1 Policy Schema Validation...")
        
        test_name = "a1_policy_schema_validation"
        
        try:
            if not hasattr(self.xapp, 'oauth_token'):
                self.results[test_name] = {'status': 'SKIP', 'message': 'No token available'}
                return
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
            
            # Platform should reject with 400 Bad Request
            if response.status_code == 400:
                error_response = response.json()
                if 'schema' in error_response.get('error', '').lower():
                    self.results[test_name] = {
                        'status': 'PASS',
                        'message': 'Platform correctly rejected invalid policy schema',
                        'control': 'SEC-CTL-NEAR-RT-8'
                    }
                    logger.info(f"    ✓ PASS: Schema validation enforced")
                else:
                    self.results[test_name] = {
                        'status': 'WARN',
                        'message': f'Rejected but error unclear: {error_response}',
                        'control': 'SEC-CTL-NEAR-RT-8'
                    }
                    logger.warning(f"    ⚠ WARN: Unclear error message")
            elif response.status_code == 201:
                self.results[test_name] = {
                    'status': 'FAIL',
                    'message': 'Platform accepted invalid policy schema',
                    'control': 'SEC-CTL-NEAR-RT-8'
                }
                logger.error(f"    ✗ FAIL: Invalid schema accepted")
            else:
                self.results[test_name] = {
                    'status': 'WARN',
                    'message': f'Unexpected status: {response.status_code}',
                    'control': 'SEC-CTL-NEAR-RT-8'
                }
                logger.warning(f"    ⚠ WARN: Status {response.status_code}")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'SEC-CTL-NEAR-RT-8'
            }
            logger.error(f"    ✗ ERROR: {e}")
    
    def test_a1_policy_value_validation(self):
        """
        SEC-CTL-NEAR-RT-8: Test A1 policy value validation
        Verify policy values are valid (within acceptable ranges)
        """
        logger.info("  [3.2] Testing A1 Policy Value Validation...")
        
        test_name = "a1_policy_value_validation"
        
        try:
            if not hasattr(self.xapp, 'oauth_token'):
                self.results[test_name] = {'status': 'SKIP', 'message': 'No token available'}
                return
            
            api_url = self.xapp.config.get('platform_api_url', 'https://localhost:8080/api')
            
            # Send policy with out-of-range values
            invalid_value_policy = {
                "policy_id": "test-policy-002",
                "policy_type_id": "20008",
                "ric_id": "ric1",
                "policy_data": {
                    "threshold": 99999999,  # Exceeds maximum
                    "scope": {
                        "ue_id": "invalid-ue-format",  # Invalid format
                        "cell_id": -1  # Negative value
                    }
                }
            }
            
            response = requests.post(
                f"{api_url}/a1-p/policies",
                headers={
                    'Authorization': f'Bearer {self.xapp.oauth_token}',
                    'Content-Type': 'application/json'
                },
                json=invalid_value_policy,
                cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                verify='/opt/certs/ca-cert.pem',
                timeout=10
            )
            
            if response.status_code == 400:
                self.results[test_name] = {
                    'status': 'PASS',
                    'message': 'Platform correctly rejected invalid policy values',
                    'control': 'SEC-CTL-NEAR-RT-8'
                }
                logger.info(f"    ✓ PASS: Value validation enforced")
            elif response.status_code == 201:
                self.results[test_name] = {
                    'status': 'FAIL',
                    'message': 'Platform accepted invalid policy values',
                    'control': 'SEC-CTL-NEAR-RT-8'
                }
                logger.error(f"    ✗ FAIL: Invalid values accepted")
            else:
                self.results[test_name] = {
                    'status': 'WARN',
                    'message': f'Unexpected status: {response.status_code}',
                    'control': 'SEC-CTL-NEAR-RT-8'
                }
                logger.warning(f"    ⚠ WARN: Status {response.status_code}")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'SEC-CTL-NEAR-RT-8'
            }
            logger.error(f"    ✗ ERROR: {e}")
    
    def test_a1_policy_rate_validation(self):
        """
        SEC-CTL-NEAR-RT-8: Test A1 policy rate limiting
        Verify policies are received at/below pre-defined rate
        """
        logger.info("  [3.3] Testing A1 Policy Rate Limiting...")
        
        test_name = "a1_policy_rate_validation"
        
        try:
            if not hasattr(self.xapp, 'oauth_token'):
                self.results[test_name] = {'status': 'SKIP', 'message': 'No token available'}
                return
            
            api_url = self.xapp.config.get('platform_api_url', 'https://localhost:8080/api')
            
            # Send burst of policies to test rate limiting
            max_rate = self.xapp.config.get('a1_policy_max_rate', 10)  # 10 policies/sec
            burst_count = max_rate * 2  # Send double the allowed rate
            
            valid_policy = {
                "policy_type_id": "20008",
                "ric_id": "ric1",
                "policy_data": {"threshold": 10}
            }
            
            rejected_count = 0
            accepted_count = 0
            
            logger.info(f"    Sending {burst_count} policies in burst...")
            
            start_time = time.time()
            for i in range(burst_count):
                policy = valid_policy.copy()
                policy['policy_id'] = f"rate-test-{i}"
                
                response = requests.post(
                    f"{api_url}/a1-p/policies",
                    headers={
                        'Authorization': f'Bearer {self.xapp.oauth_token}',
                        'Content-Type': 'application/json'
                    },
                    json=policy,
                    cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                    verify='/opt/certs/ca-cert.pem',
                    timeout=5
                )
                
                if response.status_code == 429:  # Too Many Requests
                    rejected_count += 1
                elif response.status_code == 201:
                    accepted_count += 1
            
            elapsed = time.time() - start_time
            actual_rate = accepted_count / elapsed
            
            logger.info(f"    Accepted: {accepted_count}, Rejected: {rejected_count}")
            logger.info(f"    Actual rate: {actual_rate:.2f} policies/sec")
            
            if rejected_count > 0:
                self.results[test_name] = {
                    'status': 'PASS',
                    'message': f'Rate limiting enforced: {rejected_count}/{burst_count} rejected',
                    'control': 'SEC-CTL-NEAR-RT-8',
                    'accepted': accepted_count,
                    'rejected': rejected_count,
                    'actual_rate': round(actual_rate, 2)
                }
                logger.info(f"    ✓ PASS: Rate limiting working")
            else:
                self.results[test_name] = {
                    'status': 'FAIL',
                    'message': f'No rate limiting: {accepted_count}/{burst_count} accepted',
                    'control': 'SEC-CTL-NEAR-RT-8',
                    'actual_rate': round(actual_rate, 2)
                }
                logger.error(f"    ✗ FAIL: No rate limiting detected")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'SEC-CTL-NEAR-RT-8'
            }
            logger.error(f"    ✗ ERROR: {e}")
    
    def test_sql_injection_protection(self):
        """
        REQ-SEC-NEAR-RT-7, 8, 9: Test SQL injection protection
        Verify platform defends against injection attacks
        """
        logger.info("  [3.4] Testing SQL Injection Protection...")
        
        test_name = "sql_injection_protection"
        
        try:
            if not hasattr(self.xapp, 'oauth_token'):
                self.results[test_name] = {'status': 'SKIP', 'message': 'No token available'}
                return
            
            api_url = self.xapp.config.get('platform_api_url', 'https://localhost:8080/api')
            
            # SQL injection payloads
            sql_payloads = [
                "' OR '1'='1",
                "1; DROP TABLE policies--",
                "' UNION SELECT * FROM users--",
                "admin'--",
                "1' AND '1'='1"
            ]
            
            injection_blocked = 0
            injection_passed = 0
            
            for payload in sql_payloads:
                response = requests.get(
                    f"{api_url}/policies",
                    params={'ric_id': payload},
                    headers={'Authorization': f'Bearer {self.xapp.oauth_token}'},
                    cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                    verify='/opt/certs/ca-cert.pem',
                    timeout=10
                )
                
                # Should be rejected with 400 or 403
                if response.status_code in [400, 403]:
                    injection_blocked += 1
                elif response.status_code == 200:
                    # Check if response seems normal (not SQL error)
                    try:
                        data = response.json()
                        if 'error' in str(data).lower() and 'sql' in str(data).lower():
                            injection_passed += 1  # SQL error leaked
                        else:
                            injection_blocked += 1  # Sanitized
                    except:
                        injection_blocked += 1
            
            if injection_blocked == len(sql_payloads):
                self.results[test_name] = {
                    'status': 'PASS',
                    'message': f'All {len(sql_payloads)} SQL injection attempts blocked',
                    'control': 'REQ-SEC-NEAR-RT-7'
                }
                logger.info(f"    ✓ PASS: SQL injection protection working")
            elif injection_blocked > 0:
                self.results[test_name] = {
                    'status': 'WARN',
                    'message': f'{injection_blocked}/{len(sql_payloads)} injections blocked',
                    'control': 'REQ-SEC-NEAR-RT-7'
                }
                logger.warning(f"    ⚠ WARN: Partial protection")
            else:
                self.results[test_name] = {
                    'status': 'FAIL',
                    'message': 'No SQL injection protection detected',
                    'control': 'REQ-SEC-NEAR-RT-7'
                }
                logger.error(f"    ✗ FAIL: SQL injection vulnerable")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'REQ-SEC-NEAR-RT-7'
            }
            logger.error(f"    ✗ ERROR: {e}")
    
    def test_command_injection_protection(self):
        """Test command injection protection"""
        logger.info("  [3.5] Testing Command Injection Protection...")
        
        test_name = "command_injection_protection"
        
        try:
            if not hasattr(self.xapp, 'oauth_token'):
                self.results[test_name] = {'status': 'SKIP', 'message': 'No token available'}
                return
            
            api_url = self.xapp.config.get('platform_api_url', 'https://localhost:8080/api')
            
            # Command injection payloads
            cmd_payloads = [
                "; ls -la",
                "| cat /etc/passwd",
                "`whoami`",
                "$(id)",
                "&& rm -rf /"
            ]
            
            injection_blocked = 0
            
            for payload in cmd_payloads:
                policy = {
                    "policy_id": f"cmd-test-{hash(payload)}",
                    "policy_type_id": "20008",
                    "ric_id": payload,  # Injection in ric_id field
                    "policy_data": {"threshold": 10}
                }
                
                response = requests.post(
                    f"{api_url}/a1-p/policies",
                    headers={
                        'Authorization': f'Bearer {self.xapp.oauth_token}',
                        'Content-Type': 'application/json'
                    },
                    json=policy,
                    cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                    verify='/opt/certs/ca-cert.pem',
                    timeout=10
                )
                
                if response.status_code in [400, 403]:
                    injection_blocked += 1
            
            if injection_blocked == len(cmd_payloads):
                self.results[test_name] = {
                    'status': 'PASS',
                    'message': f'All {len(cmd_payloads)} command injection attempts blocked',
                    'control': 'REQ-SEC-NEAR-RT-7'
                }
                logger.info(f"    ✓ PASS: Command injection protection working")
            else:
                self.results[test_name] = {
                    'status': 'FAIL',
                    'message': f'Only {injection_blocked}/{len(cmd_payloads)} injections blocked',
                    'control': 'REQ-SEC-NEAR-RT-7'
                }
                logger.error(f"    ✗ FAIL: Command injection vulnerable")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'REQ-SEC-NEAR-RT-7'
            }
            logger.error(f"    ✗ ERROR: {e}")
    
    def test_buffer_overflow_protection(self):
        """
        REQ-SEC-NEAR-RT-7, 8, 9: Test buffer overflow protection
        Verify platform handles oversized inputs safely
        """
        logger.info("  [3.6] Testing Buffer Overflow Protection...")
        
        test_name = "buffer_overflow_protection"
        
        try:
            if not hasattr(self.xapp, 'oauth_token'):
                self.results[test_name] = {'status': 'SKIP', 'message': 'No token available'}
                return
            
            api_url = self.xapp.config.get('platform_api_url', 'https://localhost:8080/api')
            
            # Create oversized payloads
            oversized_payloads = [
                {'size': 1024, 'data': 'A' * 1024},           # 1KB
                {'size': 10240, 'data': 'B' * 10240},         # 10KB
                {'size': 102400, 'data': 'C' * 102400},       # 100KB
                {'size': 1048576, 'data': 'D' * 1048576},     # 1MB
            ]
            
            overflow_blocked = 0
            
            for payload_info in oversized_payloads:
                policy = {
                    "policy_id": f"overflow-test-{payload_info['size']}",
                    "policy_type_id": "20008",
                    "ric_id": "ric1",
                    "policy_data": {
                        "description": payload_info['data']
                    }
                }
                
                try:
                    response = requests.post(
                        f"{api_url}/a1-p/policies",
                        headers={
                            'Authorization': f'Bearer {self.xapp.oauth_token}',
                            'Content-Type': 'application/json'
                        },
                        json=policy,
                        cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                        verify='/opt/certs/ca-cert.pem',
                        timeout=10
                    )
                    
                    if response.status_code in [400, 413]:  # Bad Request or Payload Too Large
                        overflow_blocked += 1
                        logger.debug(f"      {payload_info['size']} bytes: BLOCKED")
                    else:
                        logger.debug(f"      {payload_info['size']} bytes: status {response.status_code}")
                        
                except requests.exceptions.RequestException as e:
                    # Connection error might indicate crash - bad sign
                    logger.error(f"      {payload_info['size']} bytes: Connection error")
            
            if overflow_blocked >= len(oversized_payloads) - 1:  # Allow one size to pass
                self.results[test_name] = {
                    'status': 'PASS',
                    'message': f'{overflow_blocked}/{len(oversized_payloads)} oversized payloads blocked',
                    'control': 'REQ-SEC-NEAR-RT-7'
                }
                logger.info(f"    ✓ PASS: Buffer overflow protection working")
            else:
                self.results[test_name] = {
                    'status': 'FAIL',
                    'message': f'Only {overflow_blocked}/{len(oversized_payloads)} blocked',
                    'control': 'REQ-SEC-NEAR-RT-7'
                }
                logger.error(f"    ✗ FAIL: Insufficient overflow protection")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'REQ-SEC-NEAR-RT-7'
            }
            logger.error(f"    ✗ ERROR: {e}")
    
    def test_e2_subscription_validation(self):
        """
        SEC-CTL-NEAR-RT-17, 18: Test E2 subscription data validation
        Verify E2-related API data is validated
        """
        logger.info("  [3.7] Testing E2 Subscription Data Validation...")
        
        test_name = "e2_subscription_validation"
        
        try:
            if not hasattr(self.xapp, 'oauth_token'):
                self.results[test_name] = {'status': 'SKIP', 'message': 'No token available'}
                return
            
            api_url = self.xapp.config.get('platform_api_url', 'https://localhost:8080/api')
            
            # Invalid E2 subscription request
            invalid_subscription = {
                "ClientEndpoint": {
                    "Host": "invalid-host-format",  # Invalid format
                    "HTTPPort": -1,  # Invalid port
                    "RMRPort": 999999  # Out of range
                },
                "Meid": "../../../etc/passwd",  # Path traversal attempt
                "RANFunctionID": "not-a-number",  # Invalid type
                "SubscriptionDetails": []  # Empty (should have entries)
            }
            
            response = requests.post(
                f"{api_url}/subscriptions",
                headers={
                    'Authorization': f'Bearer {self.xapp.oauth_token}',
                    'Content-Type': 'application/json'
                },
                json=invalid_subscription,
                cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                verify='/opt/certs/ca-cert.pem',
                timeout=10
            )
            
            if response.status_code == 400:
                self.results[test_name] = {
                    'status': 'PASS',
                    'message': 'Platform correctly rejected invalid E2 subscription data',
                    'control': 'SEC-CTL-NEAR-RT-17,18'
                }
                logger.info(f"    ✓ PASS: E2 data validation enforced")
            elif response.status_code == 201:
                self.results[test_name] = {
                    'status': 'FAIL',
                    'message': 'Platform accepted invalid E2 subscription data',
                    'control': 'SEC-CTL-NEAR-RT-17,18'
                }
                logger.error(f"    ✗ FAIL: Invalid E2 data accepted")
            else:
                self.results[test_name] = {
                    'status': 'WARN',
                    'message': f'Unexpected status: {response.status_code}',
                    'control': 'SEC-CTL-NEAR-RT-17,18'
                }
                logger.warning(f"    ⚠ WARN: Status {response.status_code}")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'SEC-CTL-NEAR-RT-17,18'
            }
            logger.error(f"    ✗ ERROR: {e}")
    
    def test_invalid_data_logging(self):
        """
        SEC-CTL-NEAR-RT-8, 16, 17, 18: Test security event logging
        Verify that invalid data attempts are logged
        """
        logger.info("  [3.8] Testing Invalid Data Logging...")
        
        test_name = "invalid_data_logging"
        
        try:
            # This test would require access to platform logs
            # For now, we'll make a request and check if logging endpoint exists
            
            if not hasattr(self.xapp, 'oauth_token'):
                self.results[test_name] = {'status': 'SKIP', 'message': 'No token available'}
                return
            
            api_url = self.xapp.config.get('platform_api_url', 'https://localhost:8080/api')
            
            # Send invalid data that should be logged
            invalid_policy = {
                "policy_id": "logging-test",
                "injection_attempt": "'; DROP TABLE--"
            }
            
            response = requests.post(
                f"{api_url}/a1-p/policies",
                headers={
                    'Authorization': f'Bearer {self.xapp.oauth_token}',
                    'Content-Type': 'application/json'
                },
                json=invalid_policy,
                cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                verify='/opt/certs/ca-cert.pem',
                timeout=10
            )
            
            # Query security logs (if available)
            time.sleep(2)  # Wait for log to be written
            
            log_response = requests.get(
                f"{api_url}/logs/security",
                params={
                    'timeframe': '5m',
                    'event_type': 'validation_failure'
                },
                headers={'Authorization': f'Bearer {self.xapp.oauth_token}'},
                cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                verify='/opt/certs/ca-cert.pem',
                timeout=10
            )
            
            if log_response.status_code == 200:
                logs = log_response.json()
                
                # Check if our validation failure was logged
                recent_logs = [log for log in logs if 'logging-test' in str(log)]
                
                if recent_logs:
                    self.results[test_name] = {
                        'status': 'PASS',
                        'message': f'Validation failure logged ({len(recent_logs)} entries)',
                        'control': 'SEC-CTL-NEAR-RT-8,16,17,18'
                    }
                    logger.info(f"    ✓ PASS: Security logging working")
                else:
                    self.results[test_name] = {
                        'status': 'WARN',
                        'message': 'Logs accessible but event not found',
                        'control': 'SEC-CTL-NEAR-RT-8,16,17,18'
                    }
                    logger.warning(f"    ⚠ WARN: Event not in logs")
            else:
                self.results[test_name] = {
                    'status': 'SKIP',
                    'message': f'Security logs not accessible: {log_response.status_code}',
                    'control': 'SEC-CTL-NEAR-RT-8,16,17,18'
                }
                logger.info(f"    ⊘ SKIP: Logs not accessible")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'SEC-CTL-NEAR-RT-8,16,17,18'
            }
            logger.error(f"    ✗ ERROR: {e}")
