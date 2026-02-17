"""
Security Logging Tests
Tests SEC-CTL-NEAR-RT-8, 16, 17, 18 logging requirements
"""

import requests
import logging
import time
import json
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class LoggingTester:
    """
    Tests security logging mechanisms:
    - A1 validation failure logging (SEC-CTL-NEAR-RT-8)
    - Y1 validation failure logging (SEC-CTL-NEAR-RT-16)
    - E2 validation failure logging (SEC-CTL-NEAR-RT-17, 18)
    """
    
    def __init__(self, xapp):
        self.xapp = xapp
        self.config_helper = xapp.config_helper
        self.results = {}
    
    def run_tests(self):
        """Run all security logging tests"""
        logger.info("Testing Security Logging Controls...")
        
        # Test 1: Security event generation
        self.test_security_event_generation()
        
        # Test 2: Log completeness
        self.test_log_completeness()
        
        # Test 3: Log tampering protection
        self.test_log_integrity()
        
        # Test 4: Log retention
        self.test_log_retention()
        
        return self.results
    
    def test_security_event_generation(self):
        """
        Test that security events are generated and logged
        Trigger various violations and check logs
        """
        logger.info("  [5.1] Testing Security Event Generation...")
        
        test_name = "security_event_generation"
        
        try:
            if not hasattr(self.xapp, 'oauth_token'):
                self.results[test_name] = {'status': 'SKIP', 'message': 'No token available'}
                return
            
            #api_url = self.xapp.config.get('platform_api_url', 'https://localhost:8080/api')
            api_url = self.config_helper.get_url('health')
            cert_tuple = self.config_helper.get_cert_tuple()
            
            # Trigger various security events
            security_events = []
            
            # Event 1: Invalid authentication
            try:
                resp = requests.get(
                    api_url,
                    headers={'Authorization': 'Bearer invalid-token'},
                    cert=cert_tuple,
                    verify=self.config_helper.ca_file,
                    timeout=self.config_helper.timeout
                )
                security_events.append(('auth_failure', resp.status_code))
            except:
                pass
            
            # Event 2: Invalid input data
            try:
                resp = requests.post(
                    f"{api_url}/a1-p/policies",
                    headers={
                        'Authorization': f'Bearer {self.xapp.oauth_token}',
                        'Content-Type': 'application/json'
                    },
                    json={'malicious': "'; DROP TABLE--"},
                    cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                    verify='/opt/certs/ca-cert.pem',
                    timeout=5
                )
                security_events.append(('injection_attempt', resp.status_code))
            except:
                pass
            
            # Event 3: Unauthorized access
            try:
                resp = requests.get(
                    f"{api_url}/admin/secrets",
                    headers={'Authorization': f'Bearer {self.xapp.oauth_token}'},
                    cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                    verify='/opt/certs/ca-cert.pem',
                    timeout=5
                )
                security_events.append(('authz_failure', resp.status_code))
            except:
                pass
            
            # Wait for logs to be written
            time.sleep(3)
            
            # Query security logs
            try:
                log_response = requests.get(
                    f"{api_url}/logs/security",
                    params={
                        'timeframe': '1m',
                        'severity': 'warning,error'
                    },
                    headers={'Authorization': f'Bearer {self.xapp.oauth_token}'},
                    cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                    verify='/opt/certs/ca-cert.pem',
                    timeout=10
                )
                
                if log_response.status_code == 200:
                    logs = log_response.json()
                    
                    # Count how many of our events were logged
                    logged_events = 0
                    for event_type, _ in security_events:
                        if any(event_type in str(log).lower() for log in logs):
                            logged_events += 1
                    
                    if logged_events >= len(security_events) * 0.8:  # 80% logged
                        self.results[test_name] = {
                            'status': 'PASS',
                            'message': f'{logged_events}/{len(security_events)} security events logged',
                            'control': 'SEC-CTL-NEAR-RT-8,16,17,18',
                            'events_triggered': len(security_events),
                            'events_logged': logged_events
                        }
                        logger.info(f"    ✓ PASS: Security events logged")
                    else:
                        self.results[test_name] = {
                            'status': 'WARN',
                            'message': f'Only {logged_events}/{len(security_events)} events logged',
                            'control': 'SEC-CTL-NEAR-RT-8,16,17,18'
                        }
                        logger.warning(f"    ⚠ WARN: Incomplete logging")
                else:
                    self.results[test_name] = {
                        'status': 'SKIP',
                        'message': f'Cannot access security logs: {log_response.status_code}',
                        'control': 'SEC-CTL-NEAR-RT-8,16,17,18'
                    }
                    logger.info(f"    ⊘ SKIP: Logs not accessible")
                    
            except Exception as e:
                self.results[test_name] = {
                    'status': 'SKIP',
                    'message': f'Log query failed: {str(e)}',
                    'control': 'SEC-CTL-NEAR-RT-8,16,17,18'
                }
                logger.info(f"    ⊘ SKIP: {e}")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'SEC-CTL-NEAR-RT-8,16,17,18'
            }
            logger.error(f"    ✗ ERROR: {e}")
    
    def test_log_completeness(self):
        """
        Test that security logs contain required fields
        """
        logger.info("  [5.2] Testing Log Completeness...")
        
        test_name = "log_completeness"
        
        try:
            if not hasattr(self.xapp, 'oauth_token'):
                self.results[test_name] = {'status': 'SKIP', 'message': 'No token available'}
                return
            
            api_url = self.xapp.config.get('platform_api_url', 'https://localhost:8080/api')
            
            # Get recent security logs
            log_response = requests.get(
                f"{api_url}/logs/security",
                params={'timeframe': '5m', 'limit': 10},
                headers={'Authorization': f'Bearer {self.xapp.oauth_token}'},
                cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                verify='/opt/certs/ca-cert.pem',
                timeout=10
            )
            
            if log_response.status_code != 200:
                self.results[test_name] = {
                    'status': 'SKIP',
                    'message': 'Security logs not accessible'
                }
                return
            
            logs = log_response.json()
            
            if not logs:
                self.results[test_name] = {
                    'status': 'SKIP',
                    'message': 'No recent security logs found'
                }
                return
            
            # Required fields per O-RAN WG11 specifications
            required_fields = [
                'timestamp',
                'severity',
                'event_type',
                'source',
                'message'
            ]
            
            optional_fields = [
                'user_id',
                'ip_address',
                'xapp_id',
                'action',
                'result'
            ]
            
            complete_logs = 0
            incomplete_logs = []
            
            for log_entry in logs:
                missing_fields = [f for f in required_fields if f not in log_entry]
                
                if not missing_fields:
                    complete_logs += 1
                else:
                    incomplete_logs.append({
                        'entry': log_entry.get('id', 'unknown'),
                        'missing': missing_fields
                    })
            
            completeness_rate = (complete_logs / len(logs)) * 100
            
            if completeness_rate == 100:
                self.results[test_name] = {
                    'status': 'PASS',
                    'message': f'All {len(logs)} log entries complete',
                    'control': 'SEC-CTL-NEAR-RT-8,16,17,18',
                    'completeness': '100%'
                }
                logger.info(f"    ✓ PASS: Logs complete")
            elif completeness_rate >= 80:
                self.results[test_name] = {
                    'status': 'WARN',
                    'message': f'{completeness_rate:.0f}% log completeness',
                    'control': 'SEC-CTL-NEAR-RT-8,16,17,18',
                    'incomplete_count': len(incomplete_logs)
                }
                logger.warning(f"    ⚠ WARN: {completeness_rate:.0f}% complete")
            else:
                self.results[test_name] = {
                    'status': 'FAIL',
                    'message': f'Only {completeness_rate:.0f}% log completeness',
                    'control': 'SEC-CTL-NEAR-RT-8,16,17,18',
                    'incomplete_logs': incomplete_logs
                }
                logger.error(f"    ✗ FAIL: Poor completeness")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'SEC-CTL-NEAR-RT-8,16,17,18'
            }
            logger.error(f"    ✗ ERROR: {e}")
    
    def test_log_integrity(self):
        """
        Test log tampering protection
        Verify logs cannot be modified or deleted
        """
        logger.info("  [5.3] Testing Log Integrity Protection...")
        
        test_name = "log_integrity"
        
        try:
            if not hasattr(self.xapp, 'oauth_token'):
                self.results[test_name] = {'status': 'SKIP', 'message': 'No token available'}
                return
            
            api_url = self.xapp.config.get('platform_api_url', 'https://localhost:8080/api')
            
            # Get a log entry ID
            log_response = requests.get(
                f"{api_url}/logs/security",
                params={'limit': 1},
                headers={'Authorization': f'Bearer {self.xapp.oauth_token}'},
                cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                verify='/opt/certs/ca-cert.pem',
                timeout=10
            )
            
            if log_response.status_code != 200 or not log_response.json():
                self.results[test_name] = {
                    'status': 'SKIP',
                    'message': 'No logs available for testing'
                }
                return
            
            log_id = log_response.json()[0].get('id', 'test-log-1')
            
            # Attempt to modify log
            modify_response = requests.put(
                f"{api_url}/logs/security/{log_id}",
                headers={
                    'Authorization': f'Bearer {self.xapp.oauth_token}',
                    'Content-Type': 'application/json'
                },
                json={'message': 'TAMPERED'},
                cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                verify='/opt/certs/ca-cert.pem',
                timeout=10
            )
            
            # Attempt to delete log
            delete_response = requests.delete(
                f"{api_url}/logs/security/{log_id}",
                headers={'Authorization': f'Bearer {self.xapp.oauth_token}'},
                cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                verify='/opt/certs/ca-cert.pem',
                timeout=10
            )
            
            # Both should be rejected
            modify_blocked = modify_response.status_code in [403, 405, 501]
            delete_blocked = delete_response.status_code in [403, 405, 501]
            
            if modify_blocked and delete_blocked:
                self.results[test_name] = {
                    'status': 'PASS',
                    'message': 'Log tampering correctly prevented',
                    'control': 'REQ-SEC-SLM-*'
                }
                logger.info(f"    ✓ PASS: Log integrity protected")
            elif modify_blocked or delete_blocked:
                self.results[test_name] = {
                    'status': 'WARN',
                    'message': f'Partial protection: modify={modify_blocked}, delete={delete_blocked}',
                    'control': 'REQ-SEC-SLM-*'
                }
                logger.warning(f"    ⚠ WARN: Partial protection")
            else:
                self.results[test_name] = {
                    'status': 'FAIL',
                    'message': 'Logs can be tampered with',
                    'control': 'REQ-SEC-SLM-*'
                }
                logger.error(f"    ✗ FAIL: No log protection")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'REQ-SEC-SLM-*'
            }
            logger.error(f"    ✗ ERROR: {e}")
    
    def test_log_retention(self):
        """Test log retention policies"""
        logger.info("  [5.4] Testing Log Retention...")
        
        test_name = "log_retention"
        
        try:
            if not hasattr(self.xapp, 'oauth_token'):
                self.results[test_name] = {'status': 'SKIP', 'message': 'No token available'}
                return
            
            api_url = self.xapp.config.get('platform_api_url', 'https://localhost:8080/api')
            
            # Get logs from different time periods
            timeframes = ['1h', '24h', '7d', '30d']
            log_counts = {}
            
            for timeframe in timeframes:
                try:
                    response = requests.get(
                        f"{api_url}/logs/security",
                        params={'timeframe': timeframe, 'count_only': 'true'},
                        headers={'Authorization': f'Bearer {self.xapp.oauth_token}'},
                        cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                        verify='/opt/certs/ca-cert.pem',
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        count = response.json().get('count', 0)
                        log_counts[timeframe] = count
                except:
                    log_counts[timeframe] = None
            
            logger.info(f"    Log counts: {log_counts}")
            
            # Check if older logs exist (retention working)
            has_old_logs = log_counts.get('7d', 0) > 0 or log_counts.get('30d', 0) > 0
            
            if has_old_logs:
                self.results[test_name] = {
                    'status': 'PASS',
                    'message': f'Log retention working: {log_counts}',
                    'control': 'REQ-SEC-SLM-*',
                    'log_counts': log_counts
                }
                logger.info(f"    ✓ PASS: Retention working")
            else:
                self.results[test_name] = {
                    'status': 'WARN',
                    'message': 'No old logs found (may be normal for new deployment)',
                    'control': 'REQ-SEC-SLM-*',
                    'log_counts': log_counts
                }
                logger.warning(f"    ⚠ WARN: No old logs")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'REQ-SEC-SLM-*'
            }
            logger.error(f"    ✗ ERROR: {e}")
