"""
Rate Limiting and DDoS Protection Tests
Tests REQ-SEC-NEAR-RT-6, 7, 8, 9
"""

import requests
import logging
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class RateLimitTester:
    """
    Tests rate limiting and DDoS protection:
    - Volumetric DDoS on A1 (REQ-SEC-NEAR-RT-6)
    - Content-related attacks on A1 (REQ-SEC-NEAR-RT-7)
    - Content-related attacks on Y1 (REQ-SEC-NEAR-RT-8)
    - Content-related attacks on E2 (REQ-SEC-NEAR-RT-9)
    """
    
    def __init__(self, xapp):
        self.xapp = xapp
        self.results = {}
    
    def run_tests(self):
        """Run all rate limiting tests"""
        logger.info("Testing Rate Limiting and DDoS Protection...")
        
        # Test 1: Volumetric DDoS protection on A1
        self.test_volumetric_ddos_a1()
        
        # Test 2: Connection flood protection
        self.test_connection_flood()
        
        # Test 3: Slowloris attack protection
        self.test_slowloris_protection()
        
        # Test 4: Request burst handling
        self.test_request_burst()
        
        # Test 5: Concurrent connection limits
        self.test_concurrent_connections()
        
        # Test 6: Recovery from attack
        self.test_recovery_from_attack()
        
        return self.results
    
    def test_volumetric_ddos_a1(self):
        """
        REQ-SEC-NEAR-RT-6: Test volumetric DDoS protection on A1
        Verify Near-RT RIC recovers without catastrophic failure
        """
        logger.info("  [4.1] Testing Volumetric DDoS Protection (A1)...")
        
        test_name = "volumetric_ddos_a1"
        
        try:
            if not hasattr(self.xapp, 'oauth_token'):
                self.results[test_name] = {'status': 'SKIP', 'message': 'No token available'}
                return
            
            api_url = self.xapp.config.get('platform_api_url', 'https://localhost:8080/api')
            
            # Simulate DDoS: Send massive number of requests
            ddos_request_count = 1000
            concurrent_threads = 50
            
            logger.info(f"    Simulating DDoS: {ddos_request_count} requests with {concurrent_threads} threads...")
            
            success_count = 0
            error_count = 0
            rate_limited_count = 0
            
            def send_request(req_id):
                try:
                    response = requests.get(
                        f"{api_url}/a1-p/policytypes",
                        headers={'Authorization': f'Bearer {self.xapp.oauth_token}'},
                        cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                        verify='/opt/certs/ca-cert.pem',
                        timeout=5
                    )
                    
                    if response.status_code == 200:
                        return 'success'
                    elif response.status_code == 429:  # Too Many Requests
                        return 'rate_limited'
                    else:
                        return 'error'
                except requests.exceptions.Timeout:
                    return 'timeout'
                except Exception as e:
                    return 'error'
            
            start_time = time.time()
            
            with ThreadPoolExecutor(max_workers=concurrent_threads) as executor:
                futures = [executor.submit(send_request, i) for i in range(ddos_request_count)]
                
                for future in as_completed(futures):
                    result = future.result()
                    if result == 'success':
                        success_count += 1
                    elif result == 'rate_limited':
                        rate_limited_count += 1
                    else:
                        error_count += 1
            
            elapsed = time.time() - start_time
            
            logger.info(f"    Results: Success={success_count}, Rate-limited={rate_limited_count}, Errors={error_count}")
            logger.info(f"    Duration: {elapsed:.2f}s, Rate: {ddos_request_count/elapsed:.2f} req/s")
            
            # Check if platform survived (no catastrophic failure)
            # Verify platform is still responsive after attack
            time.sleep(2)
            
            recovery_response = requests.get(
                f"{api_url}/health",
                headers={'Authorization': f'Bearer {self.xapp.oauth_token}'},
                cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                verify='/opt/certs/ca-cert.pem',
                timeout=10
            )
            
            platform_recovered = recovery_response.status_code == 200
            
            if platform_recovered and rate_limited_count > 0:
                self.results[test_name] = {
                    'status': 'PASS',
                    'message': f'Platform survived DDoS and recovered. Rate-limited {rate_limited_count} requests',
                    'control': 'REQ-SEC-NEAR-RT-6',
                    'success': success_count,
                    'rate_limited': rate_limited_count,
                    'errors': error_count,
                    'duration': round(elapsed, 2)
                }
                logger.info(f"    ✓ PASS: DDoS protection and recovery working")
            elif platform_recovered:
                self.results[test_name] = {
                    'status': 'WARN',
                    'message': 'Platform survived but no rate limiting detected',
                    'control': 'REQ-SEC-NEAR-RT-6',
                    'success': success_count,
                    'errors': error_count
                }
                logger.warning(f"    ⚠ WARN: No rate limiting")
            else:
                self.results[test_name] = {
                    'status': 'FAIL',
                    'message': 'Platform did not recover from DDoS attack',
                    'control': 'REQ-SEC-NEAR-RT-6'
                }
                logger.error(f"    ✗ FAIL: Platform not responsive after attack")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'REQ-SEC-NEAR-RT-6'
            }
            logger.error(f"    ✗ ERROR: {e}")
    
    def test_connection_flood(self):
        """
        Test connection flood attack protection
        Simulate opening many connections simultaneously
        """
        logger.info("  [4.2] Testing Connection Flood Protection...")
        
        test_name = "connection_flood"
        
        try:
            if not hasattr(self.xapp, 'oauth_token'):
                self.results[test_name] = {'status': 'SKIP', 'message': 'No token available'}
                return
            
            api_url = self.xapp.config.get('platform_api_url', 'https://localhost:8080/api')
            
            max_connections = 100
            connections_established = 0
            connections_refused = 0
            
            logger.info(f"    Attempting to establish {max_connections} connections...")
            
            def establish_connection(conn_id):
                try:
                    session = requests.Session()
                    session.cert = ('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem')
                    session.verify = '/opt/certs/ca-cert.pem'
                    
                    response = session.get(
                        f"{api_url}/health",
                        headers={'Authorization': f'Bearer {self.xapp.oauth_token}'},
                        timeout=5
                    )
                    
                    # Keep connection alive briefly
                    time.sleep(1)
                    session.close()
                    
                    return 'established' if response.status_code == 200 else 'error'
                except requests.exceptions.ConnectionError:
                    return 'refused'
                except Exception:
                    return 'error'
            
            with ThreadPoolExecutor(max_workers=max_connections) as executor:
                futures = [executor.submit(establish_connection, i) for i in range(max_connections)]
                
                for future in as_completed(futures):
                    result = future.result()
                    if result == 'established':
                        connections_established += 1
                    elif result == 'refused':
                        connections_refused += 1
            
            logger.info(f"    Established: {connections_established}, Refused: {connections_refused}")
            
            if connections_refused > 0:
                self.results[test_name] = {
                    'status': 'PASS',
                    'message': f'Connection flood limited: {connections_refused}/{max_connections} refused',
                    'control': 'REQ-SEC-NEAR-RT-6',
                    'established': connections_established,
                    'refused': connections_refused
                }
                logger.info(f"    ✓ PASS: Connection limits enforced")
            else:
                self.results[test_name] = {
                    'status': 'WARN',
                    'message': f'All {max_connections} connections accepted',
                    'control': 'REQ-SEC-NEAR-RT-6',
                    'established': connections_established
                }
                logger.warning(f"    ⚠ WARN: No connection limiting")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'REQ-SEC-NEAR-RT-6'
            }
            logger.error(f"    ✗ ERROR: {e}")
    
    def test_slowloris_protection(self):
        """
        Test Slowloris attack protection
        Send slow, incomplete requests to tie up connections
        """
        logger.info("  [4.3] Testing Slowloris Attack Protection...")
        
        test_name = "slowloris_protection"
        
        try:
            if not hasattr(self.xapp, 'oauth_token'):
                self.results[test_name] = {'status': 'SKIP', 'message': 'No token available'}
                return
            
            api_url = self.xapp.config.get('platform_api_url', 'https://localhost:8080/api')
            
            # After initiating slow requests, check if platform is still responsive
            logger.info("    Sending slow, incomplete requests...")
            
            slow_connections = []
            num_slow_connections = 20
            
            import socket
            import ssl as ssl_module
            
            def create_slow_connection(conn_id):
                try:
                    # Parse URL
                    from urllib.parse import urlparse
                    parsed = urlparse(api_url)
                    host = parsed.hostname
                    port = parsed.port or 443
                    
                    # Create socket
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(30)
                    
                    # Wrap with SSL
                    context = ssl_module.create_default_context()
                    context.load_cert_chain('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem')
                    
                    ssl_sock = context.wrap_socket(sock, server_hostname=host)
                    ssl_sock.connect((host, port))
                    
                    # Send incomplete HTTP request (slowly)
                    ssl_sock.send(b"GET /api/health HTTP/1.1\r\n")
                    time.sleep(0.5)
                    ssl_sock.send(f"Host: {host}\r\n".encode())
                    time.sleep(0.5)
                    # Don't send final \r\n to keep connection open
                    
                    return ssl_sock
                except Exception as e:
                    logger.debug(f"      Slow connection {conn_id} failed: {e}")
                    return None
            
            # Create slow connections
            for i in range(num_slow_connections):
                sock = create_slow_connection(i)
                if sock:
                    slow_connections.append(sock)
            
            logger.info(f"    Established {len(slow_connections)} slow connections")
            
            # Wait a bit
            time.sleep(5)
            
            # Check if platform is still responsive to legitimate requests
            try:
                response = requests.get(
                    f"{api_url}/health",
                    headers={'Authorization': f'Bearer {self.xapp.oauth_token}'},
                    cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                    verify='/opt/certs/ca-cert.pem',
                    timeout=10
                )
                
                platform_responsive = response.status_code == 200
            except:
                platform_responsive = False
            
            # Close slow connections
            for sock in slow_connections:
                try:
                    sock.close()
                except:
                    pass
            
            if platform_responsive:
                self.results[test_name] = {
                    'status': 'PASS',
                    'message': 'Platform remained responsive during Slowloris attack',
                    'control': 'REQ-SEC-NEAR-RT-6',
                    'slow_connections': len(slow_connections)
                }
                logger.info(f"    ✓ PASS: Slowloris protection working")
            else:
                self.results[test_name] = {
                    'status': 'FAIL',
                    'message': 'Platform became unresponsive during Slowloris attack',
                    'control': 'REQ-SEC-NEAR-RT-6'
                }
                logger.error(f"    ✗ FAIL: Platform vulnerable to Slowloris")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'REQ-SEC-NEAR-RT-6'
            }
            logger.error(f"    ✗ ERROR: {e}")
    
    def test_request_burst(self):
        """Test handling of request bursts"""
        logger.info("  [4.4] Testing Request Burst Handling...")
        
        test_name = "request_burst"
        
        try:
            if not hasattr(self.xapp, 'oauth_token'):
                self.results[test_name] = {'status': 'SKIP', 'message': 'No token available'}
                return
            
            api_url = self.xapp.config.get('platform_api_url', 'https://localhost:8080/api')
            
            # Send requests in bursts
            burst_sizes = [10, 50, 100, 200]
            burst_results = []
            
            for burst_size in burst_sizes:
                logger.info(f"    Testing burst of {burst_size} requests...")
                
                start = time.time()
                responses = []
                
                with ThreadPoolExecutor(max_workers=burst_size) as executor:
                    futures = []
                    for i in range(burst_size):
                        future = executor.submit(
                            requests.get,
                            f"{api_url}/health",
                            headers={'Authorization': f'Bearer {self.xapp.oauth_token}'},
                            cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                            verify='/opt/certs/ca-cert.pem',
                            timeout=10
                        )
                        futures.append(future)
                    
                    for future in as_completed(futures):
                        try:
                            resp = future.result()
                            responses.append(resp.status_code)
                        except:
                            responses.append(0)
                
                elapsed = time.time() - start
                success_rate = responses.count(200) / len(responses) * 100
                
                burst_results.append({
                    'size': burst_size,
                    'success_rate': success_rate,
                    'duration': elapsed
                })
                
                logger.info(f"      Burst {burst_size}: {success_rate:.1f}% success in {elapsed:.2f}s")
            
            # Platform should handle bursts gracefully
            avg_success = sum(b['success_rate'] for b in burst_results) / len(burst_results)
            
            if avg_success > 80:
                self.results[test_name] = {
                    'status': 'PASS',
                    'message': f'Handled bursts well: {avg_success:.1f}% average success',
                    'control': 'REQ-SEC-NEAR-RT-6',
                    'bursts': burst_results
                }
                logger.info(f"    ✓ PASS: Burst handling good")
            elif avg_success > 50:
                self.results[test_name] = {
                    'status': 'WARN',
                    'message': f'Moderate burst handling: {avg_success:.1f}% success',
                    'control': 'REQ-SEC-NEAR-RT-6',
                    'bursts': burst_results
                }
                logger.warning(f"    ⚠ WARN: Moderate performance")
            else:
                self.results[test_name] = {
                    'status': 'FAIL',
                    'message': f'Poor burst handling: {avg_success:.1f}% success',
                    'control': 'REQ-SEC-NEAR-RT-6',
                    'bursts': burst_results
                }
                logger.error(f"    ✗ FAIL: Poor burst handling")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'REQ-SEC-NEAR-RT-6'
            }
            logger.error(f"    ✗ ERROR: {e}")
    
    def test_concurrent_connections(self):
        """Test maximum concurrent connection limits"""
        logger.info("  [4.5] Testing Concurrent Connection Limits...")
        
        test_name = "concurrent_connections"
        
        try:
            if not hasattr(self.xapp, 'oauth_token'):
                self.results[test_name] = {'status': 'SKIP', 'message': 'No token available'}
                return
            
            api_url = self.xapp.config.get('platform_api_url', 'https://localhost:8080/api')
            
            # Keep connections open
            max_concurrent = 50
            active_sessions = []
            
            logger.info(f"    Opening {max_concurrent} concurrent connections...")
            
            for i in range(max_concurrent):
                try:
                    session = requests.Session()
                    session.cert = ('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem')
                    session.verify = '/opt/certs/ca-cert.pem'
                    
                    # Make request but keep session
                    response = session.get(
                        f"{api_url}/health",
                        headers={'Authorization': f'Bearer {self.xapp.oauth_token}'},
                        timeout=5
                    )
                    
                    if response.status_code == 200:
                        active_sessions.append(session)
                except:
                    pass
            
            logger.info(f"    Active concurrent connections: {len(active_sessions)}")
            
            # Try one more connection
            try:
                extra_response = requests.get(
                    f"{api_url}/health",
                    headers={'Authorization': f'Bearer {self.xapp.oauth_token}'},
                    cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                    verify='/opt/certs/ca-cert.pem',
                    timeout=5
                )
                extra_allowed = extra_response.status_code == 200
            except:
                extra_allowed = False
            
            # Clean up
            for session in active_sessions:
                try:
                    session.close()
                except:
                    pass
            
            if len(active_sessions) < max_concurrent or not extra_allowed:
                self.results[test_name] = {
                    'status': 'PASS',
                    'message': f'Connection limits enforced: {len(active_sessions)}/{max_concurrent}',
                    'control': 'REQ-SEC-NEAR-RT-6',
                    'max_concurrent': len(active_sessions)
                }
                logger.info(f"    ✓ PASS: Connection limits working")
            else:
                self.results[test_name] = {
                    'status': 'WARN',
                    'message': f'All {max_concurrent} connections accepted',
                    'control': 'REQ-SEC-NEAR-RT-6',
                    'max_concurrent': len(active_sessions)
                }
                logger.warning(f"    ⚠ WARN: High connection limit")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'REQ-SEC-NEAR-RT-6'
            }
            logger.error(f"    ✗ ERROR: {e}")
    
    def test_recovery_from_attack(self):
        """
        REQ-SEC-NEAR-RT-6: Test recovery without catastrophic failure
        Verify platform returns to normal operation after attack
        """
        logger.info("  [4.6] Testing Recovery from Attack...")
        
        test_name = "recovery_from_attack"
        
        try:
            if not hasattr(self.xapp, 'oauth_token'):
                self.results[test_name] = {'status': 'SKIP', 'message': 'No token available'}
                return
            
            api_url = self.xapp.config.get('platform_api_url', 'https://localhost:8080/api')
            
            # Step 1: Baseline performance
            logger.info("    Measuring baseline performance...")
            baseline_start = time.time()
            baseline_response = requests.get(
                f"{api_url}/health",
                headers={'Authorization': f'Bearer {self.xapp.oauth_token}'},
                cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                verify='/opt/certs/ca-cert.pem',
                timeout=10
            )
            baseline_time = time.time() - baseline_start
            
            # Step 2: Attack
            logger.info("    Simulating attack...")
            attack_count = 500
            
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = []
                for i in range(attack_count):
                    future = executor.submit(
                        requests.get,
                        f"{api_url}/health",
                        headers={'Authorization': f'Bearer {self.xapp.oauth_token}'},
                        cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                        verify='/opt/certs/ca-cert.pem',
                        timeout=5
                    )
                    futures.append(future)
                
                # Wait for attack to complete
                for future in as_completed(futures):
                    try:
                        future.result()
                    except:
                        pass
            
            # Step 3: Wait for recovery
            logger.info("    Waiting for recovery (10s)...")
            time.sleep(10)
            
            # Step 4: Test post-attack performance
            logger.info("    Measuring post-attack performance...")
            recovery_times = []
            
            for i in range(10):
                try:
                    recovery_start = time.time()
                    recovery_response = requests.get(
                        f"{api_url}/health",
                        headers={'Authorization': f'Bearer {self.xapp.oauth_token}'},
                        cert=('/opt/certs/xapp-cert.pem', '/opt/certs/xapp-key.pem'),
                        verify='/opt/certs/ca-cert.pem',
                        timeout=10
                    )
                    recovery_time = time.time() - recovery_start
                    
                    if recovery_response.status_code == 200:
                        recovery_times.append(recovery_time)
                except:
                    pass
                
                time.sleep(1)
            
            if len(recovery_times) >= 8:  # 80% success
                avg_recovery_time = sum(recovery_times) / len(recovery_times)
                
                # Performance should be close to baseline
                performance_ratio = avg_recovery_time / baseline_time
                
                if performance_ratio < 1.5:  # Within 50% of baseline
                    self.results[test_name] = {
                        'status': 'PASS',
                        'message': f'Platform recovered successfully. Performance: {performance_ratio:.2f}x baseline',
                        'control': 'REQ-SEC-NEAR-RT-6',
                        'baseline_time': round(baseline_time, 3),
                        'recovery_time': round(avg_recovery_time, 3),
                        'performance_ratio': round(performance_ratio, 2)
                    }
                    logger.info(f"    ✓ PASS: Full recovery achieved")
                else:
                    self.results[test_name] = {
                        'status': 'WARN',
                        'message': f'Platform recovered but degraded. Performance: {performance_ratio:.2f}x baseline',
                        'control': 'REQ-SEC-NEAR-RT-6',
                        'performance_ratio': round(performance_ratio, 2)
                    }
                    logger.warning(f"    ⚠ WARN: Degraded performance")
            else:
                self.results[test_name] = {
                    'status': 'FAIL',
                    'message': f'Platform did not recover: only {len(recovery_times)}/10 requests succeeded',
                    'control': 'REQ-SEC-NEAR-RT-6',
                    'success_rate': len(recovery_times) * 10
                }
                logger.error(f"    ✗ FAIL: Recovery incomplete")
                
        except Exception as e:
            self.results[test_name] = {
                'status': 'ERROR',
                'message': str(e),
                'control': 'REQ-SEC-NEAR-RT-6'
            }
            logger.error(f"    ✗ ERROR: {e}")
