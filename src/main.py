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
    
    def _rmr_handler(self, summary, sbuf):
        """
        RMR message handler
        Processes incoming messages from Near-RT RIC
        """
        logger.debug(f"Received RMR message: {summary}")
        
        # Extract message type and payload
        mtype = summary[rmr.RMR_MS_MSG_TYPE]
        payload = summary[rmr.RMR_MS_PAYLOAD]
        
        # Route to appropriate test handler based on message type
        if mtype == 60000:  # Health check
            self._handle_health_check(summary, sbuf)
        elif mtype == 60001:  # Start security tests
            self._handle_start_tests(summary, sbuf)
        elif mtype == 60002:  # Get test results
            self._handle_get_results(summary, sbuf)
        else:
            logger.warning(f"Unknown message type: {mtype}")
        
        # Free the RMR buffer
        self.xapp.rmr_free(sbuf)
    
    def _handle_health_check(self, summary, sbuf):
        """Respond to health check"""
        response = {"status": "healthy", "timestamp": time.time()}
        self.xapp.rmr_rts(sbuf, new_payload=json.dumps(response).encode())
    
    def _handle_start_tests(self, summary, sbuf):
        """Start security test suite"""
        logger.info("Starting security test suite")
        Thread(target=self.run_all_tests, daemon=True).start()
        
        response = {"status": "tests_started", "timestamp": time.time()}
        self.xapp.rmr_rts(sbuf, new_payload=json.dumps(response).encode())
    
    def _handle_get_results(self, summary, sbuf):
        """Return test results"""
        response = {
            "status": "completed",
            "results": self.test_results,
            "timestamp": time.time()
        }
        self.xapp.rmr_rts(sbuf, new_payload=json.dumps(response).encode())
    
    def run_all_tests(self):
        """Execute all security test modules"""
        logger.info("="*60)
        logger.info("O-RAN Near-RT RIC Security Compliance Test Suite")
        logger.info("Testing against O-RAN.WG11.TS.SRCS.0-R004-v13.00 Ch 5.1.3")
        logger.info("="*60)
        
        # Test 1: Authentication (SEC-CTL-NEAR-RT-1, 2, 2A, 9)
        logger.info("\n[1/5] Running Authentication Tests...")
        self.test_results['authentication'] = self.auth_tester.run_tests()
        
        # Test 2: Authorization (SEC-CTL-NEAR-RT-3, 3A-3C, 4, 5, 10)
        logger.info("\n[2/5] Running Authorization Tests...")
        self.test_results['authorization'] = self.authz_tester.run_tests()
        
        # Test 3: Data Validation (SEC-CTL-NEAR-RT-8, 15, 17, 18)
        logger.info("\n[3/5] Running Data Validation Tests...")
        self.test_results['data_validation'] = self.data_validator.run_tests()
        
        # Test 4: Rate Limiting (REQ-SEC-NEAR-RT-6, 7, 8, 9)
        logger.info("\n[4/5] Running Rate Limiting Tests...")
        self.test_results['rate_limiting'] = self.rate_limiter.run_tests()
        
        # Test 5: Security Logging (SEC-CTL-NEAR-RT-8, 16, 17, 18)
        logger.info("\n[5/5] Running Security Logging Tests...")
        self.test_results['logging'] = self.log_tester.run_tests()
        
        # Generate comprehensive report
        logger.info("\n" + "="*60)
        logger.info("Generating Security Compliance Report...")
        report = self.report_gen.generate(self.test_results)
        
        # Save report
        report_file = f"/tmp/security_report_{int(time.time())}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report saved to: {report_file}")
        logger.info("="*60)
    
    def start(self):
        """Start the xApp"""
        logger.info("Starting Security Testing xApp...")
        self.xapp.run()


def main():
    """Main entry point"""
    xapp = SecurityTestXapp()
    xapp.start()


if __name__ == "__main__":
    main()