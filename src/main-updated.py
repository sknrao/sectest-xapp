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