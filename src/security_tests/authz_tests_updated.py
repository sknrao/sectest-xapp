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