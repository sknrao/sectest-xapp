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