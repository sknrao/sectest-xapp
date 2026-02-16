"""
xDevSM State Machine for Security Testing
Orchestrates test execution with state management
"""

from enum import Enum
import logging

logger = logging.getLogger(__name__)


class TestState(Enum):
    """Test execution states"""
    IDLE = "idle"
    INITIALIZING = "initializing"
    AUTHENTICATING = "authenticating"
    TESTING_AUTH = "testing_auth"
    TESTING_AUTHZ = "testing_authz"
    TESTING_DATA = "testing_data"
    TESTING_RATE = "testing_rate"
    TESTING_LOGGING = "testing_logging"
    GENERATING_REPORT = "generating_report"
    COMPLETED = "completed"
    FAILED = "failed"


class SecurityTestStateMachine:
    """
    State machine for orchestrating security tests
    Follows xDevSM framework pattern
    """
    
    def __init__(self, xapp):
        self.xapp = xapp
        self.state = TestState.IDLE
        self.results = {}
        
    def transition(self, new_state):
        """Transition to new state"""
        logger.info(f"State transition: {self.state.value} -> {new_state.value}")
        self.state = new_state
    
    def run(self):
        """Execute state machine"""
        logger.info("Starting security test state machine...")
        
        self.transition(TestState.INITIALIZING)
        if not self._initialize():
            self.transition(TestState.FAILED)
            return False
        
        self.transition(TestState.AUTHENTICATING)
        if not self._authenticate():
            self.transition(TestState.FAILED)
            return False
        
        # Run tests in sequence
        test_sequence = [
            (TestState.TESTING_AUTH, self._test_authentication),
            (TestState.TESTING_AUTHZ, self._test_authorization),
            (TestState.TESTING_DATA, self._test_data_validation),
            (TestState.TESTING_RATE, self._test_rate_limiting),
            (TestState.TESTING_LOGGING, self._test_logging)
        ]
        
        for state, test_func in test_sequence:
            self.transition(state)
            try:
                result = test_func()
                self.results[state.value] = result
            except Exception as e:
                logger.error(f"Test failed in state {state.value}: {e}")
                self.results[state.value] = {'status': 'ERROR', 'message': str(e)}
        
        self.transition(TestState.GENERATING_REPORT)
        self._generate_report()
        
        self.transition(TestState.COMPLETED)
        logger.info("Security test state machine completed")
        return True
    
    def _initialize(self):
        """Initialize resources"""
        logger.info("Initializing test environment...")
        return True
    
    def _authenticate(self):
        """Authenticate xApp"""
        logger.info("Authenticating xApp...")
        # Would acquire OAuth token here
        return True
    
    def _test_authentication(self):
        """Run authentication tests"""
        logger.info("Running authentication tests...")
        from security_tests.auth_tests import AuthenticationTester
        tester = AuthenticationTester(self.xapp)
        return tester.run_tests()
    
    def _test_authorization(self):
        """Run authorization tests"""
        logger.info("Running authorization tests...")
        from security_tests.authz_tests import AuthorizationTester
        tester = AuthorizationTester(self.xapp)
        return tester.run_tests()
    
    def _test_data_validation(self):
        """Run data validation tests"""
        logger.info("Running data validation tests...")
        from security_tests.data_validation_tests import DataValidationTester
        tester = DataValidationTester(self.xapp)
        return tester.run_tests()
    
    def _test_rate_limiting(self):
        """Run rate limiting tests"""
        logger.info("Running rate limiting tests...")
        from security_tests.rate_limit_tests import RateLimitTester
        tester = RateLimitTester(self.xapp)
        return tester.run_tests()
    
    def _test_logging(self):
        """Run logging tests"""
        logger.info("Running logging tests...")
        from security_tests.logging_tests import LoggingTester
        tester = LoggingTester(self.xapp)
        return tester.run_tests()
    
    def _generate_report(self):
        """Generate final report"""
        logger.info("Generating compliance report...")
        from utils.report_generator import SecurityReportGenerator
        generator = SecurityReportGenerator()
        report = generator.generate(self.results)
        
        # Save report
        import json
        with open('/tmp/security_compliance_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info("Report saved to /tmp/security_compliance_report.json")