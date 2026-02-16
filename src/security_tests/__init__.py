"""
Security test modules for O-RAN Near-RT RIC compliance testing

Tests organized by security control categories:
- Authentication (SEC-CTL-NEAR-RT-1, 2, 2A, 9, 12-14)
- Authorization (SEC-CTL-NEAR-RT-3, 3A-3C, 4, 5, 10)
- Data Validation (SEC-CTL-NEAR-RT-8, 15, 17, 18)
- Rate Limiting (REQ-SEC-NEAR-RT-6, 7, 8, 9)
- Security Logging (SEC-CTL-NEAR-RT-8, 16, 17, 18)
"""

from .auth_tests import AuthenticationTester
from .authz_tests import AuthorizationTester
from .data_validation_tests import DataValidationTester
from .rate_limit_tests import RateLimitTester
from .logging_tests import LoggingTester

__all__ = [
    'AuthenticationTester',
    'AuthorizationTester',
    'DataValidationTester',
    'RateLimitTester',
    'LoggingTester'
]

# Test category metadata
TEST_CATEGORIES = {
    'authentication': {
        'class': AuthenticationTester,
        'description': 'mTLS, certificates, OAuth authentication',
        'controls': ['SEC-CTL-NEAR-RT-1', 'SEC-CTL-NEAR-RT-2', 'SEC-CTL-NEAR-RT-2A',
                     'SEC-CTL-NEAR-RT-9', 'SEC-CTL-NEAR-RT-12', 'SEC-CTL-NEAR-RT-13',
                     'SEC-CTL-NEAR-RT-14']
    },
    'authorization': {
        'class': AuthorizationTester,
        'description': 'OAuth 2.0, scope enforcement, API access control',
        'controls': ['SEC-CTL-NEAR-RT-3', 'SEC-CTL-NEAR-RT-3A', 'SEC-CTL-NEAR-RT-3B',
                     'SEC-CTL-NEAR-RT-3C', 'SEC-CTL-NEAR-RT-4', 'SEC-CTL-NEAR-RT-5',
                     'SEC-CTL-NEAR-RT-10']
    },
    'data_validation': {
        'class': DataValidationTester,
        'description': 'Input sanitization, injection protection, schema validation',
        'controls': ['SEC-CTL-NEAR-RT-8', 'SEC-CTL-NEAR-RT-15', 'SEC-CTL-NEAR-RT-17',
                     'SEC-CTL-NEAR-RT-18', 'REQ-SEC-NEAR-RT-7', 'REQ-SEC-NEAR-RT-8',
                     'REQ-SEC-NEAR-RT-9']
    },
    'rate_limiting': {
        'class': RateLimitTester,
        'description': 'DDoS protection, burst handling, recovery testing',
        'controls': ['REQ-SEC-NEAR-RT-6', 'REQ-SEC-NEAR-RT-7', 'REQ-SEC-NEAR-RT-8',
                     'REQ-SEC-NEAR-RT-9']
    },
    'logging': {
        'class': LoggingTester,
        'description': 'Security event logging, log integrity, retention',
        'controls': ['SEC-CTL-NEAR-RT-8', 'SEC-CTL-NEAR-RT-16', 'SEC-CTL-NEAR-RT-17',
                     'SEC-CTL-NEAR-RT-18']
    }
}


def get_test_category(category_name):
    """Get test category information"""
    return TEST_CATEGORIES.get(category_name)


def get_all_categories():
    """Get all test categories"""
    return list(TEST_CATEGORIES.keys())


def get_tester_class(category_name):
    """Get tester class for a category"""
    category = TEST_CATEGORIES.get(category_name)
    return category['class'] if category else None