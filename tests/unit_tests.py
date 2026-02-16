"""
Unit tests for security testing xApp
Run with: pytest tests/unit_tests.py -v
"""

import pytest
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from utils.cert_utils import validate_xapp_cert
from utils.report_generator import SecurityReportGenerator
from utils.metrics import SecurityMetrics


def test_security_metrics():
    """Test metrics collection"""
    metrics = SecurityMetrics()
    
    # Record some test results
    metrics.record_test('authentication', 'test1', 'PASS')
    metrics.record_test('authentication', 'test2', 'FAIL', 'Authentication failure details')
    metrics.record_test('authorization', 'test3', 'PASS')
    metrics.record_test('data_validation', 'test4', 'WARN', 'Warning details')
    
    result = metrics.get_metrics()
    
    assert result['tests_run'] == 4
    assert result['tests_passed'] == 2
    assert result['tests_failed'] == 1
    assert result['tests_warned'] == 1
    assert len(result['vulnerabilities_found']) == 1
    assert result['pass_rate'] == 50.0


def test_metrics_by_category():
    """Test category-wise metrics"""
    metrics = SecurityMetrics()
    
    metrics.record_test('authentication', 'test1', 'PASS')
    metrics.record_test('authentication', 'test2', 'FAIL')
    metrics.record_test('authorization', 'test3', 'PASS')
    
    result = metrics.get_metrics()
    
    assert 'authentication' in result['by_category']
    assert result['by_category']['authentication']['total'] == 2
    assert result['by_category']['authentication']['passed'] == 1
    assert result['by_category']['authentication']['failed'] == 1
    
    assert 'authorization' in result['by_category']
    assert result['by_category']['authorization']['total'] == 1
    assert result['by_category']['authorization']['passed'] == 1


def test_report_generator():
    """Test report generation"""
    generator = SecurityReportGenerator()
    
    test_results = {
        'authentication': {
            'test1': {'status': 'PASS', 'control': 'SEC-CTL-NEAR-RT-1', 'message': 'Test passed'},
            'test2': {'status': 'FAIL', 'control': 'SEC-CTL-NEAR-RT-2', 'message': 'mTLS failed'}
        },
        'authorization': {
            'test3': {'status': 'PASS', 'control': 'SEC-CTL-NEAR-RT-3', 'message': 'OAuth working'},
            'test4': {'status': 'WARN', 'control': 'SEC-CTL-NEAR-RT-4', 'message': 'Scope warning'}
        }
    }
    
    report = generator.generate(test_results)
    
    # Check report structure
    assert 'metadata' in report
    assert 'summary' in report
    assert 'detailed_results' in report
    assert 'compliance_analysis' in report
    assert 'recommendations' in report
    assert 'control_coverage' in report
    
    # Check summary
    assert report['summary']['total_tests'] == 4
    assert report['summary']['passed'] == 2
    assert report['summary']['failed'] == 1
    assert report['summary']['warnings'] == 1
    assert report['summary']['compliance_rate'] == 50.0
    
    # Check recommendations
    assert len(report['recommendations']) == 2  # 1 FAIL + 1 WARN
    assert report['recommendations'][0]['priority'] == 'HIGH'  # FAIL comes first


def test_report_compliance_analysis():
    """Test compliance analysis"""
    generator = SecurityReportGenerator()
    
    test_results = {
        'authentication': {
            'test1': {'status': 'PASS', 'control': 'SEC-CTL-NEAR-RT-1'},
            'test2': {'status': 'PASS', 'control': 'SEC-CTL-NEAR-RT-2'},
            'test3': {'status': 'PASS', 'control': 'SEC-CTL-NEAR-RT-3'}
        },
        'authorization': {
            'test4': {'status': 'PASS', 'control': 'SEC-CTL-NEAR-RT-4'},
            'test5': {'status': 'FAIL', 'control': 'SEC-CTL-NEAR-RT-5'}
        }
    }
    
    report = generator.generate(test_results)
    compliance = report['compliance_analysis']
    
    assert 'authentication' in compliance
    assert compliance['authentication']['compliance_rate'] == 100.0
    assert compliance['authentication']['status'] == 'FULLY_COMPLIANT'
    
    assert 'authorization' in compliance
    assert compliance['authorization']['compliance_rate'] == 50.0
    assert compliance['authorization']['status'] in ['PARTIALLY_COMPLIANT', 'NON_COMPLIANT']


def test_report_control_coverage():
    """Test security control coverage analysis"""
    generator = SecurityReportGenerator()
    
    test_results = {
        'authentication': {
            'test1': {'status': 'PASS', 'control': 'SEC-CTL-NEAR-RT-1'},
            'test2': {'status': 'PASS', 'control': 'SEC-CTL-NEAR-RT-2'},
            'test3': {'status': 'FAIL', 'control': 'SEC-CTL-NEAR-RT-3'}
        }
    }
    
    report = generator.generate(test_results)
    coverage = report['control_coverage']
    
    assert coverage['total_controls_tested'] == 3
    assert coverage['controls_passed'] == 2
    assert coverage['controls_failed'] == 1
    assert 'SEC-CTL-NEAR-RT-1' in coverage['controls_passed_list']
    assert 'SEC-CTL-NEAR-RT-3' in coverage['controls_failed_list']


def test_report_html_generation():
    """Test HTML report generation"""
    generator = SecurityReportGenerator()
    
    test_results = {
        'authentication': {
            'test1': {'status': 'PASS', 'control': 'SEC-CTL-NEAR-RT-1', 'message': 'OK'}
        }
    }
    
    report = generator.generate(test_results)
    html = generator.generate_html(report)
    
    assert '<html>' in html
    assert 'O-RAN Near-RT RIC Security Compliance Report' in html
    assert 'SEC-CTL-NEAR-RT-1' in html
    assert str(report['summary']['compliance_rate']) in html


def test_report_recommendations_prioritization():
    """Test that recommendations are prioritized correctly"""
    generator = SecurityReportGenerator()
    
    test_results = {
        'authentication': {
            'test1': {'status': 'WARN', 'control': 'SEC-CTL-1', 'message': 'Warning'},
            'test2': {'status': 'FAIL', 'control': 'SEC-CTL-2', 'message': 'Failure'},
            'test3': {'status': 'ERROR', 'control': 'SEC-CTL-3', 'message': 'Error'}
        }
    }
    
    report = generator.generate(test_results)
    recommendations = report['recommendations']
    
    # Check HIGH priority items come first (FAIL and ERROR)
    high_priority = [r for r in recommendations if r['priority'] == 'HIGH']
    medium_priority = [r for r in recommendations if r['priority'] == 'MEDIUM']
    
    assert len(high_priority) == 2  # FAIL + ERROR
    assert len(medium_priority) == 1  # WARN
    
    # Verify ordering
    for i in range(len(recommendations) - 1):
        current_priority = recommendations[i]['priority']
        next_priority = recommendations[i + 1]['priority']
        priority_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        assert priority_order[current_priority] <= priority_order[next_priority]


if __name__ == '__main__':
    pytest.main([__file__, '-v'])