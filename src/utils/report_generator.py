"""
Security test report generator

Generates compliance reports in multiple formats (JSON, HTML, PDF)
following O-RAN WG11 specifications
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


class SecurityReportGenerator:
    """Generate comprehensive security compliance reports"""
    
    def __init__(self):
        self.report_version = "1.0"
        
    def generate(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive security report
        
        Args:
            test_results: Dict with test results from all categories
            
        Returns:
            Complete report dict
        """
        report = {
            'metadata': self._generate_metadata(),
            'summary': self._generate_summary(test_results),
            'detailed_results': test_results,
            'compliance_analysis': self._analyze_compliance(test_results),
            'recommendations': self._generate_recommendations(test_results),
            'control_coverage': self._analyze_control_coverage(test_results)
        }
        
        logger.info(f"Generated security report: {report['summary']['compliance_rate']}% compliant")
        return report
    
    def _generate_metadata(self) -> Dict[str, str]:
        """Generate report metadata"""
        return {
            'title': 'O-RAN Near-RT RIC Security Compliance Report',
            'specification': 'O-RAN.WG11.TS.SRCS.0-R004-v13.00',
            'chapter': '5.1.3 - Near-RT RIC and xApps',
            'generated_at': datetime.now().isoformat(),
            'report_version': self.report_version,
            'generator': 'security-test-xapp'
        }
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate test summary statistics"""
        total = 0
        passed = 0
        failed = 0
        errors = 0
        warnings = 0
        skipped = 0
        
        for category in results.values():
            if not isinstance(category, dict):
                continue
                
            for test_result in category.values():
                if not isinstance(test_result, dict):
                    continue
                    
                total += 1
                status = test_result.get('status', 'UNKNOWN')
                
                if status == 'PASS':
                    passed += 1
                elif status == 'FAIL':
                    failed += 1
                elif status == 'ERROR':
                    errors += 1
                elif status == 'WARN':
                    warnings += 1
                elif status == 'SKIP':
                    skipped += 1
        
        compliance_rate = round((passed / total * 100), 2) if total > 0 else 0
        
        return {
            'total_tests': total,
            'passed': passed,
            'failed': failed,
            'errors': errors,
            'warnings': warnings,
            'skipped': skipped,
            'compliance_rate': compliance_rate,
            'compliant': compliance_rate >= 80  # 80% threshold for compliance
        }
    
    def _analyze_compliance(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze compliance by category"""
        compliance_by_category = {}
        
        for category, tests in results.items():
            if not isinstance(tests, dict):
                continue
                
            total = len(tests)
            passed = sum(1 for t in tests.values() if isinstance(t, dict) and t.get('status') == 'PASS')
            
            compliance_by_category[category] = {
                'total': total,
                'passed': passed,
                'compliance_rate': round((passed / total * 100), 2) if total > 0 else 0,
                'status': self._get_compliance_status(passed, total)
            }
        
        return compliance_by_category
    
    def _get_compliance_status(self, passed: int, total: int) -> str:
        """Determine compliance status based on pass rate"""
        if total == 0:
            return 'UNKNOWN'
        
        rate = (passed / total) * 100
        
        if rate == 100:
            return 'FULLY_COMPLIANT'
        elif rate >= 90:
            return 'HIGHLY_COMPLIANT'
        elif rate >= 80:
            return 'COMPLIANT'
        elif rate >= 70:
            return 'PARTIALLY_COMPLIANT'
        else:
            return 'NON_COMPLIANT'
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate recommendations based on failures"""
        recommendations = []
        
        for category, tests in results.items():
            if not isinstance(tests, dict):
                continue
                
            for test_name, result in tests.items():
                if not isinstance(result, dict):
                    continue
                    
                status = result.get('status')
                
                if status == 'FAIL':
                    recommendations.append({
                        'category': category,
                        'test': test_name,
                        'control': result.get('control', 'Unknown'),
                        'issue': result.get('message', 'No details'),
                        'priority': 'HIGH',
                        'recommendation': self._get_recommendation(category, test_name)
                    })
                elif status == 'WARN':
                    recommendations.append({
                        'category': category,
                        'test': test_name,
                        'control': result.get('control', 'Unknown'),
                        'issue': result.get('message', 'No details'),
                        'priority': 'MEDIUM',
                        'recommendation': self._get_recommendation(category, test_name)
                    })
                elif status == 'ERROR':
                    recommendations.append({
                        'category': category,
                        'test': test_name,
                        'control': result.get('control', 'Unknown'),
                        'issue': result.get('message', 'No details'),
                        'priority': 'HIGH',
                        'recommendation': 'Review test configuration and platform connectivity'
                    })
        
        # Sort by priority
        priority_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        recommendations.sort(key=lambda x: priority_order.get(x['priority'], 3))
        
        return recommendations
    
    def _get_recommendation(self, category: str, test_name: str) -> str:
        """Get specific recommendation for failed test"""
        recommendations_map = {
            'authentication': {
                'mtls_rest_api': 'Ensure mTLS is properly configured with valid certificates',
                'xapp_cert_identity': 'Generate xApp certificate with UUID v4 in subjectAltName',
                'invalid_cert_rejection': 'Configure platform to require client certificates',
                'cert_expiry': 'Renew xApp certificate before expiration',
                'cipher_strength': 'Disable weak cipher suites, enable only TLS 1.2+'
            },
            'authorization': {
                'oauth_token_flow': 'Configure OAuth 2.0 authorization server',
                'api_access_with_token': 'Verify token validation is enabled',
                'api_access_without_token': 'Ensure APIs require Bearer tokens',
                'expired_token_rejection': 'Implement token expiration validation',
                'scope_enforcement': 'Configure scope-based access control',
                'api_discovery_restrictions': 'Implement policy-based API discovery'
            },
            'data_validation': {
                'a1_policy_schema_validation': 'Implement JSON schema validation for A1 policies',
                'a1_policy_value_validation': 'Add value range checks for policy parameters',
                'a1_policy_rate_validation': 'Implement rate limiting for policy updates',
                'sql_injection_protection': 'Use parameterized queries, sanitize inputs',
                'command_injection_protection': 'Validate and escape all command inputs',
                'buffer_overflow_protection': 'Implement input length restrictions',
                'e2_subscription_validation': 'Validate E2 subscription data formats'
            },
            'rate_limiting': {
                'volumetric_ddos_a1': 'Implement rate limiting and connection pooling',
                'connection_flood': 'Set maximum connection limits per client',
                'slowloris_protection': 'Configure connection timeouts',
                'request_burst': 'Implement token bucket rate limiting',
                'concurrent_connections': 'Set appropriate connection pool limits',
                'recovery_from_attack': 'Implement graceful degradation mechanisms'
            },
            'logging': {
                'security_event_generation': 'Ensure all security events are logged',
                'log_completeness': 'Include all required fields in log entries',
                'log_integrity': 'Implement write-once log storage',
                'log_retention': 'Configure appropriate log retention policies'
            }
        }
        
        if category in recommendations_map and test_name in recommendations_map[category]:
            return recommendations_map[category][test_name]
        else:
            return f'Review and fix {test_name} in {category} category'
    
    def _analyze_control_coverage(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze O-RAN security control coverage"""
        controls_tested = set()
        controls_passed = set()
        controls_failed = set()
        
        for category, tests in results.items():
            if not isinstance(tests, dict):
                continue
                
            for test_result in tests.values():
                if not isinstance(test_result, dict):
                    continue
                    
                control = test_result.get('control', '')
                status = test_result.get('status')
                
                if control:
                    # Handle multiple controls (comma-separated)
                    for ctrl in control.split(','):
                        ctrl = ctrl.strip()
                        controls_tested.add(ctrl)
                        
                        if status == 'PASS':
                            controls_passed.add(ctrl)
                        elif status == 'FAIL':
                            controls_failed.add(ctrl)
        
        return {
            'total_controls_tested': len(controls_tested),
            'controls_passed': len(controls_passed),
            'controls_failed': len(controls_failed),
            'control_coverage_rate': round((len(controls_passed) / len(controls_tested) * 100), 2) if controls_tested else 0,
            'controls_tested_list': sorted(list(controls_tested)),
            'controls_passed_list': sorted(list(controls_passed)),
            'controls_failed_list': sorted(list(controls_failed))
        }
    
    def save_json(self, report: Dict[str, Any], filepath: str):
        """Save report as JSON"""
        try:
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Report saved to {filepath}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
            raise
    
    def generate_html(self, report: Dict[str, Any]) -> str:
        """Generate HTML report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{report['metadata']['title']}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                h1 {{ color: #333; }}
                .summary {{ background: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .pass {{ color: green; }}
                .fail {{ color: red; }}
                .warn {{ color: orange; }}
                table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #4CAF50; color: white; }}
            </style>
        </head>
        <body>
            <h1>{report['metadata']['title']}</h1>
            <p><strong>Specification:</strong> {report['metadata']['specification']}</p>
            <p><strong>Chapter:</strong> {report['metadata']['chapter']}</p>
            <p><strong>Generated:</strong> {report['metadata']['generated_at']}</p>
            
            <div class="summary">
                <h2>Summary</h2>
                <p><strong>Compliance Rate:</strong> {report['summary']['compliance_rate']}%</p>
                <p><strong>Total Tests:</strong> {report['summary']['total_tests']}</p>
                <p class="pass"><strong>Passed:</strong> {report['summary']['passed']}</p>
                <p class="fail"><strong>Failed:</strong> {report['summary']['failed']}</p>
                <p class="warn"><strong>Warnings:</strong> {report['summary']['warnings']}</p>
            </div>
            
            <h2>Recommendations</h2>
            <table>
                <tr>
                    <th>Priority</th>
                    <th>Category</th>
                    <th>Control</th>
                    <th>Issue</th>
                    <th>Recommendation</th>
                </tr>
        """
        
        for rec in report['recommendations']:
            html += f"""
                <tr>
                    <td>{rec['priority']}</td>
                    <td>{rec['category']}</td>
                    <td>{rec['control']}</td>
                    <td>{rec['issue']}</td>
                    <td>{rec['recommendation']}</td>
                </tr>
            """
        
        html += """
            </table>
        </body>
        </html>
        """
        
        return html
    
    def save_html(self, report: Dict[str, Any], filepath: str):
        """Save report as HTML"""
        try:
            html = self.generate_html(report)
            with open(filepath, 'w') as f:
                f.write(html)
            logger.info(f"HTML report saved to {filepath}")
        except Exception as e:
            logger.error(f"Failed to save HTML report: {e}")
            raise
EOF
cat /home/claude/security-xapp-files/src/utils/report_generator.py
Output

"""
Security test report generator

Generates compliance reports in multiple formats (JSON, HTML, PDF)
following O-RAN WG11 specifications
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


class SecurityReportGenerator:
    """Generate comprehensive security compliance reports"""
    
    def __init__(self):
        self.report_version = "1.0"
        
    def generate(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive security report
        
        Args:
            test_results: Dict with test results from all categories
            
        Returns:
            Complete report dict
        """
        report = {
            'metadata': self._generate_metadata(),
            'summary': self._generate_summary(test_results),
            'detailed_results': test_results,
            'compliance_analysis': self._analyze_compliance(test_results),
            'recommendations': self._generate_recommendations(test_results),
            'control_coverage': self._analyze_control_coverage(test_results)
        }
        
        logger.info(f"Generated security report: {report['summary']['compliance_rate']}% compliant")
        return report
    
    def _generate_metadata(self) -> Dict[str, str]:
        """Generate report metadata"""
        return {
            'title': 'O-RAN Near-RT RIC Security Compliance Report',
            'specification': 'O-RAN.WG11.TS.SRCS.0-R004-v13.00',
            'chapter': '5.1.3 - Near-RT RIC and xApps',
            'generated_at': datetime.now().isoformat(),
            'report_version': self.report_version,
            'generator': 'security-test-xapp'
        }
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate test summary statistics"""
        total = 0
        passed = 0
        failed = 0
        errors = 0
        warnings = 0
        skipped = 0
        
        for category in results.values():
            if not isinstance(category, dict):
                continue
                
            for test_result in category.values():
                if not isinstance(test_result, dict):
                    continue
                    
                total += 1
                status = test_result.get('status', 'UNKNOWN')
                
                if status == 'PASS':
                    passed += 1
                elif status == 'FAIL':
                    failed += 1
                elif status == 'ERROR':
                    errors += 1
                elif status == 'WARN':
                    warnings += 1
                elif status == 'SKIP':
                    skipped += 1
        
        compliance_rate = round((passed / total * 100), 2) if total > 0 else 0
        
        return {
            'total_tests': total,
            'passed': passed,
            'failed': failed,
            'errors': errors,
            'warnings': warnings,
            'skipped': skipped,
            'compliance_rate': compliance_rate,
            'compliant': compliance_rate >= 80  # 80% threshold for compliance
        }
    
    def _analyze_compliance(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze compliance by category"""
        compliance_by_category = {}
        
        for category, tests in results.items():
            if not isinstance(tests, dict):
                continue
                
            total = len(tests)
            passed = sum(1 for t in tests.values() if isinstance(t, dict) and t.get('status') == 'PASS')
            
            compliance_by_category[category] = {
                'total': total,
                'passed': passed,
                'compliance_rate': round((passed / total * 100), 2) if total > 0 else 0,
                'status': self._get_compliance_status(passed, total)
            }
        
        return compliance_by_category
    
    def _get_compliance_status(self, passed: int, total: int) -> str:
        """Determine compliance status based on pass rate"""
        if total == 0:
            return 'UNKNOWN'
        
        rate = (passed / total) * 100
        
        if rate == 100:
            return 'FULLY_COMPLIANT'
        elif rate >= 90:
            return 'HIGHLY_COMPLIANT'
        elif rate >= 80:
            return 'COMPLIANT'
        elif rate >= 70:
            return 'PARTIALLY_COMPLIANT'
        else:
            return 'NON_COMPLIANT'
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate recommendations based on failures"""
        recommendations = []
        
        for category, tests in results.items():
            if not isinstance(tests, dict):
                continue
                
            for test_name, result in tests.items():
                if not isinstance(result, dict):
                    continue
                    
                status = result.get('status')
                
                if status == 'FAIL':
                    recommendations.append({
                        'category': category,
                        'test': test_name,
                        'control': result.get('control', 'Unknown'),
                        'issue': result.get('message', 'No details'),
                        'priority': 'HIGH',
                        'recommendation': self._get_recommendation(category, test_name)
                    })
                elif status == 'WARN':
                    recommendations.append({
                        'category': category,
                        'test': test_name,
                        'control': result.get('control', 'Unknown'),
                        'issue': result.get('message', 'No details'),
                        'priority': 'MEDIUM',
                        'recommendation': self._get_recommendation(category, test_name)
                    })
                elif status == 'ERROR':
                    recommendations.append({
                        'category': category,
                        'test': test_name,
                        'control': result.get('control', 'Unknown'),
                        'issue': result.get('message', 'No details'),
                        'priority': 'HIGH',
                        'recommendation': 'Review test configuration and platform connectivity'
                    })
        
        # Sort by priority
        priority_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        recommendations.sort(key=lambda x: priority_order.get(x['priority'], 3))
        
        return recommendations
    
    def _get_recommendation(self, category: str, test_name: str) -> str:
        """Get specific recommendation for failed test"""
        recommendations_map = {
            'authentication': {
                'mtls_rest_api': 'Ensure mTLS is properly configured with valid certificates',
                'xapp_cert_identity': 'Generate xApp certificate with UUID v4 in subjectAltName',
                'invalid_cert_rejection': 'Configure platform to require client certificates',
                'cert_expiry': 'Renew xApp certificate before expiration',
                'cipher_strength': 'Disable weak cipher suites, enable only TLS 1.2+'
            },
            'authorization': {
                'oauth_token_flow': 'Configure OAuth 2.0 authorization server',
                'api_access_with_token': 'Verify token validation is enabled',
                'api_access_without_token': 'Ensure APIs require Bearer tokens',
                'expired_token_rejection': 'Implement token expiration validation',
                'scope_enforcement': 'Configure scope-based access control',
                'api_discovery_restrictions': 'Implement policy-based API discovery'
            },
            'data_validation': {
                'a1_policy_schema_validation': 'Implement JSON schema validation for A1 policies',
                'a1_policy_value_validation': 'Add value range checks for policy parameters',
                'a1_policy_rate_validation': 'Implement rate limiting for policy updates',
                'sql_injection_protection': 'Use parameterized queries, sanitize inputs',
                'command_injection_protection': 'Validate and escape all command inputs',
                'buffer_overflow_protection': 'Implement input length restrictions',
                'e2_subscription_validation': 'Validate E2 subscription data formats'
            },
            'rate_limiting': {
                'volumetric_ddos_a1': 'Implement rate limiting and connection pooling',
                'connection_flood': 'Set maximum connection limits per client',
                'slowloris_protection': 'Configure connection timeouts',
                'request_burst': 'Implement token bucket rate limiting',
                'concurrent_connections': 'Set appropriate connection pool limits',
                'recovery_from_attack': 'Implement graceful degradation mechanisms'
            },
            'logging': {
                'security_event_generation': 'Ensure all security events are logged',
                'log_completeness': 'Include all required fields in log entries',
                'log_integrity': 'Implement write-once log storage',
                'log_retention': 'Configure appropriate log retention policies'
            }
        }
        
        if category in recommendations_map and test_name in recommendations_map[category]:
            return recommendations_map[category][test_name]
        else:
            return f'Review and fix {test_name} in {category} category'
    
    def _analyze_control_coverage(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze O-RAN security control coverage"""
        controls_tested = set()
        controls_passed = set()
        controls_failed = set()
        
        for category, tests in results.items():
            if not isinstance(tests, dict):
                continue
                
            for test_result in tests.values():
                if not isinstance(test_result, dict):
                    continue
                    
                control = test_result.get('control', '')
                status = test_result.get('status')
                
                if control:
                    # Handle multiple controls (comma-separated)
                    for ctrl in control.split(','):
                        ctrl = ctrl.strip()
                        controls_tested.add(ctrl)
                        
                        if status == 'PASS':
                            controls_passed.add(ctrl)
                        elif status == 'FAIL':
                            controls_failed.add(ctrl)
        
        return {
            'total_controls_tested': len(controls_tested),
            'controls_passed': len(controls_passed),
            'controls_failed': len(controls_failed),
            'control_coverage_rate': round((len(controls_passed) / len(controls_tested) * 100), 2) if controls_tested else 0,
            'controls_tested_list': sorted(list(controls_tested)),
            'controls_passed_list': sorted(list(controls_passed)),
            'controls_failed_list': sorted(list(controls_failed))
        }
    
    def save_json(self, report: Dict[str, Any], filepath: str):
        """Save report as JSON"""
        try:
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Report saved to {filepath}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
            raise
    
    def generate_html(self, report: Dict[str, Any]) -> str:
        """Generate HTML report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{report['metadata']['title']}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                h1 {{ color: #333; }}
                .summary {{ background: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .pass {{ color: green; }}
                .fail {{ color: red; }}
                .warn {{ color: orange; }}
                table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #4CAF50; color: white; }}
            </style>
        </head>
        <body>
            <h1>{report['metadata']['title']}</h1>
            <p><strong>Specification:</strong> {report['metadata']['specification']}</p>
            <p><strong>Chapter:</strong> {report['metadata']['chapter']}</p>
            <p><strong>Generated:</strong> {report['metadata']['generated_at']}</p>
            
            <div class="summary">
                <h2>Summary</h2>
                <p><strong>Compliance Rate:</strong> {report['summary']['compliance_rate']}%</p>
                <p><strong>Total Tests:</strong> {report['summary']['total_tests']}</p>
                <p class="pass"><strong>Passed:</strong> {report['summary']['passed']}</p>
                <p class="fail"><strong>Failed:</strong> {report['summary']['failed']}</p>
                <p class="warn"><strong>Warnings:</strong> {report['summary']['warnings']}</p>
            </div>
            
            <h2>Recommendations</h2>
            <table>
                <tr>
                    <th>Priority</th>
                    <th>Category</th>
                    <th>Control</th>
                    <th>Issue</th>
                    <th>Recommendation</th>
                </tr>
        """
        
        for rec in report['recommendations']:
            html += f"""
                <tr>
                    <td>{rec['priority']}</td>
                    <td>{rec['category']}</td>
                    <td>{rec['control']}</td>
                    <td>{rec['issue']}</td>
                    <td>{rec['recommendation']}</td>
                </tr>
            """
        
        html += """
            </table>
        </body>
        </html>
        """
        
        return html
    
    def save_html(self, report: Dict[str, Any], filepath: str):
        """Save report as HTML"""
        try:
            html = self.generate_html(report)
            with open(filepath, 'w') as f:
                f.write(html)
            logger.info(f"HTML report saved to {filepath}")
        except Exception as e:
            logger.error(f"Failed to save HTML report: {e}")
            raise
