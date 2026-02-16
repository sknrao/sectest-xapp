"""Security metrics collection and tracking"""
import time
import logging

logger = logging.getLogger(__name__)

class SecurityMetrics:
    """Collect and track security test metrics"""
    
    def __init__(self):
        self.metrics = {
            'start_time': time.time(),
            'tests_run': 0,
            'tests_passed': 0,
            'tests_failed': 0,
            'tests_warned': 0,
            'tests_skipped': 0,
            'tests_errored': 0,
            'vulnerabilities_found': [],
            'by_category': {}
        }
    
    def record_test(self, category, test_name, status, details=None):
        """Record test result"""
        self.metrics['tests_run'] += 1
        
        if status == 'PASS':
            self.metrics['tests_passed'] += 1
        elif status == 'FAIL':
            self.metrics['tests_failed'] += 1
            if details:
                self.metrics['vulnerabilities_found'].append({
                    'category': category,
                    'test': test_name,
                    'details': details,
                    'timestamp': time.time()
                })
        elif status == 'WARN':
            self.metrics['tests_warned'] += 1
        elif status == 'SKIP':
            self.metrics['tests_skipped'] += 1
        elif status == 'ERROR':
            self.metrics['tests_errored'] += 1
        
        # Track by category
        if category not in self.metrics['by_category']:
            self.metrics['by_category'][category] = {
                'total': 0, 'passed': 0, 'failed': 0, 'warned': 0, 'skipped': 0, 'errored': 0
            }
        
        self.metrics['by_category'][category]['total'] += 1
        if status == 'PASS':
            self.metrics['by_category'][category]['passed'] += 1
        elif status == 'FAIL':
            self.metrics['by_category'][category]['failed'] += 1
        elif status == 'WARN':
            self.metrics['by_category'][category]['warned'] += 1
        elif status == 'SKIP':
            self.metrics['by_category'][category]['skipped'] += 1
        elif status == 'ERROR':
            self.metrics['by_category'][category]['errored'] += 1
    
    def get_metrics(self):
        """Get current metrics"""
        self.metrics['duration'] = time.time() - self.metrics['start_time']
        self.metrics['pass_rate'] = (
            (self.metrics['tests_passed'] / self.metrics['tests_run'] * 100)
            if self.metrics['tests_run'] > 0 else 0
        )
        return self.metrics
    
    def print_summary(self):
        """Print metrics summary"""
        m = self.get_metrics()
        print("\n" + "="*60)
        print("SECURITY TEST METRICS SUMMARY")
        print("="*60)
        print(f"Duration: {m['duration']:.2f}s")
        print(f"Tests Run: {m['tests_run']}")
        print(f"Passed: {m['tests_passed']} ({m['pass_rate']:.1f}%)")
        print(f"Failed: {m['tests_failed']}")
        print(f"Warnings: {m['tests_warned']}")
        print(f"Errors: {m['tests_errored']}")
        print(f"Skipped: {m['tests_skipped']}")
        print(f"Vulnerabilities Found: {len(m['vulnerabilities_found'])}")
        print("="*60)