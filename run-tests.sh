#!/bin/bash
set -e

NAMESPACE="ricxapp"
POD_NAME=$(kubectl get pod -n ${NAMESPACE} -l app=security-test-xapp -o jsonpath='{.items[0].metadata.name}')

echo "================================================"
echo "  Running Security Compliance Tests"
echo "================================================"
echo "Pod: ${POD_NAME}"
echo ""

# Start tests
kubectl exec -it ${POD_NAME} -n ${NAMESPACE} -- python -c "
from src.main import SecurityTestXapp
xapp = SecurityTestXapp()
xapp.run_all_tests()
"

echo ""
echo "Retrieving test report..."
kubectl exec ${POD_NAME} -n ${NAMESPACE} -- cat /tmp/security_compliance_report.json > security_report_$(date +%Y%m%d_%H%M%S).json

echo ""
echo "================================================"
echo "  Tests Complete!"
echo "  Report saved to current directory"
echo "================================================"